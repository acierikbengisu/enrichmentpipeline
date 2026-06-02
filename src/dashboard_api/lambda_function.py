"""
dashboard_api — HTTP API. Two routes, one lambda:

  GET /api/events     — recent events from the DDB events table
  GET /api/pipeline   — live snapshot of the pipeline: SFN executions,
                         WAF blocklist, CW metrics (last 1h), event counts
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3

# ─── env ──────────────────────────────────────────────────────────────────────

DDB_TABLE = os.environ["DDB_TABLE"]
SFN_ARN = os.environ.get("SFN_ARN", "")
IPSET_NAME = os.environ.get("IPSET_NAME", "")
IPSET_ID = os.environ.get("IPSET_ID", "")
IPSET_SCOPE = os.environ.get("IPSET_SCOPE", "REGIONAL")
SNS_TOPIC_NAME = os.environ.get("SNS_TOPIC_NAME", "")
EB_BUS_NAME = os.environ.get("EB_BUS_NAME", "")
EB_RULE_NAME = os.environ.get("EB_RULE_NAME", "")
LAMBDA_NAMES = [n for n in os.environ.get("LAMBDA_NAMES", "").split(",") if n.strip()]

# ─── clients ──────────────────────────────────────────────────────────────────

ddb_table = boto3.resource("dynamodb").Table(DDB_TABLE)
sfn = boto3.client("stepfunctions")
wafv2 = boto3.client("wafv2")
cw = boto3.client("cloudwatch")


# ─── helpers ──────────────────────────────────────────────────────────────────

def _ddb_to_json(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, dict):
        return {k: _ddb_to_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_ddb_to_json(x) for x in obj]
    return obj


def _resp(code: int, body: dict):
    return {
        "statusCode": code,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body, default=str),
    }


def _utc_iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _safe(fn, default=None):
    """Run fn(), catch + return default on any boto3 error so one broken leg
    doesn't break the whole status response."""
    try:
        return fn()
    except Exception as exc:
        return {"_error": str(exc)} if default is None else default


# ─── handlers ─────────────────────────────────────────────────────────────────

def _handle_events(event):
    qs = event.get("queryStringParameters") or {}
    try:
        limit = max(1, min(int(qs.get("limit", "50")), 200))
    except (TypeError, ValueError):
        limit = 50

    sev_filter = None
    if "severity" in qs and qs["severity"]:
        sev_filter = {s.strip().upper() for s in qs["severity"].split(",") if s.strip()}

    resp = ddb_table.scan()
    items = resp.get("Items", [])
    if sev_filter:
        items = [i for i in items if i.get("severity") in sev_filter]
    items.sort(key=lambda x: x.get("event_time", ""), reverse=True)
    items = items[:limit]

    return _resp(200, {"count": len(items), "events": _ddb_to_json(items)})


def _gather_sfn_executions(max_results: int = 20):
    if not SFN_ARN:
        return []
    resp = sfn.list_executions(stateMachineArn=SFN_ARN, maxResults=max_results)
    out = []
    for e in resp.get("executions", []):
        start = e.get("startDate")
        stop = e.get("stopDate")
        out.append({
            "name": e.get("name"),
            "status": e.get("status"),
            "start_date": _utc_iso(start),
            "stop_date": _utc_iso(stop),
            "duration_ms": int((stop - start).total_seconds() * 1000) if start and stop else None,
        })
    return out


def _gather_waf():
    if not (IPSET_NAME and IPSET_ID):
        return {"size": 0, "addresses": []}
    resp = wafv2.get_ip_set(Name=IPSET_NAME, Id=IPSET_ID, Scope=IPSET_SCOPE)
    addrs = list(resp["IPSet"]["Addresses"])
    return {"size": len(addrs), "addresses": addrs}


def _gather_metrics():
    """Sum totals over the last 60 minutes for each interesting metric."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=60)
    out = {}

    def _sum(namespace, metric, dim_name, dim_value):
        try:
            r = cw.get_metric_statistics(
                Namespace=namespace, MetricName=metric,
                Dimensions=[{"Name": dim_name, "Value": dim_value}],
                StartTime=start, EndTime=end, Period=300, Statistics=["Sum"],
            )
            return int(sum(p["Sum"] for p in r.get("Datapoints", [])))
        except Exception:
            return None

    if SFN_ARN:
        out["sfn_started"] = _sum("AWS/States", "ExecutionsStarted", "StateMachineArn", SFN_ARN)
        out["sfn_succeeded"] = _sum("AWS/States", "ExecutionsSucceeded", "StateMachineArn", SFN_ARN)
        out["sfn_failed"] = _sum("AWS/States", "ExecutionsFailed", "StateMachineArn", SFN_ARN)
    if SNS_TOPIC_NAME:
        out["sns_published"] = _sum("AWS/SNS", "NumberOfMessagesPublished", "TopicName", SNS_TOPIC_NAME)
    if EB_BUS_NAME and EB_RULE_NAME:
        try:
            r = cw.get_metric_statistics(
                Namespace="AWS/Events", MetricName="MatchedEvents",
                Dimensions=[
                    {"Name": "EventBusName", "Value": EB_BUS_NAME},
                    {"Name": "RuleName", "Value": EB_RULE_NAME},
                ],
                StartTime=start, EndTime=end, Period=300, Statistics=["Sum"],
            )
            out["eb_catchall_matched"] = int(sum(p["Sum"] for p in r.get("Datapoints", [])))
        except Exception:
            out["eb_catchall_matched"] = None

    lambdas = {}
    for name in LAMBDA_NAMES:
        lambdas[name] = _sum("AWS/Lambda", "Invocations", "FunctionName", name)
    out["lambda_invocations"] = lambdas

    return out


def _gather_event_counts():
    """Scan ddb (limit 500) and bucket by severity. Cheap at our scale."""
    resp = ddb_table.scan(Limit=500)
    items = resp.get("Items", [])
    counts = {"HIGH": 0, "MED": 0, "LOW": 0, "OTHER": 0}
    for i in items:
        sev = i.get("severity", "OTHER")
        counts[sev if sev in counts else "OTHER"] += 1
    counts["total"] = sum(counts.values())
    return counts


def _handle_pipeline():
    return _resp(200, {
        "fetched_at": _utc_iso(datetime.now(timezone.utc)),
        "executions": _safe(_gather_sfn_executions, []),
        "waf": _safe(_gather_waf, {"size": 0, "addresses": []}),
        "metrics_1h": _safe(_gather_metrics, {}),
        "event_counts": _safe(_gather_event_counts, {}),
    })


# ─── router ───────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    route_key = event.get("routeKey", "")
    if route_key == "GET /api/pipeline":
        return _handle_pipeline()
    if route_key == "GET /api/events":
        return _handle_events(event)
    return _resp(404, {"error": f"unknown routeKey: {route_key!r}"})
