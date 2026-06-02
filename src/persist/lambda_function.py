"""
persist — Step Functions target.

Takes an event payload (as passed by SFN, originally from EventBridge), writes
one row to the DDB events table and one object to the S3 raw archive.

Stdlib + boto3. Runs on python3.13.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import boto3


def _to_ddb_safe(obj):
    """DDB resource API rejects native python floats — convert to Decimal."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_ddb_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_ddb_safe(x) for x in obj]
    return obj

DDB_TABLE = os.environ["DDB_TABLE"]
RAW_BUCKET = os.environ["RAW_BUCKET"]
RAW_PREFIX = os.environ.get("RAW_PREFIX", "eb/")

ddb = boto3.resource("dynamodb").Table(DDB_TABLE)
s3 = boto3.client("s3")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def s3_key_for(ts: datetime, event_id: str) -> str:
    return (
        f"{RAW_PREFIX}"
        f"year={ts.year:04d}/month={ts.month:02d}/day={ts.day:02d}/"
        f"hour={ts.hour:02d}/{event_id}.json"
    )


def lambda_handler(event, context):
    """
    SFN passes the EventBridge event payload as-is. EB events have a fixed
    envelope: id, source, detail-type, time, detail, ...
    """
    now = datetime.now(timezone.utc)
    event_id = event.get("id") or str(uuid.uuid4())
    source = event.get("source", "unknown")
    detail_type = event.get("detail-type", "unknown")
    detail = event.get("detail", {})
    event_time = event.get("time", utc_now_iso())

    # Derive severity from detail if dns_detector tagged it; default MED.
    severity = "MED"
    if isinstance(detail, dict):
        severity = detail.get("severity", severity)

    # Item with TTL — DDB will sweep this row 30d after now.
    ttl_epoch = int(time.time()) + (30 * 24 * 3600)

    item = {
        "event_id": event_id,
        "event_time": event_time,
        "source": source,
        "detail_type": detail_type,
        "severity": severity,
        "detail": detail,
        "ingested_at": utc_now_iso(),
        "ttl": ttl_epoch,
    }

    ddb.put_item(Item=_to_ddb_safe(item))

    # Drop the raw JSON into S3 partitioned by hour. Phase 4+ analytics can
    # backfill from here cheap.
    key = s3_key_for(now, event_id)
    s3.put_object(
        Bucket=RAW_BUCKET,
        Key=key,
        Body=json.dumps(event, default=str).encode("utf-8"),
        ContentType="application/json",
    )

    return {
        "event_id": event_id,
        "severity": severity,
        "s3_key": key,
        "ddb_table": DDB_TABLE,
    }
