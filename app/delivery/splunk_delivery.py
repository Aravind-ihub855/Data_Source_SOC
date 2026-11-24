"""Delivery to Splunk HEC.

schedule() turns a generated event into a HEC item, writes its ground-truth label (never sent to
Splunk), applies injected data-quality faults and queues it for its send time. run_delivery()
sends due items in batches with indexer acknowledgement, retry with backoff and a dead-letter file.
"""
import asyncio
import heapq
import itertools
import json
import logging
import random
import uuid
from collections import deque
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.registry.entities import tenant
from app.sources import source_of
from app.splunk_config import splunk_config, is_splunk_enabled
from app.util import iso, new_uuid, now, parse_iso

logger = logging.getLogger("synthetic_generator.delivery")

# What was generated recently (for /events), with the scenario it belongs to (kept off the wire).
_event_buffer: deque = deque(maxlen=settings.BUFFER_MAX_SIZE)
_queue: List = []                      # heap of (send_epoch, seq, hec_item)
_seq = itertools.count()
_wake = asyncio.Event()
_channel = str(uuid.uuid4())           # HEC channel for indexer acknowledgement

_metrics: Dict[str, Any] = {
    "total_generated": 0,
    "defender_events": 0,
    "entra_events": 0,
    "cloudtrail_events": 0,
    "windows_events": 0,
    "firewall_events": 0,
    "scenario_events": 0,
    "faults_injected": 0,
    "ground_truth_rows": 0,
    "splunk_delivered": 0,
    "splunk_failed": 0,
    "splunk_retries": 0,
    "splunk_dead_lettered": 0,
    "splunk_last_status": "NOT_CONFIGURED" if not is_splunk_enabled() else "INITIALIZED",
    "splunk_last_error": None
}

FAULTS = ("duplicate", "late_arrival", "truncated", "schema_drift")


def _append_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")


def baseline_truth() -> Dict[str, Any]:
    return {"label": "benign", "scenario_instance_id": "baseline", "scenario_type": "baseline", "scenario_id": None,
            "expected_severity": "none", "expected_verdict": "not_applicable", "attack_stage": None,
            "expected_detection_rule_ids": [], "correlation_group_id": None, "injected_fault": "none",
            "duplicate_of": None}


def _pick_fault(allow_late: bool) -> str:
    rates = (settings.FAULT_DUPLICATE_RATE, settings.FAULT_LATE_RATE if allow_late else 0.0,
             settings.FAULT_TRUNCATED_RATE, settings.FAULT_SCHEMA_DRIFT_RATE)
    roll = random.random()
    for fault, rate in zip(FAULTS, rates):
        if roll < rate:
            return fault
        roll -= rate
    return "none"


def _damage(payload: Any, fault: str) -> Any:
    if fault == "truncated":
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return text[: max(1, len(text) // 2)]
    if fault == "schema_drift" and isinstance(payload, dict):
        renamed = sorted(payload)[random.randrange(len(payload))]
        return {(f"{k}_v2" if k == renamed else k): v for k, v in payload.items()}
    return payload


async def schedule(event: Dict[str, Any], source_name: str, truth: Dict[str, Any],
                   send_at=None, allow_late: bool = True) -> Dict[str, Any]:
    """Queues one event for delivery at send_at (default: event time + the source's ingest delay)."""
    src = source_of(source_name)
    event_time = parse_iso(src.time(event))
    if send_at is None:
        send_at = max(now(), event_time) + timedelta(seconds=random.uniform(*src.ingest_delay_s))
    payload, sourcetype, source, host = src.wire(event)

    # A scenario may label its own faults (a resent copy, a backdated event); otherwise roll for one.
    given = truth["injected_fault"]
    fault = given if given != "none" else _pick_fault(allow_late)
    if fault == "schema_drift" and not isinstance(payload, dict):
        fault = "none"  # drift renames a JSON field; XML and CEF lines are sent unchanged, so nothing to label
    copies = [(fault, None, send_at)]      # (fault, index of the original copy, send time)
    if given == "none" and fault == "late_arrival":
        copies = [(fault, None, send_at + timedelta(seconds=random.uniform(300, 900)))]
    elif given == "none" and fault == "duplicate":
        copies = [("none", None, send_at), ("duplicate", 0, send_at + timedelta(seconds=random.uniform(5, 120)))]

    items, rows = [], []
    for copy_fault, dup_index, at in copies:
        delivery_id = new_uuid()
        key = src.key(event)
        item = {
            "time": round(event_time.timestamp(), 3),
            "host": host,
            "source": source,
            "sourcetype": sourcetype,
            "index": src.index,
            "event": _damage(payload, copy_fault),
            "fields": {"tenant_id": tenant()["tenant_id"], "delivery_id": delivery_id, "event_key": key},
        }
        duplicate_of = truth["duplicate_of"] if dup_index is None else rows[dup_index]["label_id"]
        rows.append({
            **truth,
            "label_id": f"lbl-{delivery_id}",
            "dataset_version": settings.APP_VERSION,
            "seed": settings.SEED,
            "tenant_id": tenant()["tenant_id"],
            "delivery_id": delivery_id,
            "source": src.short,
            "event_key": key,
            "event_time": iso(event_time),
            "ingest_delay_seconds": max(0.0, round((at - event_time).total_seconds(), 3)),
            "injected_fault": copy_fault,
            "duplicate_of": duplicate_of if copy_fault == "duplicate" else None,
        })
        items.append((at, item))

    _append_jsonl(settings.GROUND_TRUTH_PATH, rows)
    _metrics["ground_truth_rows"] += len(rows)
    for (at, item), row in zip(items, rows):
        _metrics["total_generated"] += 1
        _metrics[f"{src.short}_events"] += 1
        _metrics["scenario_events"] += row["scenario_id"] is not None
        _metrics["faults_injected"] += row["injected_fault"] != "none"
        _event_buffer.append({"hec": item, "scenario_id": row["scenario_id"], "send_at": iso(at)})
        if is_splunk_enabled() or settings.MIRROR_URL:
            heapq.heappush(_queue, (at.timestamp(), next(_seq), item))
    _wake.set()
    return items[0][1]


async def _wait_for_ack(client: httpx.AsyncClient, ack_id: int, headers: Dict[str, str]) -> bool:
    ack_url = splunk_config.HEC_URL.rsplit("/services/collector", 1)[0] + "/services/collector/ack"
    deadline = asyncio.get_running_loop().time() + splunk_config.ACK_TIMEOUT_SEC
    while asyncio.get_running_loop().time() < deadline:
        resp = await client.post(ack_url, json={"acks": [ack_id]}, headers=headers)
        if resp.status_code == 200 and resp.json().get("acks", {}).get(str(ack_id)):
            return True
        await asyncio.sleep(1.0)
    return False


async def send_to_splunk_hec(client: httpx.AsyncClient, batch: List[Dict[str, Any]]) -> bool:
    """Sends one batch until Splunk confirms it is indexed; otherwise retries, then dead-letters it."""
    headers = {"Authorization": f"Splunk {splunk_config.HEC_TOKEN}", "X-Splunk-Request-Channel": _channel}
    body = "\n".join(json.dumps(item, separators=(",", ":")) for item in batch)
    reason = ""
    for attempt in range(splunk_config.MAX_RETRIES + 1):
        if attempt:
            _metrics["splunk_retries"] += 1
            await asyncio.sleep(min(30.0, 2 ** (attempt - 1)) + random.random())
        try:
            resp = await client.post(splunk_config.HEC_URL, content=body, headers=headers)
            if resp.status_code == 200:
                ack_id = resp.json().get("ackId")
                if ack_id is None or await _wait_for_ack(client, ack_id, headers):
                    _metrics["splunk_delivered"] += len(batch)
                    _metrics["splunk_last_status"] = "DELIVERED"
                    _metrics["splunk_last_error"] = None
                    return True
                reason = f"no indexer acknowledgement within {splunk_config.ACK_TIMEOUT_SEC}s"
            elif resp.status_code == 429 or resp.status_code >= 500:
                reason = f"HEC_ERROR_{resp.status_code}: {resp.text[:200]}"
            else:  # 4xx other than 429: bad token or bad data, retrying cannot help
                reason = f"HEC_ERROR_{resp.status_code}: {resp.text[:200]}"
                break
        except httpx.HTTPError as e:
            reason = f"CONNECTION_FAILED: {e}"
        _metrics["splunk_last_status"] = reason.split(":")[0]
        _metrics["splunk_last_error"] = reason
        logger.warning(f"Splunk HEC batch of {len(batch)} not delivered (attempt {attempt + 1}): {reason}")

    _metrics["splunk_failed"] += len(batch)
    _metrics["splunk_dead_lettered"] += len(batch)
    _append_jsonl(settings.DEAD_LETTER_PATH, [{"failed_at": iso(now()), "reason": reason, "item": i} for i in batch])
    return False


async def _mirror(client: httpx.AsyncClient, batch: List[Dict[str, Any]]) -> None:
    try:
        await client.post(settings.MIRROR_URL, json=batch, timeout=2.0)
    except httpx.HTTPError as e:
        logger.debug(f"Mirror to {settings.MIRROR_URL} failed: {e}")


def _due_batch() -> List[Dict[str, Any]]:
    wall = now().timestamp()
    batch = []
    while _queue and _queue[0][0] <= wall and len(batch) < splunk_config.BATCH_SIZE:
        batch.append(heapq.heappop(_queue)[2])
    return batch


async def run_delivery() -> None:
    """Background task: sends every queued item once its send time has come."""
    async with httpx.AsyncClient(verify=splunk_config.VERIFY_SSL, timeout=splunk_config.TIMEOUT_SEC) as client:
        while True:
            batch = _due_batch()
            if not batch:
                wait = splunk_config.FLUSH_INTERVAL_SEC
                if _queue:
                    wait = min(wait, max(0.05, _queue[0][0] - now().timestamp()))
                _wake.clear()
                try:
                    await asyncio.wait_for(_wake.wait(), timeout=wait)
                except asyncio.TimeoutError:
                    pass
                continue
            if settings.MIRROR_URL:
                await _mirror(client, batch)
            if is_splunk_enabled():
                await send_to_splunk_hec(client, batch)


def queue_depth() -> int:
    return len(_queue)


def get_recent_events(
    limit: int = 50,
    source: Optional[str] = None,
    scenario_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves latest generated HEC items, optionally filtered by source or scenario.
    """
    items = list(_event_buffer)
    if source:
        items = [i for i in items if source.lower() in (i["hec"]["source"] + i["hec"]["sourcetype"]).lower()
                 or source.lower() in i["hec"]["index"].lower()]
    if scenario_id:
        items = [i for i in items if (i["scenario_id"] or "").upper() == scenario_id.upper()]
    return [dict(i["hec"], send_at=i["send_at"]) for i in items[-limit:]]


def get_metrics_summary() -> Dict[str, Any]:
    """Returns current generation and delivery ledger."""
    return {
        "metrics": dict(_metrics),
        "buffer_size": len(_event_buffer),
        "buffer_max": settings.BUFFER_MAX_SIZE,
        "queue_depth": len(_queue),
        "splunk_enabled": is_splunk_enabled()
    }


async def test_splunk_connection() -> Dict[str, Any]:
    """Tests heartbeat to Splunk HEC."""
    if not is_splunk_enabled():
        return {
            "status": "NOT_CONFIGURED",
            "message": "SPLUNK_HEC_TOKEN or SPLUNK_HEC_URL is not set."
        }
    try:
        health_url = splunk_config.HEC_URL.rsplit("/services/collector", 1)[0] + "/services/collector/health"
        async with httpx.AsyncClient(verify=splunk_config.VERIFY_SSL, timeout=4.0) as client:
            resp = await client.get(health_url)
            return {
                "status": "HEALTHY" if resp.status_code == 200 else f"HTTP_{resp.status_code}",
                "status_code": resp.status_code,
                "response": resp.text,
                "url": splunk_config.HEC_URL
            }
    except Exception as e:
        return {
            "status": "UNREACHABLE",
            "error": str(e),
            "url": splunk_config.HEC_URL
        }
