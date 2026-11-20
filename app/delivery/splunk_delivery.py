import json
import httpx
import logging
from collections import deque
from typing import Dict, Any, List, Optional
from app.config import settings
from app.splunk_config import splunk_config, is_splunk_enabled, format_hec_envelope

logger = logging.getLogger("synthetic_generator.delivery")

# Global In-Memory Buffer for Local Inspection & Failover
_event_buffer: deque = deque(maxlen=settings.BUFFER_MAX_SIZE)

# Delivery & Telemetry Metrics Ledger
_metrics = {
    "total_generated": 0,
    "defender_events": 0,
    "entra_events": 0,
    "cloudtrail_events": 0,
    "powershell_events": 0,
    "scenario_events": 0,
    "splunk_delivered": 0,
    "splunk_failed": 0,
    "splunk_last_status": "NOT_CONFIGURED" if not is_splunk_enabled() else "INITIALIZED",
    "splunk_last_error": None
}

def record_generated_event(event: Dict[str, Any], source: str) -> Dict[str, Any]:
    """
    Saves event to the local in-memory circular buffer and updates metrics.
    """
    _metrics["total_generated"] += 1
    src = source.lower()
    if "defender" in src:
        _metrics["defender_events"] += 1
    elif "entra" in src:
        _metrics["entra_events"] += 1
    elif "cloudtrail" in src:
        _metrics["cloudtrail_events"] += 1
    elif "powershell" in src:
        _metrics["powershell_events"] += 1

    if event.get("scenarioId") or event.get("ScenarioId"):
        _metrics["scenario_events"] += 1

    # Format HEC envelope
    hec_item = format_hec_envelope(event=event, source=source)
    _event_buffer.append(hec_item)
    return hec_item

async def send_to_splunk_hec(hec_items: List[Dict[str, Any]]) -> bool:
    """
    Reusable function to deliver a batch of formatted HEC items to Splunk.
    """
    if not is_splunk_enabled():
        _metrics["splunk_last_status"] = "PENDING_CREDENTIALS"
        return False

    url = splunk_config.HEC_URL
    headers = {
        "Authorization": f"Splunk {splunk_config.HEC_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        # Splunk HEC accepts multiple JSON objects concatenated together
        payload = "\n".join([json.dumps(item) for item in hec_items])
        async with httpx.AsyncClient(verify=splunk_config.VERIFY_SSL, timeout=splunk_config.TIMEOUT_SEC) as client:
            resp = await client.post(url, content=payload, headers=headers)
            
            if resp.status_code == 200:
                _metrics["splunk_delivered"] += len(hec_items)
                _metrics["splunk_last_status"] = "DELIVERED"
                _metrics["splunk_last_error"] = None
                return True
            else:
                _metrics["splunk_failed"] += len(hec_items)
                _metrics["splunk_last_status"] = f"HEC_ERROR_{resp.status_code}"
                _metrics["splunk_last_error"] = resp.text
                logger.warning(f"Splunk HEC returned status {resp.status_code}: {resp.text}")
                return False
    except Exception as e:
        _metrics["splunk_failed"] += len(hec_items)
        _metrics["splunk_last_status"] = "CONNECTION_FAILED"
        _metrics["splunk_last_error"] = str(e)
        logger.debug(f"Splunk HEC delivery connection error: {e}")
        return False

async def deliver_single_event(event: Dict[str, Any], source: str) -> Dict[str, Any]:
    """
    Buffers event and attempts delivery to Splunk HEC if configured.
    """
    hec_item = record_generated_event(event, source)
    if is_splunk_enabled():
        await send_to_splunk_hec([hec_item])
    return hec_item

async def deliver_batch_events(events_with_sources: List[tuple]) -> List[Dict[str, Any]]:
    """
    Buffers and delivers a batch of (event, source) tuples to Splunk HEC.
    """
    hec_items = []
    for event, source in events_with_sources:
        hec_items.append(record_generated_event(event, source))
    
    if is_splunk_enabled() and hec_items:
        await send_to_splunk_hec(hec_items)
    return hec_items

async def test_splunk_connection() -> Dict[str, Any]:
    """
    Reusable diagnostic function to verify Splunk HEC reachability and token validity.
    """
    if not splunk_config.HEC_URL:
        return {"status": "ERROR", "message": "SPLUNK_HEC_URL is not set"}
    if not splunk_config.HEC_TOKEN:
        return {"status": "WARNING", "message": "SPLUNK_HEC_TOKEN is not set. Splunk forwarding is paused; events are buffered locally."}

    test_envelope = format_hec_envelope(
        event={"test": "ping", "message": "Aetheris AI Synthetic Generator Diagnostic Ping"},
        source="Microsoft Defender"
    )

    try:
        headers = {
            "Authorization": f"Splunk {splunk_config.HEC_TOKEN}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(verify=splunk_config.VERIFY_SSL, timeout=4.0) as client:
            resp = await client.post(splunk_config.HEC_URL, json=test_envelope, headers=headers)
            if resp.status_code == 200:
                return {
                    "status": "SUCCESS",
                    "http_status": resp.status_code,
                    "response": resp.json() if resp.headers.get("content-type") == "application/json" else resp.text,
                    "message": "Splunk HEC is reachable and token is valid!"
                }
            else:
                return {
                    "status": "FAILED",
                    "http_status": resp.status_code,
                    "response": resp.text,
                    "message": f"Splunk HEC responded with HTTP {resp.status_code}"
                }
    except Exception as e:
        return {
            "status": "CONNECTION_ERROR",
            "error": str(e),
            "message": f"Could not connect to Splunk at {splunk_config.HEC_URL}. Ensure Splunk HEC is enabled and port is accessible."
        }

def get_recent_events(
    limit: int = 50,
    source: Optional[str] = None,
    scenario_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves recent buffered events with optional filtering.
    """
    events = list(_event_buffer)
    events.reverse() # Most recent first

    filtered = []
    for item in events:
        if source and source.lower() not in item.get("source", "").lower():
            continue
        if scenario_id:
            raw = item.get("event", {})
            sid = raw.get("scenarioId") or raw.get("ScenarioId")
            if sid != scenario_id:
                continue
        filtered.append(item)
        if len(filtered) >= limit:
            break

    return filtered

def get_metrics_summary() -> Dict[str, Any]:
    """
    Returns live delivery and generation metrics.
    """
    return {
        **_metrics,
        "buffer_size": len(_event_buffer),
        "buffer_capacity": settings.BUFFER_MAX_SIZE,
        "splunk_enabled": is_splunk_enabled()
    }
