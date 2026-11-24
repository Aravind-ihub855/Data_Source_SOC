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

# Delivery & Telemetry Metrics Ledger for 5 Sources
_metrics = {
    "total_generated": 0,
    "defender_events": 0,
    "entra_events": 0,
    "cloudtrail_events": 0,
    "windows_events": 0,
    "firewall_events": 0,
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
    elif "cloudtrail" in src or "aws" in src:
        _metrics["cloudtrail_events"] += 1
    elif "firewall" in src:
        _metrics["firewall_events"] += 1
    elif "windows" in src or "powershell" in src or "sysmon" in src:
        _metrics["windows_events"] += 1

    if event.get("scenarioId") or event.get("ScenarioId"):
        _metrics["scenario_events"] += 1

    # Format HEC envelope
    hec_item = format_hec_envelope(event=event, source=source)
    _event_buffer.append(hec_item)
    return hec_item

async def send_to_splunk_hec(hec_items: List[Dict[str, Any]]) -> bool:
    """
    Delivers a batch of formatted HEC items to Splunk and mirrors to backend consumer.
    """
    if not is_splunk_enabled():
        _metrics["splunk_last_status"] = "PENDING_CREDENTIALS"
        # Mirror directly to local backend consumer even if Splunk is disabled
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                await client.post("http://localhost:8000/api/pipeline/ingest-splunk", json=hec_items)
        except Exception:
            pass
        return False

    url = splunk_config.HEC_URL
    headers = {
        "Authorization": f"Splunk {splunk_config.HEC_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        payload = "\n".join([json.dumps(item) for item in hec_items])
        async with httpx.AsyncClient(verify=splunk_config.VERIFY_SSL, timeout=splunk_config.TIMEOUT_SEC) as client:
            resp = await client.post(url, content=payload, headers=headers)
            
            # Mirror to Aetheris Backend Consumer
            try:
                await client.post("http://localhost:8000/api/pipeline/ingest-splunk", json=hec_items, timeout=2.0)
            except Exception:
                pass

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

async def deliver_batch_events(events_with_source: List[tuple]) -> List[Dict[str, Any]]:
    """
    Batch buffers and delivers multiple events.
    """
    hec_batch = []
    for event, source in events_with_source:
        item = record_generated_event(event, source)
        hec_batch.append(item)

    if hec_batch and is_splunk_enabled():
        await send_to_splunk_hec(hec_batch)
    return hec_batch

def get_recent_events(
    limit: int = 50,
    source: Optional[str] = None,
    scenario_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves latest events from the circular buffer with optional filtering.
    """
    items = list(_event_buffer)
    if source:
        items = [i for i in items if source.lower() in i.get("source", "").lower()]
    if scenario_id:
        items = [
            i for i in items 
            if i.get("event", {}).get("scenarioId") == scenario_id 
            or i.get("event", {}).get("ScenarioId") == scenario_id
            or i.get("event", {}).get("parsed_fields", {}).get("scenario_id") == scenario_id
            or i.get("event", {}).get("parsed_event", {}).get("ScenarioId") == scenario_id
        ]
    return items[-limit:]

def get_metrics_summary() -> Dict[str, Any]:
    """Returns current generation and delivery ledger."""
    return {
        "metrics": dict(_metrics),
        "buffer_size": len(_event_buffer),
        "buffer_max": settings.BUFFER_MAX_SIZE,
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
        health_url = splunk_config.HEC_URL.replace("/services/collector/event", "/services/collector/health")
        headers = {"Authorization": f"Splunk {splunk_config.HEC_TOKEN}"}
        async with httpx.AsyncClient(verify=splunk_config.VERIFY_SSL, timeout=4.0) as client:
            resp = await client.get(health_url, headers=headers)
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
