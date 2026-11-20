from fastapi import APIRouter, Query, HTTPException
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from app.config import settings
from app.splunk_config import splunk_config, is_splunk_enabled
from app.delivery.splunk_delivery import (
    get_recent_events,
    get_metrics_summary,
    test_splunk_connection
)
from app.coordination.scheduler import (
    start_stream,
    stop_stream,
    is_stream_running,
    trigger_scenario_by_id
)
from app.registry.entities import (
    get_all_users,
    get_all_devices,
    NORMAL_EXTERNAL_IPS,
    SUSPICIOUS_EXTERNAL_IPS,
    get_primary_aws_account
)

router = APIRouter()

class RateUpdateRequest(BaseModel):
    defender_rate: Optional[int] = None
    entra_rate: Optional[int] = None
    cloudtrail_rate: Optional[int] = None
    powershell_rate: Optional[int] = None

@router.get("/health", tags=["Status"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "HEALTHY",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "stream_running": is_stream_running(),
        "splunk_configured": is_splunk_enabled()
    }

@router.get("/status", tags=["Status"])
async def get_status():
    """Detailed operational status."""
    return {
        "service": settings.APP_NAME,
        "stream_running": is_stream_running(),
        "rates_per_minute": {
            "defender": settings.DEFENDER_RATE_PER_MIN,
            "entra_id": settings.ENTRA_RATE_PER_MIN,
            "cloudtrail": settings.CLOUDTRAIL_RATE_PER_MIN,
            "powershell": settings.POWERSHELL_RATE_PER_MIN,
            "total_estimated": (
                settings.DEFENDER_RATE_PER_MIN +
                settings.ENTRA_RATE_PER_MIN +
                settings.CLOUDTRAIL_RATE_PER_MIN +
                settings.POWERSHELL_RATE_PER_MIN
            )
        },
        "splunk_hec": {
            "url": splunk_config.HEC_URL,
            "token_configured": bool(splunk_config.HEC_TOKEN),
            "target_indexes": {
                "endpoint": splunk_config.INDEX_ENDPOINT,
                "cloud": splunk_config.INDEX_CLOUD,
                "authentication": splunk_config.INDEX_AUTH
            }
        }
    }

@router.get("/metrics", tags=["Telemetry Metrics"])
async def get_metrics():
    """Returns generation and delivery statistics."""
    return get_metrics_summary()

@router.get("/events", tags=["Event Inspection"])
async def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    source: Optional[str] = Query(default=None, description="Filter by source (Defender, PowerShell, CloudTrail, Entra ID)"),
    scenario_id: Optional[str] = Query(default=None, description="Filter by Scenario ID (e.g. SCN-001)")
):
    """
    Retrieves recent events from the in-memory circular buffer.
    Allows real-time inspection of generated events without needing Splunk.
    """
    events = get_recent_events(limit=limit, source=source, scenario_id=scenario_id)
    return {
        "total_returned": len(events),
        "filter": {"source": source, "scenario_id": scenario_id},
        "events": events
    }

@router.post("/scenarios/trigger/{scenario_id}", tags=["Scenario Coordinator"])
async def trigger_scenario(scenario_id: str):
    """
    Manually triggers a multi-source coordinated attack scenario (e.g. SCN-001, SCN-002).
    Generates correlated events across Entra ID, PowerShell, Defender, and CloudTrail,
    buffers them, and forwards to Splunk HEC.
    """
    delivered = await trigger_scenario_by_id(scenario_id)
    return {
        "status": "SUCCESS",
        "scenario_id": scenario_id,
        "events_count": len(delivered),
        "events": delivered,
        "message": f"Successfully injected scenario {scenario_id} ({len(delivered)} correlated events delivered)"
    }

@router.post("/stream/start", tags=["Stream Control"])
async def stream_start():
    """Starts continuous 1-minute streaming telemetry."""
    if is_stream_running():
        return {"status": "ALREADY_RUNNING", "message": "Stream is already running"}
    await start_stream()
    return {"status": "STARTED", "message": "Telemetry streaming started"}

@router.post("/stream/stop", tags=["Stream Control"])
async def stream_stop():
    """Pauses continuous telemetry streaming."""
    if not is_stream_running():
        return {"status": "ALREADY_STOPPED", "message": "Stream is not currently running"}
    await stop_stream()
    return {"status": "STOPPED", "message": "Telemetry streaming paused"}

@router.post("/stream/rates", tags=["Stream Control"])
async def update_rates(req: RateUpdateRequest):
    """Dynamically adjusts events per minute rates for any source."""
    if req.defender_rate is not None:
        settings.DEFENDER_RATE_PER_MIN = max(1, req.defender_rate)
    if req.entra_rate is not None:
        settings.ENTRA_RATE_PER_MIN = max(1, req.entra_rate)
    if req.cloudtrail_rate is not None:
        settings.CLOUDTRAIL_RATE_PER_MIN = max(1, req.cloudtrail_rate)
    if req.powershell_rate is not None:
        settings.POWERSHELL_RATE_PER_MIN = max(1, req.powershell_rate)

    return {
        "status": "UPDATED",
        "rates_per_minute": {
            "defender": settings.DEFENDER_RATE_PER_MIN,
            "entra_id": settings.ENTRA_RATE_PER_MIN,
            "cloudtrail": settings.CLOUDTRAIL_RATE_PER_MIN,
            "powershell": settings.POWERSHELL_RATE_PER_MIN
        }
    }

@router.post("/splunk/test-hec", tags=["Splunk Delivery"])
async def test_splunk():
    """Tests connection to the configured Splunk HEC endpoint."""
    return await test_splunk_connection()

@router.get("/entities", tags=["Shared Registry"])
async def list_entities():
    """Inspects the Shared Entity Registry maintaining consistency across all 4 generators."""
    return {
        "users": get_all_users(),
        "devices": get_all_devices(),
        "ip_pools": {
            "normal_external_ips": NORMAL_EXTERNAL_IPS,
            "suspicious_external_ips": SUSPICIOUS_EXTERNAL_IPS
        },
        "cloud_account": get_primary_aws_account()
    }
