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
    trigger_scenario_by_id,
    trigger_random_scenario,
    get_cooldown_info
)
from app.coordination.registry import scenario_registry
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
    windows_rate: Optional[int] = None
    firewall_rate: Optional[int] = None
    powershell_rate: Optional[int] = None # legacy alias for windows_rate

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
    """Detailed operational status for the 5 sources."""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "stream_running": is_stream_running(),
        "sources_count": 5,
        "rates_per_minute": {
            "defender": settings.DEFENDER_RATE_PER_MIN,
            "entra_id": settings.ENTRA_RATE_PER_MIN,
            "cloudtrail": settings.CLOUDTRAIL_RATE_PER_MIN,
            "windows_event_logs": settings.WINDOWS_RATE_PER_MIN,
            "firewall_logs": settings.FIREWALL_RATE_PER_MIN,
            "total_estimated": (
                settings.DEFENDER_RATE_PER_MIN +
                settings.ENTRA_RATE_PER_MIN +
                settings.CLOUDTRAIL_RATE_PER_MIN +
                settings.WINDOWS_RATE_PER_MIN +
                settings.FIREWALL_RATE_PER_MIN
            )
        },
        "splunk_hec": {
            "url": splunk_config.HEC_URL,
            "token_configured": bool(splunk_config.HEC_TOKEN),
            "target_indexes": {
                "endpoint": splunk_config.INDEX_ENDPOINT,
                "cloud": splunk_config.INDEX_CLOUD,
                "authentication": splunk_config.INDEX_AUTH,
                "network": splunk_config.INDEX_NETWORK
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
    source: Optional[str] = Query(default=None, description="Filter by source (Defender, Entra ID, CloudTrail, Windows Event Logs, Firewall logs)"),
    scenario_id: Optional[str] = Query(default=None, description="Filter by Scenario ID (e.g. SCN-001)")
):
    """
    Retrieves recent events from the in-memory circular buffer.
    Allows real-time inspection of generated events across all 5 sources without needing Splunk.
    """
    events = get_recent_events(limit=limit, source=source, scenario_id=scenario_id)
    return {
        "total_returned": len(events),
        "filter": {"source": source, "scenario_id": scenario_id},
        "events": events
    }

@router.get("/scenarios/catalogue", tags=["Scenario Coordinator"])
async def list_scenario_catalogue():
    """
    Returns the comprehensive 20-scenario library indexed by category, classification,
    MITRE ATT&CK techniques, and participating sources.
    """
    scenarios = scenario_registry.list_all()
    catalogue = []
    for s in scenarios:
        catalogue.append({
            "scenario_id": s.scenario_id,
            "name": s.name,
            "category": s.category,
            "classification": s.classification,
            "severity": s.severity,
            "mitre_attack": s.mitre_attack,
            "required_sources": s.required_sources,
            "expected_detections": s.expected_detections,
            "description": s.description,
            "last_run_timestamp": s.last_run_timestamp,
            "execution_count": s.execution_count
        })
    return {
        "total_scenarios": len(catalogue),
        "categories_count": len(set(s["category"] for s in catalogue)),
        "scenarios": catalogue
    }

@router.get("/scenarios/cooldown", tags=["Scenario Coordinator"])
async def get_cooldown():
    """
    Returns the Shuffle-Deck LRU cooldown status (last 8 executions) to verify
    non-repetition and fair scenario rotation.
    """
    return get_cooldown_info()

@router.post("/scenarios/trigger/{scenario_id}", tags=["Scenario Coordinator"])
async def trigger_scenario(scenario_id: str):
    """
    Manually triggers any of the 20 coordinated attack/benign/quality scenarios
    (e.g. SCN-ID-01, SCN-EP-01, SCN-NW-01, SCN-CL-01, SCN-CH-01, SCN-FP-01, SCN-DQ-01).
    Generates correlated events across Defender, Entra ID, CloudTrail, Windows Event Logs, and Firewall,
    buffers them, and forwards to Splunk HEC.
    """
    try:
        delivered = await trigger_scenario_by_id(scenario_id)
        return {
            "status": "SUCCESS",
            "scenario_id": scenario_id,
            "events_count": len(delivered),
            "events": delivered,
            "message": f"Successfully injected scenario {scenario_id} ({len(delivered)} correlated events delivered across 5 sources)"
        }
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate scenario {scenario_id}: {str(e)}")

@router.post("/scenarios/trigger-random", tags=["Scenario Coordinator"])
async def trigger_random():
    """
    Picks and triggers the next random scenario from outside the 8-scenario LRU cooldown window.
    Guarantees no immediate repetition across the 20 scenarios.
    """
    try:
        result = await trigger_random_scenario()
        return {
            "status": "SUCCESS",
            "scenario": result,
            "message": f"Successfully picked and injected scenario {result['scenario_id']}: {result['name']} ({result['events_delivered_count']} events delivered)"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to trigger random scenario: {str(e)}")

@router.post("/stream/start", tags=["Stream Control"])
async def stream_start():
    """Starts continuous streaming telemetry across 5 sources."""
    if is_stream_running():
        return {"status": "ALREADY_RUNNING", "message": "Stream is already running"}
    await start_stream()
    return {"status": "STARTED", "message": "5-source telemetry streaming started"}

@router.post("/stream/stop", tags=["Stream Control"])
async def stream_stop():
    """Pauses continuous telemetry streaming."""
    if not is_stream_running():
        return {"status": "ALREADY_STOPPED", "message": "Stream is not currently running"}
    await stop_stream()
    return {"status": "STOPPED", "message": "Telemetry streaming paused"}

@router.post("/stream/rates", tags=["Stream Control"])
async def update_rates(req: RateUpdateRequest):
    """Dynamically adjusts events per minute rates for any of the 5 sources."""
    if req.defender_rate is not None:
        settings.DEFENDER_RATE_PER_MIN = max(1, req.defender_rate)
    if req.entra_rate is not None:
        settings.ENTRA_RATE_PER_MIN = max(1, req.entra_rate)
    if req.cloudtrail_rate is not None:
        settings.CLOUDTRAIL_RATE_PER_MIN = max(1, req.cloudtrail_rate)
    if req.windows_rate is not None:
        settings.WINDOWS_RATE_PER_MIN = max(1, req.windows_rate)
    elif req.powershell_rate is not None:
        settings.WINDOWS_RATE_PER_MIN = max(1, req.powershell_rate)
    if req.firewall_rate is not None:
        settings.FIREWALL_RATE_PER_MIN = max(1, req.firewall_rate)

    return {
        "status": "UPDATED",
        "rates_per_minute": {
            "defender": settings.DEFENDER_RATE_PER_MIN,
            "entra_id": settings.ENTRA_RATE_PER_MIN,
            "cloudtrail": settings.CLOUDTRAIL_RATE_PER_MIN,
            "windows_event_logs": settings.WINDOWS_RATE_PER_MIN,
            "firewall_logs": settings.FIREWALL_RATE_PER_MIN
        }
    }

@router.post("/splunk/test-hec", tags=["Splunk Delivery"])
async def test_splunk():
    """Tests connection to the configured Splunk HEC endpoint."""
    return await test_splunk_connection()

@router.get("/entities", tags=["Shared Registry"])
async def list_entities():
    """Inspects the Shared Entity Registry maintaining consistency across all 5 generators."""
    return {
        "users": get_all_users(),
        "devices": get_all_devices(),
        "ip_pools": {
            "normal_external_ips": NORMAL_EXTERNAL_IPS,
            "suspicious_external_ips": SUSPICIOUS_EXTERNAL_IPS
        },
        "cloud_account": get_primary_aws_account()
    }
