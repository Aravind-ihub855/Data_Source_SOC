import asyncio
from datetime import timedelta
from fastapi import APIRouter, Query, HTTPException
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from app.config import settings
from app.splunk_config import splunk_config, is_splunk_enabled
from app.delivery.splunk_delivery import (
    begin_run,
    end_run,
    get_recent_events,
    get_metrics_summary,
    test_splunk_connection
)
from app.util import now, parse_iso
from app.coordination.scheduler import (
    start_stream,
    stop_stream,
    is_stream_running,
    trigger_scenario_by_id,
    trigger_random_scenario,
    get_cooldown_info,
    activity_factor,
    resolve_pack,
    run_backfill
)
from app.coordination.registry import scenario_registry
from app.registry.entities import TENANTS, NORMAL_EXTERNAL_IPS, SUSPICIOUS_EXTERNAL_IPS

router = APIRouter()

class RateUpdateRequest(BaseModel):
    defender_rate: Optional[int] = None
    entra_rate: Optional[int] = None
    cloudtrail_rate: Optional[int] = None
    windows_rate: Optional[int] = None
    firewall_rate: Optional[int] = None
    powershell_rate: Optional[int] = None # legacy alias for windows_rate

class BackfillRequest(BaseModel):
    minutes: float = Field(default=30, gt=0, le=1440, description="Length of the simulated window")
    end: Optional[str] = Field(default=None, description="Window end (ISO 8601 UTC, in the past); default now")
    volume: float = Field(default=1.0, gt=0, le=50, description="Multiplier on every baseline rate")
    diurnal: bool = Field(default=False, description="Follow the working-hours curve (False = always peak)")
    delays: bool = Field(default=False, description="Apply each source's real-world delivery delay")
    scenarios: Optional[List[str]] = Field(default=None, description="Scenario ids and/or 'full', 'quick', 'none'; "
                                           "omitted = one paced random scenario every few minutes")

class RunRequest(BaseModel):
    run_id: str

_backfill: Dict[str, Any] = {"status": "IDLE", "result": None, "error": None}

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
        "tenants": settings.tenant_list,
        "seed": settings.SEED,
        "activity_factor_now": activity_factor(now()),
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
            "mirror_url": settings.MIRROR_URL or None,
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
async def trigger_scenario(scenario_id: str, tenant: Optional[str] = Query(default=None, description="Tenant id (default: first in TENANTS)")):
    """
    Manually triggers any of the 20 coordinated attack/benign/quality scenarios
    (e.g. SCN-ID-01, SCN-EP-01, SCN-NW-01, SCN-CL-01, SCN-CH-01, SCN-FP-01, SCN-DQ-01).
    Generates correlated events across Defender, Entra ID, CloudTrail, Windows Event Logs, and Firewall
    and schedules each one for delivery to Splunk HEC at its own event time.
    """
    try:
        delivered = await trigger_scenario_by_id(scenario_id, tenant)
        return {
            "status": "SUCCESS",
            "scenario_id": scenario_id,
            "tenant_id": tenant or settings.tenant_list[0],
            "events_count": len(delivered),
            "events": delivered,
            "message": f"Injected scenario {scenario_id} ({len(delivered)} correlated events scheduled at their event times)"
        }
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate scenario {scenario_id}: {str(e)}")

@router.post("/scenarios/trigger-random", tags=["Scenario Coordinator"])
async def trigger_random(tenant: Optional[str] = Query(default=None)):
    """
    Picks and triggers the next random scenario from outside the 8-scenario LRU cooldown window.
    Guarantees no immediate repetition across the 20 scenarios.
    """
    try:
        result = await trigger_random_scenario(tenant)
        return {
            "status": "SUCCESS",
            "scenario": result,
            "message": f"Picked and injected scenario {result['scenario_id']}: {result['name']} ({result['events_delivered_count']} events scheduled)"
        }
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
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
    """Inspects the Shared Entity Registry (per tenant) that keeps all 5 generators consistent."""
    return {
        "tenants": TENANTS,
        "ip_pools": {
            "normal_external_ips": NORMAL_EXTERNAL_IPS,
            "suspicious_external_ips": SUSPICIOUS_EXTERNAL_IPS
        }
    }

@router.post("/backfill", tags=["Backfill"])
async def start_backfill(req: BackfillRequest):
    """
    Generates a past window (baseline + paced scenarios) on simulated time and sends it to Splunk
    with historical timestamps. Runs in the background; poll GET /backfill. Same SEED, same events.
    """
    if _backfill["status"] == "RUNNING":
        raise HTTPException(status_code=409, detail="A backfill is already running")
    if is_stream_running():
        raise HTTPException(status_code=409, detail="Stop the live stream first (POST /stream/stop): "
                                                    "it shares the random generator, so the backfill would not be repeatable")
    try:
        end = parse_iso(req.end) if req.end else now()
    except ValueError:
        raise HTTPException(status_code=422, detail="end must be ISO 8601, e.g. 2026-11-24T09:00:00Z")
    if end > now():
        raise HTTPException(status_code=422, detail="A backfill window must end in the past (end defaults to now)")
    start = end - timedelta(minutes=req.minutes)
    try:
        if req.scenarios is not None:
            resolve_pack(req.scenarios)   # unknown ids are rejected here, not halfway through the run
    except KeyError as e:
        raise HTTPException(status_code=422, detail=str(e))

    async def _run():
        try:
            _backfill["result"] = await run_backfill(start, end, volume=req.volume, diurnal=req.diurnal,
                                                     delays=req.delays, scenarios=req.scenarios)
            _backfill["status"] = "DONE"
        except Exception as e:
            _backfill.update(status="FAILED", error=str(e))

    _backfill.update(status="RUNNING", result=None, error=None)
    _backfill["task"] = asyncio.create_task(_run())
    return {"status": "STARTED", "start": start.isoformat(), "end": end.isoformat(), "seed": settings.SEED,
            "volume": req.volume, "scenarios": req.scenarios}

@router.get("/backfill", tags=["Backfill"])
async def backfill_status():
    """Status of the last backfill."""
    return {k: v for k, v in _backfill.items() if k != "task"}


@router.post("/runs/begin", tags=["Run control"])
async def run_begin(req: RunRequest):
    """Starts a run: its ground-truth labels go to their own file until /runs/end. Returns that file's path."""
    try:
        return {"run_id": req.run_id, "ground_truth_path": begin_run(req.run_id)}
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

@router.post("/runs/end", tags=["Run control"])
async def run_finish():
    """Ends the current run: labels go back to the default (cumulative) file."""
    end_run()
    return {"status": "ENDED"}
