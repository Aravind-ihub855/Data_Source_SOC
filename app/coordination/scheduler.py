import asyncio
import heapq
import logging
import random
import re
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.config import settings
from app.coordination.context import build_scenario_context
from app.coordination.registry import scenario_registry, ScenarioDefinition
from app.coordination.scenarios import resolve_scenario_id
from app.delivery.splunk_delivery import baseline_truth, get_metrics_summary, schedule
from app.generators import windows_events
from app.generators.cloudtrail import generate_cloudtrail_baseline_event
from app.generators.defender import generate_defender_baseline_event
from app.generators.entra import generate_entra_baseline_event
from app.generators.firewall import generate_firewall_baseline_event
from app.generators.windows_events import generate_windows_baseline_event
from app.registry.entities import use_tenant
from app.sources import source_of
from app.util import now, parse_iso, sim_clock

logger = logging.getLogger("synthetic_generator.scheduler")

# source name -> (baseline generator, settings attribute with its peak events per minute)
BASELINE = {
    "Microsoft Defender": (generate_defender_baseline_event, "DEFENDER_RATE_PER_MIN"),
    "Windows Event Logs": (generate_windows_baseline_event, "WINDOWS_RATE_PER_MIN"),
    "AWS CloudTrail": (generate_cloudtrail_baseline_event, "CLOUDTRAIL_RATE_PER_MIN"),
    "Microsoft Entra ID": (generate_entra_baseline_event, "ENTRA_RATE_PER_MIN"),
    "Firewall logs": (generate_firewall_baseline_event, "FIREWALL_RATE_PER_MIN"),
}
COOLDOWN = 8
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def activity_factor(at: datetime) -> float:
    """Share of peak traffic at this moment: a working-hours curve in the business's local time."""
    if not settings.DIURNAL_CURVE:
        return 1.0
    local = at + timedelta(hours=settings.BUSINESS_UTC_OFFSET_HOURS)
    h = local.hour + local.minute / 60
    if local.weekday() >= 5:
        return 0.15
    if 8 <= h < 18:
        return 1.0
    if 7 <= h < 8 or 18 <= h < 20:
        return 0.5
    return 0.12


def _next_gap_seconds(source: str, at: datetime) -> float:
    rate_per_min = getattr(settings, BASELINE[source][1]) * activity_factor(at)
    return random.expovariate(max(rate_per_min, 0.01) / 60.0)  # Poisson arrivals


async def emit_baseline(source: str, allow_late: bool = True) -> Dict[str, Any]:
    with use_tenant(random.choice(settings.tenant_list)):
        return await schedule(BASELINE[source][0](), source, baseline_truth(), allow_late=allow_late)


async def run_scenario(definition: ScenarioDefinition, tenant_id: str, allow_late: bool = True) -> List[Dict[str, Any]]:
    """Generates one scenario in a tenant and schedules every step for its own event time."""
    with use_tenant(tenant_id):
        ctx = build_scenario_context(definition.scenario_id)
        steps = scenario_registry.execute_scenario(definition.scenario_id, ctx)
        started = parse_iso(ctx.start_time)
        mitre = definition.mitre_attack
        seen: Dict[str, str] = {}
        scheduled = []
        for idx, (event, source_name) in enumerate(steps):
            src = source_of(source_name)
            key = src.key(event)
            fault, duplicate_of = "none", None
            if key in seen:
                fault, duplicate_of = "duplicate", seen[key]
            elif parse_iso(src.time(event)) < started - timedelta(seconds=60):
                fault = "late_arrival"
            truth = {
                "label": definition.label,
                "scenario_id": definition.scenario_id,
                "scenario_instance_id": ctx.execution_id,
                "scenario_type": definition.scenario_type,
                "expected_severity": definition.severity,
                "expected_verdict": definition.expected_verdict,
                "attack_stage": ({"stage_index": idx + 1, "tactic": mitre["tactic"], "technique": mitre["technique_id"]}
                                 if TECHNIQUE.match(mitre.get("technique_id", "")) else None),
                "expected_detection_rule_ids": definition.expected_detections,
                "correlation_group_id": ctx.correlation_id,
                "injected_fault": fault,
                "duplicate_of": duplicate_of,
            }
            item = await schedule(event, source_name, truth, allow_late=allow_late)
            seen.setdefault(key, f"lbl-{item['fields']['delivery_id']}")
            scheduled.append(item)
        return scheduled


class TelemetryScheduler:
    """
    Manages continuous background streaming and scenario coordination across 5 security sources.
    Incorporates a Shuffle-Deck LRU Cooldown mechanism to ensure scenarios are chosen evenly
    without immediate repetition, and paced to avoid flood or starvation.
    """
    def __init__(self):
        self.running: bool = False
        self.tasks: List[asyncio.Task] = []
        self.lock = asyncio.Lock()
        self.window_stats = {"window_count": 0, "last_window_events": 0}
        # LRU cooldown memory: stores the 8 most recently executed scenario IDs
        self._cooldown_history: deque = deque(maxlen=COOLDOWN)
        self.last_scenario_info: Optional[Dict[str, Any]] = None
        self.total_scenarios_triggered: int = 0

    async def _worker(self, source: str):
        while self.running:
            try:
                await asyncio.sleep(_next_gap_seconds(source, now()))
                if self.running:
                    await emit_baseline(source)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in {source} worker: {e}")
                await asyncio.sleep(2.0)

    async def _window_reporter(self):
        """Reports 1-minute telemetry stats across the 5 sources."""
        while self.running:
            try:
                await asyncio.sleep(60.0)
                if not self.running:
                    break
                summary = get_metrics_summary()
                m = summary["metrics"]
                self.window_stats["window_count"] += 1
                logger.info(
                    f"[1-MINUTE TICK] Window #{self.window_stats['window_count']} | activity {activity_factor(now()):.2f} | "
                    f"Total: {m['total_generated']} | Defender: {m['defender_events']}, Entra: {m['entra_events']}, "
                    f"CloudTrail: {m['cloudtrail_events']}, Windows: {m['windows_events']}, Firewall: {m['firewall_events']} | "
                    f"Queued: {summary['queue_depth']} | Splunk Delivered: {m['splunk_delivered']} | "
                    f"Dead-lettered: {m['splunk_dead_lettered']}"
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in window reporter: {e}")

    async def _worker_scenario_pacer(self):
        """
        Paces continuous scenario generation to maintain a realistic, unflooded SOC environment.
        Runs once every SCENARIO_INTERVAL_MIN (default ~4 minutes) with random jitter.
        """
        await asyncio.sleep(20.0)  # warm up with baseline telemetry first
        while self.running:
            try:
                base_interval = settings.SCENARIO_INTERVAL_MIN * 60.0
                interval = random.uniform(base_interval * 0.85, base_interval * 1.15)
                logger.info(f"[SCENARIO PACER] Next automated scenario in {interval:.1f}s (~{interval/60:.1f} min)")
                await asyncio.sleep(interval)
                if not self.running:
                    break
                result = await self.trigger_random_scenario(random.choice(settings.tenant_list))
                logger.info(
                    f"[SCENARIO PACER] Executed {result['scenario_id']} ({result['name']}) in {result['tenant_id']} - "
                    f"{result['events_delivered_count']} events scheduled. Cooldown: {result['cooldown_history']}"
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scenario pacer worker: {e}")
                await asyncio.sleep(10.0)

    def get_cooldown_status(self) -> Dict[str, Any]:
        """Returns the current state of the LRU scenario cooldown pool."""
        all_defs = scenario_registry.list_all()
        available_ids = [s.scenario_id for s in all_defs if s.scenario_id not in self._cooldown_history]
        return {
            "cooldown_window_size": COOLDOWN,
            "recent_executions": list(self._cooldown_history),
            "available_scenarios_count": len(available_ids),
            "available_scenario_ids": available_ids,
            "total_registered_scenarios": len(all_defs),
            "total_scenarios_triggered": self.total_scenarios_triggered,
            "last_scenario_info": self.last_scenario_info
        }

    def pick_next_random_scenario(self) -> ScenarioDefinition:
        """
        Shuffle-Deck pick: only scenarios outside the recent 8-execution window are eligible.
        """
        all_defs = scenario_registry.list_all()
        available = [s for s in all_defs if s.scenario_id not in self._cooldown_history] or all_defs
        chosen = random.choice(available)
        self._cooldown_history.append(chosen.scenario_id)
        return chosen

    async def trigger_random_scenario(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        chosen = self.pick_next_random_scenario()
        tid = tenant_id or settings.tenant_list[0]
        delivered = await run_scenario(chosen, tid)
        self.total_scenarios_triggered += 1
        info = {
            "scenario_id": chosen.scenario_id,
            "name": chosen.name,
            "tenant_id": tid,
            "category": chosen.category,
            "classification": chosen.classification,
            "severity": chosen.severity,
            "mitre_attack": chosen.mitre_attack,
            "events_delivered_count": len(delivered),
            "cooldown_history": list(self._cooldown_history)
        }
        self.last_scenario_info = info
        return info

    async def start(self):
        async with self.lock:
            if self.running:
                return
            self.running = True
            logger.info("Starting Aetheris 5-Source Synthetic Security Telemetry Scheduler...")
            self.tasks = [asyncio.create_task(self._worker(s), name=f"{s}-worker") for s in BASELINE]
            self.tasks.append(asyncio.create_task(self._window_reporter(), name="window-reporter"))
            if settings.SCENARIO_PACER_ENABLED:
                logger.info(f"Enabling Scenario Pacer (Interval: ~{settings.SCENARIO_INTERVAL_MIN} min, Cooldown: {COOLDOWN})")
                self.tasks.append(asyncio.create_task(self._worker_scenario_pacer(), name="scenario-pacer"))

    async def stop(self):
        async with self.lock:
            if not self.running:
                return
            self.running = False
            logger.info("Stopping Synthetic Telemetry Scheduler...")
            for t in self.tasks:
                t.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            self.tasks.clear()

    async def trigger_scenario(self, scenario_id: str, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Manually injects an attack scenario into the stream; each step is sent at its own time.
        """
        definition = scenario_registry.get(resolve_scenario_id(scenario_id))
        scheduled = await run_scenario(definition, tenant_id or settings.tenant_list[0])
        logger.info(f"Injected scenario {definition.scenario_id} ({len(scheduled)} correlated events scheduled)")
        return scheduled


async def run_backfill(start: datetime, end: datetime, collect: Optional[List] = None) -> Dict[str, Any]:
    """
    Generates [start, end) on simulated time: baseline traffic and paced scenarios, as the live
    stream would have produced them, sent to Splunk straight away with their historical timestamps.
    Re-seeds first, so the same SEED and window always produce the same events.
    """
    random.seed(settings.SEED)
    windows_events._record_ids.clear()
    timeline = [(start + timedelta(seconds=_next_gap_seconds(s, start)), i, s) for i, s in enumerate(BASELINE)]
    pace = settings.SCENARIO_INTERVAL_MIN * 60.0
    timeline.append((start + timedelta(seconds=random.uniform(pace * 0.85, pace * 1.15)), len(BASELINE), "scenario"))
    heapq.heapify(timeline)
    recent: deque = deque(maxlen=COOLDOWN)
    counts = {"events": 0, "scenarios": 0}
    while timeline and timeline[0][0] < end:
        at, order, kind = heapq.heappop(timeline)
        with sim_clock(at):
            if kind == "scenario":
                defs = scenario_registry.list_all()
                chosen = random.choice([d for d in defs if d.scenario_id not in recent] or defs)
                recent.append(chosen.scenario_id)
                items = await run_scenario(chosen, random.choice(settings.tenant_list), allow_late=False)
                counts["scenarios"] += 1
                nxt = at + timedelta(seconds=random.uniform(pace * 0.85, pace * 1.15))
            else:
                items = [await emit_baseline(kind, allow_late=False)]
                nxt = at + timedelta(seconds=_next_gap_seconds(kind, at))
        counts["events"] += len(items)
        if collect is not None:
            collect.extend(items)
        heapq.heappush(timeline, (nxt, order, kind))
    return {"start": start.isoformat(), "end": end.isoformat(), "seed": settings.SEED, **counts}


scheduler = TelemetryScheduler()

async def start_stream():
    await scheduler.start()

async def stop_stream():
    await scheduler.stop()

def is_stream_running() -> bool:
    return scheduler.running

async def trigger_scenario_by_id(scenario_id: str, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return await scheduler.trigger_scenario(scenario_id, tenant_id)

async def trigger_random_scenario(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    return await scheduler.trigger_random_scenario(tenant_id)

def get_cooldown_info() -> Dict[str, Any]:
    return scheduler.get_cooldown_status()
