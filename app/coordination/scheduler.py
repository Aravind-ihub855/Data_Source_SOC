import asyncio
import logging
import random
from collections import deque
from typing import Dict, Any, List, Optional
from app.config import settings
from app.generators.defender import generate_defender_baseline_event
from app.generators.windows_events import generate_windows_baseline_event
from app.generators.cloudtrail import generate_cloudtrail_baseline_event
from app.generators.entra import generate_entra_baseline_event
from app.generators.firewall import generate_firewall_baseline_event
from app.coordination.scenarios import get_scenario_by_id
from app.coordination.registry import scenario_registry, ScenarioDefinition
from app.delivery.splunk_delivery import (
    deliver_single_event,
    deliver_batch_events,
    get_metrics_summary
)

logger = logging.getLogger("synthetic_generator.scheduler")

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
        self.window_stats = {
            "window_count": 0,
            "last_window_events": 0
        }
        # LRU cooldown memory: stores the 8 most recently executed scenario IDs
        self._cooldown_history: deque = deque(maxlen=8)
        self.last_scenario_info: Optional[Dict[str, Any]] = None
        self.total_scenarios_triggered: int = 0

    async def _worker_defender(self):
        while self.running:
            try:
                delay = 60.0 / max(1, settings.DEFENDER_RATE_PER_MIN)
                interval = random.uniform(delay * 0.75, delay * 1.25)
                await asyncio.sleep(interval)
                if not self.running:
                    break
                event = generate_defender_baseline_event()
                await deliver_single_event(event, source="Microsoft Defender")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in Defender worker: {e}")
                await asyncio.sleep(2.0)

    async def _worker_windows(self):
        while self.running:
            try:
                delay = 60.0 / max(1, settings.WINDOWS_RATE_PER_MIN)
                interval = random.uniform(delay * 0.75, delay * 1.25)
                await asyncio.sleep(interval)
                if not self.running:
                    break
                event = generate_windows_baseline_event()
                await deliver_single_event(event, source="Windows Event Logs")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in Windows Event worker: {e}")
                await asyncio.sleep(2.0)

    async def _worker_cloudtrail(self):
        while self.running:
            try:
                delay = 60.0 / max(1, settings.CLOUDTRAIL_RATE_PER_MIN)
                interval = random.uniform(delay * 0.75, delay * 1.25)
                await asyncio.sleep(interval)
                if not self.running:
                    break
                event = generate_cloudtrail_baseline_event()
                await deliver_single_event(event, source="AWS CloudTrail")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in CloudTrail worker: {e}")
                await asyncio.sleep(2.0)

    async def _worker_entra(self):
        while self.running:
            try:
                delay = 60.0 / max(1, settings.ENTRA_RATE_PER_MIN)
                interval = random.uniform(delay * 0.75, delay * 1.25)
                await asyncio.sleep(interval)
                if not self.running:
                    break
                event = generate_entra_baseline_event()
                await deliver_single_event(event, source="Microsoft Entra ID")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in Entra ID worker: {e}")
                await asyncio.sleep(2.0)

    async def _worker_firewall(self):
        while self.running:
            try:
                delay = 60.0 / max(1, settings.FIREWALL_RATE_PER_MIN)
                interval = random.uniform(delay * 0.75, delay * 1.25)
                await asyncio.sleep(interval)
                if not self.running:
                    break
                event = generate_firewall_baseline_event()
                await deliver_single_event(event, source="Firewall logs")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in Firewall worker: {e}")
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
                    f"⏰ [1-MINUTE TICK] Window #{self.window_stats['window_count']} Summary: "
                    f"Total: {m['total_generated']} | "
                    f"Defender: {m['defender_events']}, Entra: {m['entra_events']}, "
                    f"CloudTrail: {m['cloudtrail_events']}, Windows: {m['windows_events']}, Firewall: {m['firewall_events']} | "
                    f"Buffer: {summary['buffer_size']}/{summary['buffer_max']} | "
                    f"Splunk Delivered: {m['splunk_delivered']}"
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in window reporter: {e}")

    async def _worker_scenario_pacer(self):
        """
        Paces continuous scenario generation to maintain a realistic, unflooded SOC environment.
        Runs once every SCENARIO_INTERVAL_MIN (default ~4 minutes) with random jitter.
        Uses Shuffle-Deck LRU cooldown so attacks are never repetitive.
        """
        # Initial warmup delay so system starts clean with baseline telemetry
        await asyncio.sleep(20.0)
        while self.running:
            try:
                base_interval = settings.SCENARIO_INTERVAL_MIN * 60.0
                interval = random.uniform(base_interval * 0.85, base_interval * 1.15)
                logger.info(f"⏳ [SCENARIO PACER] Next automated scenario scheduled in {interval:.1f}s (~{interval/60:.1f} min)")
                await asyncio.sleep(interval)
                if not self.running:
                    break
                # Trigger random scenario respecting cooldown window
                result = await self.trigger_random_scenario()
                logger.info(
                    f"🎯 [SCENARIO PACER] Executed scenario {result['scenario_id']} ({result['name']}) - "
                    f"{result['events_delivered_count']} events delivered. Cooldown memory: {result['cooldown_history']}"
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scenario pacer worker: {e}")
                await asyncio.sleep(10.0)

    def get_cooldown_status(self) -> Dict[str, Any]:
        """Returns the current state of the LRU scenario cooldown pool."""
        all_defs = scenario_registry.list_all()
        cooldown_ids = list(self._cooldown_history)
        available_ids = [s.scenario_id for s in all_defs if s.scenario_id not in self._cooldown_history]
        return {
            "cooldown_window_size": 8,
            "recent_executions": cooldown_ids,
            "available_scenarios_count": len(available_ids),
            "available_scenario_ids": available_ids,
            "total_registered_scenarios": len(all_defs),
            "total_scenarios_triggered": self.total_scenarios_triggered,
            "last_scenario_info": self.last_scenario_info
        }

    def pick_next_random_scenario(self) -> ScenarioDefinition:
        """
        Selects the next scenario from the registered pool using Shuffle-Deck logic:
        Only scenarios outside the recent 8-execution sliding window are eligible,
        guaranteeing diversity without repeated attacks.
        """
        all_defs = scenario_registry.list_all()
        available = [s for s in all_defs if s.scenario_id not in self._cooldown_history]
        if not available:
            # Fallback if window size >= total scenarios
            available = all_defs
        chosen = random.choice(available)
        self._cooldown_history.append(chosen.scenario_id)
        return chosen

    async def trigger_random_scenario(self) -> Dict[str, Any]:
        """
        Picks the next non-cooldown scenario, generates correlated events, delivers them,
        and returns execution telemetry.
        """
        chosen = self.pick_next_random_scenario()
        delivered = await self.trigger_scenario(chosen.scenario_id)
        self.total_scenarios_triggered += 1
        info = {
            "scenario_id": chosen.scenario_id,
            "name": chosen.name,
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
            logger.info("🚀 Starting Aetheris 5-Source Synthetic Security Telemetry Scheduler...")
            self.tasks = [
                asyncio.create_task(self._worker_defender(), name="defender-worker"),
                asyncio.create_task(self._worker_windows(), name="windows-worker"),
                asyncio.create_task(self._worker_cloudtrail(), name="cloudtrail-worker"),
                asyncio.create_task(self._worker_entra(), name="entra-worker"),
                asyncio.create_task(self._worker_firewall(), name="firewall-worker"),
                asyncio.create_task(self._window_reporter(), name="window-reporter")
            ]
            if settings.SCENARIO_PACER_ENABLED:
                logger.info(f"🛡️ Enabling Scenario Pacer (Interval: ~{settings.SCENARIO_INTERVAL_MIN} min, Cooldown: 8)")
                self.tasks.append(asyncio.create_task(self._worker_scenario_pacer(), name="scenario-pacer"))

    async def stop(self):
        async with self.lock:
            if not self.running:
                return
            self.running = False
            logger.info("🛑 Stopping Synthetic Telemetry Scheduler...")
            for t in self.tasks:
                t.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            self.tasks.clear()

    async def trigger_scenario(self, scenario_id: str) -> List[Dict[str, Any]]:
        """
        Manually injects an attack scenario into the stream and delivers to Splunk.
        """
        scenario_tuples = get_scenario_by_id(scenario_id)
        events_with_sources = []
        for item in scenario_tuples:
            if isinstance(item, tuple) and len(item) == 2:
                evt, src = item
                events_with_sources.append((evt, src))
            else:
                evt = item
                src = evt.get("Source") or evt.get("eventSource") or "Microsoft Defender"
                if "iam" in src or "s3" in src or "signin" in src:
                    src = "AWS CloudTrail"
                elif "CEF" in str(evt):
                    src = "Firewall logs"
                elif "raw_xml" in evt:
                    src = "Windows Event Logs"
                events_with_sources.append((evt, src))

        delivered = await deliver_batch_events(events_with_sources)
        logger.info(f"⚡ Injected Coordinated Scenario {scenario_id} ({len(delivered)} correlated events delivered across 5 sources)")
        return delivered

scheduler = TelemetryScheduler()

async def start_stream():
    await scheduler.start()

async def stop_stream():
    await scheduler.stop()

def is_stream_running() -> bool:
    return scheduler.running

async def trigger_scenario_by_id(scenario_id: str) -> List[Dict[str, Any]]:
    return await scheduler.trigger_scenario(scenario_id)

async def trigger_random_scenario() -> Dict[str, Any]:
    return await scheduler.trigger_random_scenario()

def get_cooldown_info() -> Dict[str, Any]:
    return scheduler.get_cooldown_status()
