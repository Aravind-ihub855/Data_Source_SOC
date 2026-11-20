import asyncio
import logging
import random
from typing import Dict, Any, List
from app.config import settings
from app.generators.defender import generate_defender_baseline_event
from app.generators.powershell import generate_powershell_baseline_event
from app.generators.cloudtrail import generate_cloudtrail_baseline_event
from app.generators.entra import generate_entra_baseline_event
from app.coordination.scenarios import get_scenario_by_id
from app.delivery.splunk_delivery import (
    deliver_single_event,
    deliver_batch_events,
    get_metrics_summary
)

logger = logging.getLogger("synthetic_generator.scheduler")

class TelemetryScheduler:
    """
    Manages continuous background streaming and scenario coordination.
    """
    def __init__(self):
        self.running: bool = False
        self.tasks: List[asyncio.Task] = []
        self.lock = asyncio.Lock()
        self.window_stats = {
            "window_count": 0,
            "last_window_events": 0
        }

    async def _worker_defender(self):
        while self.running:
            try:
                # Interval based on target rate: 30/min = ~2.0s interval
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

    async def _worker_powershell(self):
        while self.running:
            try:
                # 15/min = ~4.0s interval
                delay = 60.0 / max(1, settings.POWERSHELL_RATE_PER_MIN)
                interval = random.uniform(delay * 0.75, delay * 1.25)
                await asyncio.sleep(interval)
                if not self.running:
                    break
                event = generate_powershell_baseline_event()
                await deliver_single_event(event, source="PowerShell")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in PowerShell worker: {e}")
                await asyncio.sleep(2.0)

    async def _worker_cloudtrail(self):
        while self.running:
            try:
                # 10/min = ~6.0s interval
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
                await asyncio.sleep(3.0)

    async def _worker_entra(self):
        while self.running:
            try:
                # 20/min = ~3.0s interval
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

    async def _window_reporter(self):
        """Reports 1-minute telemetry stats to the console."""
        while self.running:
            try:
                await asyncio.sleep(60.0)
                if not self.running:
                    break
                metrics = get_metrics_summary()
                self.window_stats["window_count"] += 1
                logger.info(
                    f"⏰ [1-MINUTE TICK] Window #{self.window_stats['window_count']} Summary: "
                    f"Total Generated: {metrics['total_generated']} "
                    f"(Defender: {metrics['defender_events']}, Entra: {metrics['entra_events']}, "
                    f"PowerShell: {metrics['powershell_events']}, CloudTrail: {metrics['cloudtrail_events']}) | "
                    f"Buffer: {metrics['buffer_size']}/{metrics['buffer_capacity']} | "
                    f"Splunk Status: {metrics['splunk_last_status']} (Delivered: {metrics['splunk_delivered']})"
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in window reporter: {e}")

    async def start(self):
        async with self.lock:
            if self.running:
                return
            self.running = True
            logger.info("🚀 Starting Aetheris Synthetic Security Telemetry Scheduler...")
            self.tasks = [
                asyncio.create_task(self._worker_defender(), name="defender-worker"),
                asyncio.create_task(self._worker_powershell(), name="powershell-worker"),
                asyncio.create_task(self._worker_cloudtrail(), name="cloudtrail-worker"),
                asyncio.create_task(self._worker_entra(), name="entra-worker"),
                asyncio.create_task(self._window_reporter(), name="window-reporter")
            ]

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
        scenario_events = get_scenario_by_id(scenario_id)
        events_with_sources = []
        for evt in scenario_events:
            src = evt.get("Source") or evt.get("eventSource") or "Unknown"
            if "iam" in src or "s3" in src or "signin" in src:
                src = "AWS CloudTrail"
            events_with_sources.append((evt, src))

        delivered = await deliver_batch_events(events_with_sources)
        logger.info(f"⚡ Injected Coordinated Scenario {scenario_id} ({len(delivered)} correlated events delivered)")
        return delivered

scheduler = TelemetryScheduler()

# Reusable module functions
async def start_stream():
    await scheduler.start()

async def stop_stream():
    await scheduler.stop()

def is_stream_running() -> bool:
    return scheduler.running

async def trigger_scenario_by_id(scenario_id: str) -> List[Dict[str, Any]]:
    return await scheduler.trigger_scenario(scenario_id)
