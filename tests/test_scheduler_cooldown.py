import asyncio
import sys
from app.coordination.scheduler import scheduler, trigger_random_scenario, get_cooldown_info
from app.coordination.registry import scenario_registry

async def main():
    all_s = scenario_registry.list_all()
    print(f"Total scenarios registered: {len(all_s)}")
    assert len(all_s) == 20, f"Expected 20 scenarios, found {len(all_s)}"

    history = []
    print("\n--- Testing 20 Consecutive Random Picks with LRU Cooldown ---")
    for i in range(20):
        res = await trigger_random_scenario()
        sid = res["scenario_id"]
        recent_8 = history[-8:] if len(history) >= 8 else history
        assert sid not in recent_8, f"Violation! {sid} was in recent cooldown history {recent_8}"
        history.append(sid)
        print(f"Pick #{i+1:02d}: [{sid}] {res['name']} ({res['events_delivered_count']} events) - Severity: {res['severity']}")

    status = get_cooldown_info()
    print("\nFinal Cooldown Status:")
    print(f"  Window Size: {status['cooldown_window_size']}")
    print(f"  Recent Executions (LRU 8): {status['recent_executions']}")
    print(f"  Available Candidates: {status['available_scenarios_count']}")
    print(f"  Total Triggered: {status['total_scenarios_triggered']}")
    print("\n>>> All 20 scenarios tested and LRU Shuffle-Deck verified successfully! <<<")

if __name__ == "__main__":
    asyncio.run(main())
