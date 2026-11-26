import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft202012Validator

import app.coordination.scenarios  # noqa: F401  (registers the 20 scenarios)
from app.config import settings
from app.coordination.registry import scenario_registry
from app.coordination.scheduler import BASELINE, QUICK_PACK, activity_factor, resolve_pack, run_backfill, run_scenario, scheduler
from app.delivery import splunk_delivery as delivery
from app.registry.entities import TENANTS, use_tenant
from app.sources import source_of
from app.splunk_config import splunk_config
from app.util import parse_iso

SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"
SCHEMA_FILES = {"defender": "01_microsoft_defender", "entra": "02_microsoft_entra_id",
                "cloudtrail": "03_aws_cloudtrail", "windows": "04_windows_event_logs", "firewall": "05_firewall",
                "labels": "06_ground_truth_labels"}
VALIDATORS = {k: Draft202012Validator(json.loads((SCHEMAS / f"{f}.schema.json").read_text(encoding="utf-8")))
              for k, f in (("defender", "01_microsoft_defender"), ("entra", "02_microsoft_entra_id"),
                           ("cloudtrail", "03_aws_cloudtrail"), ("windows", "04_windows_event_logs"),
                           ("firewall", "05_firewall"), ("labels", "06_ground_truth_labels"))}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Each test writes labels to its own file, starts with empty queues and no Splunk token."""
    monkeypatch.setattr(settings, "GROUND_TRUTH_PATH", str(tmp_path / "ground_truth.jsonl"))
    monkeypatch.setattr(settings, "DEAD_LETTER_PATH", str(tmp_path / "dead_letter.jsonl"))
    for rate in ("FAULT_DUPLICATE_RATE", "FAULT_LATE_RATE", "FAULT_TRUNCATED_RATE", "FAULT_SCHEMA_DRIFT_RATE"):
        monkeypatch.setattr(settings, rate, 0.0)
    monkeypatch.setattr(splunk_config, "HEC_TOKEN", "")
    delivery._event_buffer.clear()
    delivery._queue.clear()
    yield tmp_path


def truth_rows(tmp_path):
    p = tmp_path / "ground_truth.jsonl"
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


def scenario(sid):
    return scenario_registry.get(sid)


def test_every_event_matches_its_source_schema_in_every_tenant():
    for tid in TENANTS:
        with use_tenant(tid):
            for name, (gen, _) in BASELINE.items():
                for _ in range(30):
                    errs = list(VALIDATORS[source_of(name).short].iter_errors(gen()))
                    assert not errs, (tid, name, errs[0].message)
            for s in scenario_registry.list_all():
                for event, name in scenario_registry.execute_scenario(s.scenario_id):
                    errs = list(VALIDATORS[source_of(name).short].iter_errors(event))
                    assert not errs, (tid, s.scenario_id, name, errs[0].message)


def test_nothing_sent_to_splunk_reveals_the_scenario():
    for tid in TENANTS:
        for s in scenario_registry.list_all():
            for item in asyncio.run(run_scenario(s, tid)):
                wire = json.dumps(item).lower()
                assert "scenario" not in wire and "corr-" not in wire and "run-" not in wire, (s.scenario_id, wire[:200])


def test_one_person_and_one_host_look_the_same_in_every_source():
    with use_tenant("tnt-acme"):
        steps = scenario_registry.execute_scenario("SCN-CH-01")
    by = {}
    for event, name in steps:
        by.setdefault(source_of(name).short, []).append(event)
    upn = by["entra"][0]["userPrincipalName"]
    proc = by["defender"][0]
    win = next(e["parsed_event"] for e in by["windows"] if e["parsed_event"]["EventID"] == 4624)
    assert proc["AccountUpn"] == upn
    assert proc["AccountName"] == win["EventData"]["TargetUserName"]
    assert proc["AccountSid"] == win["EventData"]["TargetUserSid"]
    assert proc["DeviceName"] == win["Computer"]
    assert by["firewall"][0]["parsed_fields"]["user"] == f"{proc['AccountDomain']}\\{proc['AccountName']}"
    assert by["entra"][0]["userId"] == by["entra"][-1]["initiatedBy"]["user"]["id"]
    ids = {}  # a host keeps one Defender DeviceId across events and runs
    with use_tenant("tnt-acme"):
        for _ in range(30):
            e = BASELINE["Microsoft Defender"][0]()
            ids.setdefault(e["DeviceName"], set()).add(e["DeviceId"])
    assert ids[proc["DeviceName"]] == {proc["DeviceId"]} and all(len(v) == 1 for v in ids.values())


def test_tenants_do_not_share_people_or_hosts():
    acme, globex = TENANTS["tnt-acme"], TENANTS["tnt-globex"]
    assert not {u["email"] for u in acme["users"]} & {u["email"] for u in globex["users"]}
    assert not {d["ip_address"] for d in acme["devices"]} & {d["ip_address"] for d in globex["devices"]}
    item = asyncio.run(run_scenario(scenario("SCN-CL-01"), "tnt-globex"))[0]
    assert item["fields"]["tenant_id"] == "tnt-globex"
    assert item["event"]["recipientAccountId"] == "210987654321"


def test_scenario_steps_are_sent_at_their_own_event_time():
    asyncio.run(run_scenario(scenario("SCN-ID-03"), "tnt-acme"))   # NY sign-in, then Frankfurt 15 min later
    first, second = [i for i in delivery._event_buffer]
    e1, e2 = (datetime.fromtimestamp(i["hec"]["time"], timezone.utc) for i in (first, second))
    assert e2 - e1 == timedelta(minutes=15)
    # each step waits for its own event time (plus its own random source delay), never sent early
    for i, e in ((first, e1), (second, e2)):
        assert parse_iso(i["send_at"]) >= e
    assert parse_iso(second["send_at"]) - e1 >= timedelta(minutes=15)


def test_ground_truth_rows_follow_the_label_schema(isolated):
    asyncio.run(run_scenario(scenario("SCN-CH-01"), "tnt-acme"))
    asyncio.run(run_scenario(scenario("SCN-DQ-01"), "tnt-acme"))
    asyncio.run(run_scenario(scenario("SCN-DQ-02"), "tnt-acme"))
    rows = truth_rows(isolated)
    for r in rows:
        errs = list(VALIDATORS["labels"].iter_errors(r))
        assert not errs, (r["scenario_id"], errs[0].message)
    chain = [r for r in rows if r["scenario_id"] == "SCN-CH-01"]
    assert {r["label"] for r in chain} == {"malicious"} and len({r["correlation_group_id"] for r in chain}) == 1
    dup = [r for r in rows if r["scenario_id"] == "SCN-DQ-01" and r["injected_fault"] == "duplicate"]
    assert len(dup) == 2 and all(d["duplicate_of"] in {r["label_id"] for r in rows} for d in dup)
    assert any(r["scenario_id"] == "SCN-DQ-02" and r["injected_fault"] == "late_arrival" for r in rows)


def test_injected_faults_are_labelled(isolated, monkeypatch):
    monkeypatch.setattr(settings, "FAULT_DUPLICATE_RATE", 0.5)
    monkeypatch.setattr(settings, "FAULT_TRUNCATED_RATE", 0.5)

    async def burst():
        for _ in range(40):
            with use_tenant("tnt-acme"):
                await delivery.schedule(BASELINE["AWS CloudTrail"][0](), "AWS CloudTrail", delivery.baseline_truth())
    asyncio.run(burst())
    rows = truth_rows(isolated)
    faults = {r["injected_fault"] for r in rows}
    assert {"duplicate", "truncated"} <= faults
    ids = {r["label_id"] for r in rows}
    assert all(r["duplicate_of"] in ids for r in rows if r["injected_fault"] == "duplicate")
    truncated = [i["hec"]["event"] for i in delivery._event_buffer if isinstance(i["hec"]["event"], str)]
    assert truncated and all(not t.endswith("}") for t in truncated)


def test_wire_formats_and_sourcetypes():
    with use_tenant("tnt-acme"):
        items = {name: asyncio.run(delivery.schedule(gen(), name, delivery.baseline_truth()))
                 for name, (gen, _) in BASELINE.items()}
    win = items["Windows Event Logs"]
    assert win["sourcetype"] == "XmlWinEventLog" and win["source"].startswith("XmlWinEventLog:")
    assert isinstance(win["event"], str) and win["event"].startswith("<Event ")
    assert items["Firewall logs"]["event"].startswith("CEF:0|")
    assert items["Microsoft Defender"]["event"]["category"].startswith("AdvancedHunting-")
    assert items["Microsoft Entra ID"]["event"]["category"] in ("SignInLogs", "AuditLogs")
    assert items["AWS CloudTrail"]["sourcetype"] == "aws:cloudtrail"
    for item in items.values():
        assert set(item["fields"]) == {"tenant_id", "delivery_id", "event_key", "ingest_mode"}
        assert item["fields"]["ingest_mode"] == "live"


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture
def splunk_on(monkeypatch):
    monkeypatch.setattr(splunk_config, "HEC_TOKEN", "test-token")
    monkeypatch.setattr(splunk_config, "HEC_URL", "https://splunk.test:8088/services/collector/event")
    monkeypatch.setattr(splunk_config, "MAX_RETRIES", 3)
    real_sleep = asyncio.sleep
    monkeypatch.setattr(delivery.asyncio, "sleep", lambda s: real_sleep(0))


def test_failed_batches_are_retried_then_dead_lettered(isolated, splunk_on):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(503, text="Server is busy")
    ok = asyncio.run(_run_send(handler, [{"event": "x"}]))
    assert not ok and len(calls) == 4   # first try + 3 retries
    dead = (isolated / "dead_letter.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(dead) == 1 and "503" in json.loads(dead[0])["reason"]


def test_bad_request_is_not_retried(isolated, splunk_on):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(400, json={"text": "Invalid data format", "code": 6})
    assert not asyncio.run(_run_send(handler, [{"event": "x"}]))
    assert len(calls) == 1


def test_delivery_waits_for_indexer_acknowledgement(splunk_on):
    acks = iter([False, True])

    def handler(request):
        assert request.headers["X-Splunk-Request-Channel"]
        if request.url.path.endswith("/ack"):
            return httpx.Response(200, json={"acks": {"7": next(acks)}})
        return httpx.Response(200, json={"text": "Success", "code": 0, "ackId": 7})
    assert asyncio.run(_run_send(handler, [{"event": "x"}]))


async def _run_send(handler, batch):
    async with _client(handler) as client:
        return await delivery.send_to_splunk_hec(client, batch)


def test_backfill_is_repeatable_with_the_same_seed():
    start = datetime(2026, 11, 24, 14, 0, tzinfo=timezone.utc)   # 09:00 in New York, a Tuesday
    a, b = [], []
    stats = asyncio.run(run_backfill(start, start + timedelta(minutes=20), collect=a))
    asyncio.run(run_backfill(start, start + timedelta(minutes=20), collect=b))
    assert stats["events"] > 1000 and stats["scenarios"] >= 3
    assert json.dumps(a) == json.dumps(b)
    assert all(start.timestamp() - 3600 <= i["time"] < (start + timedelta(minutes=40)).timestamp() for i in a)


def test_traffic_follows_working_hours():
    tuesday = datetime(2026, 11, 24, tzinfo=timezone.utc)
    assert activity_factor(tuesday.replace(hour=17)) == 1.0        # 12:00 New York
    assert activity_factor(tuesday.replace(hour=8)) < 0.2          # 03:00 New York
    assert activity_factor(tuesday.replace(hour=17) + timedelta(days=4)) < 0.2   # Saturday


def test_random_scenarios_do_not_repeat_within_cooldown():
    history = []
    for _ in range(20):
        sid = asyncio.run(scheduler.trigger_random_scenario())["scenario_id"]
        assert sid not in history[-8:]
        history.append(sid)


def _window(minutes):
    end = datetime(2026, 11, 24, 15, 0, tzinfo=timezone.utc)
    return end - timedelta(minutes=minutes), end


def test_batch_pack_injects_exactly_the_chosen_scenarios_without_delays(isolated):
    start, end = _window(30)
    items = []
    stats = asyncio.run(run_backfill(start, end, collect=items, volume=1.0, diurnal=False, delays=False,
                                     scenarios=["quick"]))
    assert sorted(x["scenario_id"] for x in stats["scenario_list"]) == sorted(QUICK_PACK)
    assert {x["tenant_id"] for x in stats["scenario_list"]} == {"tnt-acme", "tnt-globex"}   # round-robin over tenants
    labelled = {r["scenario_id"] for r in truth_rows(isolated) if r["scenario_id"]}
    assert labelled == set(QUICK_PACK)                      # nothing random on top of the pack
    for entry in delivery._event_buffer:                    # delays off: every event is due by the window end
        assert parse_iso(entry["send_at"]) <= end + timedelta(seconds=1)
        assert entry["hec"]["fields"]["ingest_mode"] == "batch"


def test_full_pack_covers_all_twenty_scenarios_and_volume_scales_traffic(isolated):
    start, end = _window(60)
    low, high = [], []
    asyncio.run(run_backfill(start, end, collect=low, volume=1.0, diurnal=False, delays=False, scenarios=[]))
    stats = asyncio.run(run_backfill(start, end, collect=high, volume=3.0, diurnal=False, delays=False, scenarios=["full"]))
    assert len(resolve_pack(["full"])) == 20 and stats["scenarios"] == 20
    assert len(high) - sum(x["events"] for x in stats["scenario_list"]) > 2.5 * len(low)   # ~3x baseline events
    assert {x["scenario_id"] for x in stats["scenario_list"]} == {s.scenario_id for s in scenario_registry.list_all()}


def test_batch_settings_do_not_leak_into_live_traffic(isolated):
    start, end = _window(5)
    asyncio.run(run_backfill(start, end, volume=5.0, diurnal=False, delays=False, scenarios=[]))
    assert delivery.realistic_delays.get() is True and delivery.ingest_mode.get() == "live"
    with use_tenant("tnt-acme"):
        item = asyncio.run(delivery.schedule(BASELINE["AWS CloudTrail"][0](), "AWS CloudTrail", delivery.baseline_truth()))
    assert item["fields"]["ingest_mode"] == "live"


def test_unknown_scenario_in_a_pack_is_rejected():
    with pytest.raises(KeyError):
        resolve_pack(["full", "SCN-NOPE-99"])
    assert resolve_pack(["none"]) == [] and resolve_pack(["SCN-001", "SCN-CH-01"]) == ["SCN-CH-01"]   # legacy id, deduplicated


def test_each_run_gets_its_own_label_file(isolated, tmp_path):
    path = delivery.begin_run("e2e-test-1")
    try:
        assert Path(path).parent.name == "e2e-test-1"
        asyncio.run(run_scenario(scenario("SCN-CL-02"), "tnt-acme"))
        assert len(Path(path).read_text(encoding="utf-8").splitlines()) == 1
        assert not (isolated / "ground_truth.jsonl").exists()          # the cumulative file is untouched
    finally:
        delivery.end_run()
    asyncio.run(run_scenario(scenario("SCN-CL-02"), "tnt-acme"))
    assert (isolated / "ground_truth.jsonl").exists()
    with pytest.raises(ValueError):
        delivery.begin_run("../escape")
