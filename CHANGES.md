# Data generator changes (v2.0.0 → v2.1.0)

Date: 24 Nov 2026

This release fixes how the 5-source synthetic generator produces and delivers data. Before it, events could not be linked across sources, the scenario answer was written inside each event, a whole attack chain landed in one second, and failed Splunk sends were lost. After it, the data behaves like real collection: one person looks the same in every source, labels are kept separately, every step arrives at its own time, and delivery is reliable.

The REST API is unchanged for existing callers. The Albertson frontend's `POST /scenarios/trigger/{id}` works as before.

---

## 1. Data correctness

### 1.1 One person and one host look the same in every source

**Before:**
- Defender `DeviceId`, `AccountSid` and `AccountObjectId` were a new random value on every event.
- `AccountUpn` was `<name>@example.com` instead of the user's real email.
- Entra `userId` and Windows SIDs were also random per event.

So a Defender row could never be matched to an Entra or Windows row for the same user.

**Now:** `app/registry/entities.py` gives every user and device stable identifiers, computed once and never random. Every generator reads them through two helpers, `identity(name)` and `device(name)`.

| Identifier | Same value in |
|---|---|
| UPN (`d.miller@acmefinancial.com`) | Entra `userPrincipalName`, Defender `AccountUpn` |
| SAM account (`dmiller`) + NetBIOS domain (`ACME`) | Defender `AccountName`/`AccountDomain`, Windows `TargetUserName`/`SubjectUserName`, Sysmon `User`, firewall `suser` (`ACME\dmiller`) |
| SID | Defender `AccountSid`, Windows `TargetUserSid`/`SubjectUserSid`/`Security UserID` |
| Object ID | Entra `userId` and `initiatedBy.user.id`, Defender `AccountObjectId` |
| Host FQDN (`finance-pc-01.acmefinancial.com`) | Defender `DeviceName`, Windows `Computer` |
| Defender `DeviceId` | Same for every event from that host |
| Entra device ID | Entra `deviceDetail.deviceId` (the user's own managed device) |
| AWS `principalId` | Same for every CloudTrail event from that user |
| File hashes | Same binary, same SHA1/SHA256/MD5 everywhere |

**Bug fixed:** user Emma Davis was assigned device `SEC-ANALYST-01`, which did not exist. Her events silently landed on David Miller's `FINANCE-PC-01`. The device is now in the registry.

### 1.2 Scenario labels are no longer inside the events

**Before:** every scenario event carried `scenarioId` / `ScenarioId` / `scenario_id`, and that was sent to Splunk. Any detection or AI result could simply read the answer.

**Now:**
- No label text is sent to Splunk.
- Labels are written to a separate ground-truth file, `out/ground_truth.jsonl` (setting `GROUND_TRUTH_PATH`). There is one row per delivered copy, following `schemas/06_ground_truth_labels.schema.json`. That schema already existed, but nothing wrote to it.
- Splunk only receives three HEC indexed fields: `tenant_id`, `delivery_id` and `event_key`. Use `delivery_id` to join a Splunk event to its label.

Example label row:

```json
{"label_id": "lbl-9c1…", "tenant_id": "tnt-acme", "delivery_id": "9c1…", "source": "defender",
 "event_key": "defender|783b5a65…|48211|2026-11-24T09:58:38.120Z", "event_time": "2026-11-24T09:58:38.120Z",
 "label": "malicious", "scenario_id": "SCN-CH-01", "scenario_instance_id": "run-1a2b3c4d",
 "scenario_type": "account_compromise", "expected_severity": "critical", "expected_verdict": "true_positive",
 "attack_stage": {"stage_index": 5, "tactic": "Initial Access", "technique": "T1566"},
 "correlation_group_id": "corr-…", "injected_fault": "none", "duplicate_of": null, "ingest_delay_seconds": 31.4}
```

Each scenario now has a `scenario_type`, a `label` and an `expected_verdict` (`SCENARIO_TRUTH` in `app/coordination/scenarios.py`):

| Scenarios | label | expected_verdict |
|---|---|---|
| ID, EP, NW, CL, CH (16 attack scenarios) | malicious | true_positive |
| SCN-FP-01 authorized admin maintenance | benign_true_positive | benign_true_positive |
| SCN-FP-02 approved vulnerability scanner | benign_lookalike | false_positive |
| SCN-DQ-01 / DQ-02 data-quality scenarios | benign | not_applicable (fault labelled as `duplicate` / `late_arrival`) |
| Baseline traffic | benign | not_applicable |

### 1.3 Each scenario step arrives at its own time

**Before:**
- A scenario's steps were stamped with times up to 15 minutes apart, but all were sent in one batch immediately. Some were stamped in the future.
- Nine Defender steps computed a step time but never passed it, so they used wall-clock time.

**Now:**
- Every step uses its timeline time.
- Each event is queued and sent at its event time plus a realistic source delay:

| Source | Delay to Splunk |
|---|---|
| Windows Event Logs | 1–10 s |
| Firewall | 1–5 s |
| Defender | 5–60 s |
| Entra ID | 60–240 s |
| AWS CloudTrail | 120–480 s |

A full SCN-CH-01 attack chain therefore takes about 4 minutes to finish arriving in Splunk, as it would in reality.

### 1.4 Scenarios use the active tenant's own entities

Hard-coded Acme values in scenarios now come from the active tenant:
- `FW-01`;
- `FINANCE-SRV-01`;
- `IT-ADMIN-01` / `admin_manderson`;
- `10.0.1.x` addresses;
- `198.51.100.14`.

One attacker IP, user and device are chosen per scenario run and reused by every step.

---

## 2. Delivery to Splunk (`app/delivery/splunk_delivery.py`)

| | Before | Now |
|---|---|---|
| Retries | `MAX_RETRIES` configured but never used; a failed batch was lost | Retry with exponential backoff (default 5 retries); then the batch is written to `out/dead_letter.jsonl` |
| Error handling | Any non-200 counted as failed | 429 and 5xx are retried; other 4xx (bad token, bad data) go to dead-letter at once |
| Indexer acknowledgement | Not used; `200` only meant "received" | Sends an `X-Splunk-Request-Channel` header; if HEC returns an `ackId`, polls `/services/collector/ack` until indexed (`SPLUNK_ACK_TIMEOUT_SEC`, default 30 s) |
| Batching | One HTTP request per baseline event | Background sender, batches of up to 50 (`SPLUNK_BATCH_SIZE`) |
| Copy to `localhost:8000` | Every batch always posted to the Albertson backend (that route does not exist there) | Only if `MIRROR_URL` is set |
| Indexed fields | None | `tenant_id`, `delivery_id`, `event_key` |

New metrics on `GET /metrics`:
- `splunk_retries`;
- `splunk_dead_lettered`;
- `faults_injected`;
- `ground_truth_rows`;
- `queue_depth`.

---

## 3. Realism

### 3.1 Real Splunk wire formats and sourcetypes (`app/sources.py`)

Generators still produce the schema form of each event, so `schemas/0N_*.json` validation is unchanged. A new per-source table converts each event into what the real collection path delivers:

| Source | Sent to Splunk as | sourcetype | source |
|---|---|---|---|
| Defender | Streaming API record: `{time, tenantId, operationName, category: "AdvancedHunting-<Table>", properties: <event>}` | `ms:defender:eventhub` | `azure_event_hub://…` |
| Entra ID | Azure Monitor record: `{time, category: "SignInLogs"/"AuditLogs", tenantId, resultType, callerIpAddress, correlationId, properties: <event>}` | `azure:monitor:aad` | `azure_event_hub://…` |
| CloudTrail | The CloudTrail record | `aws:cloudtrail` | `s3://aws-cloudtrail-logs-…` |
| Windows | The event XML only | `XmlWinEventLog` | `XmlWinEventLog:<Channel>` |
| Firewall | The CEF syslog line only | `cef` | `udp:514` |

The old `aetheris:*` sourcetypes and the substring matching used to pick an index (`"defender" in src`) are gone. The source table replaces both.

### 3.2 Windows events

- The XML now contains every field, rendered by one builder. The old hand-written XML dropped most of them.
- Newlines are written as `&#10;`, so each record stays on one line.
- `EventRecordID` only increases per host and channel, as on a real machine.
- Added event 4672 (special privileges assigned to a privileged logon).
- 4688 (process created) now uses the real field names (`NewProcessId`, `CommandLine`, `MandatoryLabel`).
- Baseline traffic now includes 4688 and 4672.
- Correct `Task`, `Keywords` and provider GUIDs.

### 3.3 Other source fixes

- **Firewall:**
  - CEF `rt` is epoch milliseconds, per the CEF standard.
  - Values are escaped (`\`, `=`).
  - Outbound sessions carry `sourceTranslatedAddress`.
  - Baseline traffic comes from real device IPs, with their owners as `suser`.
- **CloudTrail:**
  - `ConsoleLogin` has `additionalEventData`, `responseElements.ConsoleLogin` and event type `AwsConsoleSignIn`. It previously failed its schema.
  - Each tenant has its own account and region.
- **Entra:**
  - Successful normal sign-ins show the user's own managed device.
  - Attacker and travel sign-ins show an unmanaged device.

### 3.4 Working-hours traffic curve

- Baseline volume follows the business's local time (`BUSINESS_UTC_OFFSET_HOURS`, default −5 for New York):

| Period (local time) | Share of peak volume |
|---|---|
| Weekdays 08:00–18:00 | 100% |
| Weekdays 07:00–08:00 and 18:00–20:00 | 50% |
| Weekday nights | 12% |
| Weekends | 15% |

- Event gaps are random (Poisson), not near-even.
- Turn the curve off with `DIURNAL_CURVE=false`, or set the offset to `5.5` to follow IST.

### 3.5 Two tenants

- `tnt-acme` is Acme Financial Services, the original roster.
- `tnt-globex` is Globex Logistics, with its own people, devices, subnet (`10.20.x`), AD domain (`GLOBEX`), firewall (`GLX-FW-01`), egress IP and AWS account (`210987654321`, `eu-west-1`).
- Baseline traffic and the scenario pacer spread across `TENANTS`.
- Manual triggers default to the first tenant; add `?tenant=tnt-globex` to target Globex.

### 3.6 Data-quality faults on all traffic

Faults are injected at delivery, not only in the two data-quality scenarios, and every one is labelled in ground truth:

| Fault | Default rate | Effect |
|---|---|---|
| `duplicate` | 1.5% | A second copy is sent 5–120 s later; `duplicate_of` points to the original label |
| `late_arrival` | 2% | Sent 5–15 minutes late |
| `truncated` | 0.3% | Payload cut in half (malformed) |
| `schema_drift` | 0.1% | One top-level field renamed `<name>_v2` |

### 3.7 Repeatable runs and backfill

- `SEED` (default `20261124`) seeds every random choice and every generated ID.
- New `POST /backfill` endpoint:
  - It takes `{"hours": 1, "end": "<ISO time, optional>"}` and generates a past window on simulated time (baseline plus paced scenarios).
  - It sends that window to Splunk with historical timestamps.
  - The same seed and window always give byte-identical events.
- `GET /backfill` returns the status of the last backfill.
- Rules:
  - The window must end in the past.
  - The live stream must be stopped first (`POST /stream/stop`).
  - Backfills skip the "late" fault.

---

## 4. Code hygiene

- Removed the deprecated `datetime.utcnow()` everywhere. A shared clock in `app/util.py` lets backfills run on simulated time.
- `run.py`: auto-reload is off unless `RELOAD=true`.
- CORS: only the origins in `CORS_ORIGINS` are allowed (default `http://localhost:3000`), without credentials. It used to allow every origin.
- Settings use Pydantic v2 `model_config`, which removes the deprecation warnings.
- `requirements.txt`: removed `apscheduler` (never imported); added `jsonschema` (needed by `validate.py`) and `pytest`.
- `schemas/validate.py` no longer crashes when printing emoji on a Windows console.
- `.env.example` documents every setting. `out/` is git-ignored.

---

## 5. API changes

| Endpoint | Change |
|---|---|
| `POST /scenarios/trigger/{id}` | Optional `?tenant=`. Response adds `tenant_id`; `events` are the scheduled HEC items. An unknown tenant returns 404. |
| `POST /scenarios/trigger-random` | Optional `?tenant=`. Response adds `tenant_id`. |
| `GET /events` | Each item adds `send_at`. `scenario_id` filtering still works (from internal labels, not event fields). |
| `GET /status` | Adds `tenants`, `seed`, `activity_factor_now`, `mirror_url`. |
| `GET /metrics` | Adds `queue_depth` and the new delivery counters. |
| `GET /entities` | Returns every tenant's users, devices and AWS account (with the stable identifiers). |
| `POST /backfill`, `GET /backfill` | New. |

---

## 6. Files

| File | Change |
|---|---|
| `app/util.py` | **New.** Shared clock (real or simulated), seeded IDs, stable hashes. |
| `app/sources.py` | **New.** Per-source time, dedup key (from each schema's `x-dedupe-key`), ingest delay, wire format, sourcetype, index. |
| `app/registry/entities.py` | Tenants, stable identifiers, `identity()` / `device()`, missing `SEC-ANALYST-01`. |
| `app/generators/*.py` | Registry identities, no labels, event times passed through, Windows XML builder, CEF/CloudTrail fixes. |
| `app/coordination/scenarios.py` | Labels removed from events, tenant entities, `SCENARIO_TRUTH`, `resolve_scenario_id()`. |
| `app/coordination/scheduler.py` | One worker for all sources, working-hours curve, tenants, per-step scheduling, backfill. |
| `app/coordination/context.py`, `timeline.py`, `registry.py` | Tenant-aware context, shared clock, label fields. |
| `app/delivery/splunk_delivery.py` | Rewritten: scheduling queue, ack, retry, dead-letter, faults, ground truth. |
| `app/config.py`, `app/splunk_config.py` | New settings (below). |
| `app/api/routes.py`, `app/main.py`, `run.py` | API changes, background sender at startup, CORS, reload. |
| `schemas/0[1-5]_*.json` | `x-splunk` now documents the real sourcetype and delivery form. |
| `schemas/06_ground_truth_labels.schema.json` | Adds `tenant_id`, `delivery_id`, `scenario_id`. |
| `tests/test_generator.py`, `pytest.ini` | **New** pytest suite (replaces `tests/test_scheduler_cooldown.py`). |

### New settings (`.env`)

| Setting | Default |
|---|---|
| `TENANTS` | `tnt-acme,tnt-globex` |
| `SEED` | `20261124` |
| `DIURNAL_CURVE` | `true` |
| `BUSINESS_UTC_OFFSET_HOURS` | `-5` |
| `FAULT_DUPLICATE_RATE` / `FAULT_LATE_RATE` / `FAULT_TRUNCATED_RATE` / `FAULT_SCHEMA_DRIFT_RATE` | `0.015` / `0.02` / `0.003` / `0.001` |
| `GROUND_TRUTH_PATH` | `out/ground_truth.jsonl` |
| `DEAD_LETTER_PATH` | `out/dead_letter.jsonl` |
| `MIRROR_URL` | empty (off) |
| `CORS_ORIGINS` | `http://localhost:3000` |
| `RELOAD` | `false` |
| `SPLUNK_ACK_TIMEOUT_SEC` | `30` |
| `SPLUNK_BATCH_SIZE` | `50` (was 10) |
| `SPLUNK_MAX_RETRIES` | `5` (was 3, unused) |
| `SPLUNK_INDEX_ENDPOINT` / `_AUTH` / `_CLOUD` / `_NETWORK` | `security_endpoint` / `security_identity` / `security_cloud` / `security_network` (was endpoint / authentication / cloud / network), matching `Data_Pipeline_SOC` and the UI |
| `SPLUNK_HEC_URL` | `https://localhost:8088/services/collector/event` (local Splunk HEC uses TLS) |

---

## 7. How it was verified

- **14 pytest tests pass** (`python -m pytest -q`). They cover:
  - every event against its JSON schema, in both tenants;
  - no label text on the wire;
  - cross-source identity;
  - tenant isolation;
  - per-step timing;
  - label rows against their schema;
  - fault labelling;
  - wire formats;
  - retry then dead-letter;
  - no retry on a 400 error;
  - indexer-ack polling;
  - repeatable backfill;
  - the working-hours curve;
  - scenario cooldown.
- **Schema check:** 1,622 generated events (baseline and all 20 scenarios, both tenants) pass their JSON schemas. `schemas/validate.py` passes.
- **Live run against a mock HEC.** The mock implements Splunk's token, channel, `ackId` and `/ack`. Results:
  - Live stream: 96 events delivered, every one matched to a label row, no label text on the wire.
  - 1-hour backfill: 748 events and 15 scenarios across both tenants, all 5 sourcetypes, nothing dead-lettered.
  - A future backfill window is rejected with 422.

**Not verified:** delivery to a real Splunk instance, because it was not running during testing.

---

## 8. Things to know

- **The consumer must handle the new formats.** Windows now arrives as XML (`XmlWinEventLog`), Defender and Entra arrive wrapped in their Event Hub records, and sourcetypes changed from `aetheris:*`. Splunk searches and anything that parses this data must use the new sourcetypes and formats.
- **The Albertson backend no longer gets a copy.** Set `MIRROR_URL` if it needs one.
- **A full attack chain takes minutes in Splunk** because of the realistic per-source delays.
- **Night-time volume is low** while the curve follows New York time.

## Running

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env      # then set SPLUNK_HEC_TOKEN (and SPLUNK_HEC_URL if not local)
.venv\Scripts\python run.py # API on http://localhost:8002, docs at /docs
.venv\Scripts\python -m pytest -q
```
