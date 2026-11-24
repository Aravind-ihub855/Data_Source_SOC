"""The five sources: how each one is timed, keyed, delayed and put on the wire to Splunk.

Generators produce the schema form of an event (schemas/0N_*.schema.json). `wire()` turns it
into what the real collection path delivers to Splunk, with the sourcetype the vendor add-on uses:
  Defender   Streaming API record via Event Hub   ms:defender:eventhub  (Splunk Add-on for Microsoft Security)
  Entra ID   Azure Monitor diagnostic record      azure:monitor:aad     (Splunk Add-on for Microsoft Cloud Services)
  CloudTrail the CloudTrail record                aws:cloudtrail        (Splunk Add-on for AWS)
  Windows    the rendered event XML               XmlWinEventLog, source XmlWinEventLog:<Channel> (Add-on for Windows 5+)
  Firewall   the CEF syslog line                  cef
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict, Tuple

from app.registry.entities import tenant
from app.splunk_config import splunk_config

DEFENDER_TABLES = (("Connection", "DeviceNetworkEvents"), ("File", "DeviceFileEvents"),
                   ("Registry", "DeviceRegistryEvents"), ("Alert", "AlertEvidence"))


def _defender_wire(e: Dict[str, Any]):
    table = next((t for k, t in DEFENDER_TABLES if k in e["ActionType"]), "DeviceProcessEvents")
    record = {"time": e["Timestamp"], "tenantId": tenant()["entra_tenant_id"], "operationName": "Publish",
              "category": f"AdvancedHunting-{table}", "properties": e}
    return record, "ms:defender:eventhub", f"azure_event_hub://{tenant()['tenant_id']}-mde/advancedhunting", e["DeviceName"]


def _entra_wire(e: Dict[str, Any]):
    tid = tenant()["entra_tenant_id"]
    common = {"resourceId": f"/tenants/{tid}/providers/Microsoft.aadiam", "operationVersion": "1.0",
              "tenantId": tid, "correlationId": e["correlationId"], "Level": 4, "properties": e}
    if "createdDateTime" in e:
        st = e["status"]
        record = {"time": e["createdDateTime"], "operationName": "Sign-in activity", "category": "SignInLogs",
                  "resultType": str(st["errorCode"]), "resultSignature": "None",
                  "resultDescription": st.get("failureReason") or "", "durationMs": 0,
                  "callerIpAddress": e["ipAddress"], "identity": e["userDisplayName"],
                  "location": e["location"]["countryOrRegion"], **common}
    else:
        record = {"time": e["activityDateTime"], "operationName": e["activityDisplayName"], "category": "AuditLogs",
                  "resultType": "", "resultSignature": "None", "durationMs": 0,
                  "callerIpAddress": e["initiatedBy"]["user"].get("ipAddress", ""), **common}
    return record, "azure:monitor:aad", f"azure_event_hub://{tenant()['tenant_id']}-aad/insights-logs", "azure-ad"


def _cloudtrail_wire(e: Dict[str, Any]):
    acct = e["recipientAccountId"]
    return (e, "aws:cloudtrail",
            f"s3://aws-cloudtrail-logs-{acct}/AWSLogs/{acct}/CloudTrail/{e['awsRegion']}", "aws-cloudtrail")


def _windows_wire(e: Dict[str, Any]):
    p = e["parsed_event"]
    return e["raw_xml"], "XmlWinEventLog", f"XmlWinEventLog:{p['Channel']}", p["Computer"]


def _firewall_wire(e: Dict[str, Any]):
    return e["raw_message"], "cef", "udp:514", e["parsed_fields"]["device_name"]


@dataclass(frozen=True)
class Source:
    name: str                    # name used by generators/scenarios and the API
    short: str                   # ground-truth enum value
    index_attr: str              # splunk_config attribute holding the index
    time: Callable[[Dict[str, Any]], str]
    key: Callable[[Dict[str, Any]], str]
    wire: Callable[[Dict[str, Any]], Tuple[Any, str, str, str]]
    ingest_delay_s: Tuple[float, float]   # typical source-to-Splunk delay (min, max)

    @property
    def index(self) -> str:
        return getattr(splunk_config, self.index_attr)


SOURCES: Dict[str, Source] = {s.name: s for s in [
    Source("Microsoft Defender", "defender", "INDEX_ENDPOINT", lambda e: e["Timestamp"],
           lambda e: f"defender|{e['DeviceId']}|{e['ReportId']}|{e['Timestamp']}", _defender_wire, (5, 60)),
    Source("Microsoft Entra ID", "entra", "INDEX_AUTH",
           lambda e: e.get("createdDateTime") or e["activityDateTime"], lambda e: e["id"], _entra_wire, (60, 240)),
    Source("AWS CloudTrail", "cloudtrail", "INDEX_CLOUD", lambda e: e["eventTime"], lambda e: e["eventID"],
           _cloudtrail_wire, (120, 480)),
    Source("Windows Event Logs", "windows", "INDEX_ENDPOINT",
           lambda e: e["parsed_event"]["TimeCreated"]["SystemTime"],
           lambda e: "|".join(str(x) for x in (e["parsed_event"]["Computer"], e["parsed_event"]["Channel"],
                                                e["parsed_event"]["EventRecordID"],
                                                e["parsed_event"]["TimeCreated"]["SystemTime"])),
           _windows_wire, (1, 10)),
    Source("Firewall logs", "firewall", "INDEX_NETWORK", lambda e: e["parsed_fields"]["event_time"],
           lambda e: "|".join(str(e["parsed_fields"][k]) for k in ("device_id", "session_id", "event_time", "log_type")),
           _firewall_wire, (1, 5)),
]}


def source_of(name: str) -> Source:
    try:
        return SOURCES[name]
    except KeyError:
        raise KeyError(f"Unknown source '{name}'. Known: {list(SOURCES)}") from None
