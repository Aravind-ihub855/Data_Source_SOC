import itertools
import random
from typing import Dict, Any, Optional
from xml.sax.saxutils import escape, quoteattr
from app.registry.entities import get_random_user, get_device_for_user, identity, device, resolve_identity
from app.util import iso_now, new_uuid, stable_hex

BENIGN_PS_SCRIPTS = [
    "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 10",
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
    "Test-Connection -ComputerName 10.0.1.1 -Count 2 -Quiet",
    "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'",
    "$PSVersionTable.PSVersion",
    "Get-ChildItem -Path C:\\Logs -Filter *.log | Measure-Object -Property Length -Sum",
    "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, OSArchitecture"
]

PROVIDER_GUIDS = {
    "Microsoft-Windows-Security-Auditing": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
    "Microsoft-Windows-PowerShell": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
    "Microsoft-Windows-Sysmon": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
}

# EventRecordID only ever increases per (computer, channel), as on a real host.
_record_ids: Dict[tuple, itertools.count] = {}


def _next_record_id(computer: str, channel: str) -> int:
    key = (computer, channel)
    if key not in _record_ids:
        _record_ids[key] = itertools.count(100000 + int(stable_hex(f"{computer}|{channel}", 5), 16) % 800000)
    return next(_record_ids[key])


def _render_xml(p: Dict[str, Any]) -> str:
    """The event exactly as Windows renders it: System header plus every EventData field."""
    # Line breaks become character references: same value, and the record stays one line for Splunk.
    data = "".join(f"<Data Name={quoteattr(k)}>{escape(str(v), {chr(10): '&#10;', chr(13): '&#13;'})}</Data>"
                   for k, v in p["EventData"].items())
    guid = PROVIDER_GUIDS.get(p["Provider"]["Name"])
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name={quoteattr(p["Provider"]["Name"])}' + (f' Guid={quoteattr(guid)}' if guid else "") + '/>'
        f'<EventID>{p["EventID"]}</EventID><Version>{p["Version"]}</Version><Level>{p["Level"]}</Level>'
        f'<Task>{p["Task"]}</Task><Opcode>{p["Opcode"]}</Opcode><Keywords>{p["Keywords"]}</Keywords>'
        f'<TimeCreated SystemTime={quoteattr(p["TimeCreated"]["SystemTime"])}/>'
        f'<EventRecordID>{p["EventRecordID"]}</EventRecordID><Correlation/>'
        f'<Execution ProcessID="{p["Execution"]["ProcessID"]}" ThreadID="{p["Execution"]["ThreadID"]}"/>'
        f'<Channel>{escape(p["Channel"])}</Channel><Computer>{escape(p["Computer"])}</Computer>'
        f'<Security UserID={quoteattr(p["Security"]["UserID"])}/>'
        f'</System><EventData>{data}</EventData></Event>'
    )


def generate_windows_event_envelope(
    provider_name: str,
    event_id: int,
    channel: str,
    computer: str,
    event_data: Dict[str, Any],
    level: int = 4,
    version: int = 1,
    task: int = 0,
    opcode: int = 0,
    keywords: str = "0x8020000000000000",
    user_id: str = "S-1-5-18",
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Standard Windows Event record envelope with raw_xml and parsed_event conforming to 04_windows_event_logs.schema.json
    """
    fqdn = device(computer)["fqdn"]
    parsed_event = {
        "Provider": {"Name": provider_name},
        "EventID": event_id,
        "Version": version,
        "Level": level,
        "Task": task,
        "Opcode": opcode,
        "Keywords": keywords,
        "TimeCreated": {"SystemTime": event_time or iso_now()},
        "EventRecordID": _next_record_id(fqdn, channel),
        "Correlation": {},
        "Execution": {"ProcessID": random.randint(1000, 9000), "ThreadID": random.randint(1000, 9000)},
        "Channel": channel,
        "Computer": fqdn,
        "Security": {"UserID": user_id},
        "EventData": event_data
    }
    return {"raw_xml": _render_xml(parsed_event), "parsed_event": parsed_event}

# -----------------------------------------------------------------------------
# 1. PowerShell ScriptBlock Logging (Event ID 4104)
# -----------------------------------------------------------------------------
def generate_powershell_script_block_event(
    device_name: str,
    user_name: str,
    script_text: str,
    is_suspicious: bool = False,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft-Windows-PowerShell Event ID 4104 (ScriptBlockLogging) record.
    """
    event_data = {
        "MessageNumber": "1",
        "MessageTotal": "1",
        "ScriptBlockText": script_text,
        "ScriptBlockId": new_uuid(),
        "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    }
    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-PowerShell",
        event_id=4104,
        channel="Microsoft-Windows-PowerShell/Operational",
        computer=device_name,
        event_data=event_data,
        level=3 if is_suspicious else 5,
        task=2,
        opcode=15,
        keywords="0x0",
        user_id=identity(user_name)["sid"],
        event_time=event_time
    )

# -----------------------------------------------------------------------------
# 2. Sysmon Process Creation (Event ID 1) & Network Connection (Event ID 3)
# -----------------------------------------------------------------------------
def generate_sysmon_process_event(
    device_name: str,
    user_name: str,
    image: str,
    command_line: str,
    parent_image: str = "C:\\Windows\\explorer.exe",
    parent_command_line: str = "C:\\Windows\\explorer.exe",
    process_id: int = 4820,
    parent_process_id: int = 3012,
    process_guid: Optional[str] = None,
    sha256: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft-Windows-Sysmon Event ID 1 (Process Create).
    """
    now_utc = event_time or iso_now()
    who = identity(user_name)
    image_name = image.split("\\")[-1]
    hash_val = (sha256 or stable_hex(f"sha256:{image_name.lower()}", 64)).upper()
    event_data = {
        "RuleName": "-",
        "UtcTime": now_utc[:19].replace("T", " ") + ".000",
        "ProcessGuid": process_guid or f"{{{new_uuid()}}}",
        "ProcessId": str(process_id),
        "Image": image,
        "FileVersion": "10.0.22621.2506 (WinBuild.160101.0800)",
        "Description": "Windows Process",
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": image_name,
        "CommandLine": command_line,
        "CurrentDirectory": f"C:\\Users\\{who['sam']}\\",
        "User": f"{who['domain']}\\{who['sam']}",
        "LogonGuid": f"{{{new_uuid()}}}",
        "LogonId": "0xf1206",
        "TerminalSessionId": "1",
        "IntegrityLevel": "High",
        "Hashes": f"SHA256={hash_val}",
        "ParentProcessGuid": f"{{{new_uuid()}}}",
        "ParentProcessId": str(parent_process_id),
        "ParentImage": parent_image,
        "ParentCommandLine": parent_command_line,
        "ParentUser": f"{who['domain']}\\{who['sam']}"
    }
    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Sysmon",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=device_name,
        event_data=event_data,
        version=5,
        task=1,
        keywords="0x8000000000000000",
        event_time=now_utc
    )

def generate_sysmon_network_event(
    device_name: str,
    user_name: str,
    image: str,
    destination_ip: str,
    destination_port: int,
    source_ip: Optional[str] = None,
    process_id: int = 4820,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft-Windows-Sysmon Event ID 3 (Network Connect).
    """
    now_utc = event_time or iso_now()
    who = identity(user_name)
    event_data = {
        "UtcTime": now_utc[:19].replace("T", " ") + ".000",
        "ProcessGuid": f"{{{new_uuid()}}}",
        "ProcessId": process_id,
        "Image": image,
        "User": f"{who['domain']}\\{who['sam']}",
        "Protocol": "tcp",
        "Initiated": True,
        "SourceIp": source_ip or device(device_name)["ip_address"] or "10.0.1.45",
        "SourcePort": random.randint(49152, 65535),
        "DestinationIp": destination_ip,
        "DestinationPort": destination_port
    }
    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Sysmon",
        event_id=3,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=device_name,
        event_data=event_data,
        version=5,
        task=3,
        keywords="0x8000000000000000",
        event_time=now_utc
    )

# -----------------------------------------------------------------------------
# 3. Windows Security Auditing (4624 Logon, 4625 Failed Logon, 4672 Special Privileges, 4688 Process)
# -----------------------------------------------------------------------------
def generate_windows_security_logon_event(
    device_name: str,
    user_name: str,
    source_ip: str,
    is_success: bool = True,
    logon_type: int = 10,  # 2: Interactive, 3: Network, 10: RemoteInteractive (RDP)
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Windows Security Auditing Event ID 4624 (Logon) or 4625 (Failed Logon).
    """
    who = identity(user_name)
    event_data = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": f"{device(device_name)['device_name']}$",
        "SubjectDomainName": who["domain"],
        "SubjectLogonId": "0x3e7",
        "TargetUserSid": who["sid"] if is_success else "S-1-0-0",
        "TargetUserName": who["sam"],
        "TargetDomainName": who["domain"],
        "TargetLogonId": "0xf1206" if is_success else "0x0",
        "LogonType": str(logon_type),
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "WorkstationName": device(device_name)["device_name"],
        "LogonGuid": f"{{{new_uuid()}}}",
        "ProcessId": "0x2c4",
        "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "IpAddress": source_ip,
        "IpPort": str(random.randint(49152, 65535)),
        "ImpersonationLevel": "%%1833",
        "ElevatedToken": "%%1843"
    }
    if not is_success:
        event_data["Status"] = "0xc000006d"
        event_data["SubStatus"] = "0xc000006a"
    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_id=4624 if is_success else 4625,
        channel="Security",
        computer=device_name,
        event_data=event_data,
        level=0,
        version=2,
        task=12544,
        keywords="0x8020000000000000" if is_success else "0x8010000000000000",
        event_time=event_time
    )

def generate_windows_special_privileges_event(
    device_name: str,
    user_name: str,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """Event ID 4672: special privileges assigned to a new logon (follows an admin 4624)."""
    who = identity(user_name)
    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_id=4672,
        channel="Security",
        computer=device_name,
        event_data={
            "SubjectUserSid": who["sid"],
            "SubjectUserName": who["sam"],
            "SubjectDomainName": who["domain"],
            "SubjectLogonId": "0xf1206",
            "PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege "
                             "SeDebugPrivilege SeSystemEnvironmentPrivilege SeLoadDriverPrivilege SeImpersonatePrivilege"
        },
        level=0,
        version=0,
        task=12548,
        event_time=event_time
    )

def generate_powershell_process_event(
    device_name: str,
    user_name: str,
    command_line: str,
    parent_process: str = "explorer.exe",
    new_process: str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Security 4688 process creation event (name kept for backwards compatibility).
    """
    who = identity(user_name)
    event_data = {
        "SubjectUserSid": who["sid"],
        "SubjectUserName": who["sam"],
        "SubjectDomainName": who["domain"],
        "SubjectLogonId": "0xf1206",
        "NewProcessId": hex(random.randint(0x1000, 0x9000)),
        "NewProcessName": new_process,
        "TokenElevationType": "%%1938",
        "ProcessId": hex(random.randint(0x400, 0x1000)),
        "CommandLine": command_line,
        "ParentProcessName": f"C:\\Windows\\{parent_process}",
        "MandatoryLabel": "S-1-16-8192"
    }
    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_id=4688,
        channel="Security",
        computer=device_name,
        event_data=event_data,
        level=0,
        version=2,
        task=13312,
        event_time=event_time
    )

# -----------------------------------------------------------------------------
# 4. Continuous Baseline Telemetry (Benign)
# -----------------------------------------------------------------------------
def generate_windows_baseline_event() -> Dict[str, Any]:
    """
    A benign host event: PowerShell admin query, Sysmon or Security process creation, a logon,
    or (for privileged users) the 4672 that follows their logon.
    """
    user = get_random_user()
    dev = get_device_for_user(user["username"])["device_name"]
    roll = random.random()

    if roll < 0.30:
        return generate_powershell_script_block_event(dev, user["username"], random.choice(BENIGN_PS_SCRIPTS))
    if roll < 0.55:
        return generate_sysmon_process_event(
            device_name=dev,
            user_name=user["username"],
            image="C:\\Windows\\System32\\conhost.exe",
            command_line="\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c echo heartbeat"
        )
    if roll < 0.75:
        return generate_powershell_process_event(
            dev, user["username"], "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
            new_process="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE")
    if roll < 0.88 and resolve_identity(user["username"]).get("privileged"):
        return generate_windows_special_privileges_event(dev, user["username"])
    return generate_windows_security_logon_event(dev, user["username"], "127.0.0.1", is_success=True, logon_type=2)

# For legacy backwards compatibility
def generate_powershell_baseline_event() -> Dict[str, Any]:
    return generate_windows_baseline_event()
