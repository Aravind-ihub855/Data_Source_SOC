import uuid
import datetime
import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_device_for_user, get_random_normal_ip

BENIGN_PS_SCRIPTS = [
    "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 10",
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
    "Test-Connection -ComputerName 10.0.1.1 -Count 2 -Quiet",
    "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'",
    "$PSVersionTable.PSVersion",
    "Get-ChildItem -Path C:\\Logs -Filter *.log | Measure-Object -Property Length -Sum",
    "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, OSArchitecture"
]

def generate_windows_event_envelope(
    provider_name: str,
    event_id: int,
    channel: str,
    computer: str,
    event_data: Dict[str, Any],
    raw_xml: str,
    level: int = 4,
    version: int = 1,
    task: int = 0,
    opcode: int = 0,
    keywords: str = "0x8020000000000000",
    user_id: str = "S-1-5-18",
    event_time: Optional[str] = None,
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Standard Windows Event record envelope with raw_xml and parsed_event conforming to 04_windows_event_logs.schema.json
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    record_id = random.randint(10000, 999999)

    parsed_event = {
        "Provider": {
            "Name": provider_name
        },
        "EventID": event_id,
        "Version": version,
        "Level": level,
        "Task": task,
        "Opcode": opcode,
        "Keywords": keywords,
        "TimeCreated": {
            "SystemTime": now_utc
        },
        "EventRecordID": record_id,
        "Correlation": {},
        "Execution": {
            "ProcessID": random.randint(1000, 9000),
            "ThreadID": random.randint(1000, 9000)
        },
        "Channel": channel,
        "Computer": computer,
        "Security": {
            "UserID": user_id
        },
        "EventData": event_data
    }

    event = {
        "raw_xml": raw_xml,
        "parsed_event": parsed_event
    }

    if scenario_id:
        event["scenarioId"] = scenario_id
        event["parsed_event"]["ScenarioId"] = scenario_id

    return event

# -----------------------------------------------------------------------------
# 1. PowerShell ScriptBlock Logging (Event ID 4104) & Module Logging (4103)
# -----------------------------------------------------------------------------
def generate_powershell_script_block_event(
    device_name: str,
    user_name: str,
    script_text: str,
    is_suspicious: bool = False,
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft-Windows-PowerShell Event ID 4104 (ScriptBlockLogging) record.
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    block_id = str(uuid.uuid4())
    user_sid = f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}"

    event_data = {
        "MessageNumber": "1",
        "MessageTotal": "1",
        "ScriptBlockText": script_text,
        "ScriptBlockId": block_id,
        "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    }

    raw_xml = (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System>'
        f'<Provider Name="Microsoft-Windows-PowerShell" Guid="{{A0C1853B-5C40-4B15-8766-3CF1C58F985A}}"/>'
        f'<EventID>4104</EventID><Version>1</Version><Level>{3 if is_suspicious else 5}</Level>'
        f'<TimeCreated SystemTime="{now_utc}"/>'
        f'<Channel>Microsoft-Windows-PowerShell/Operational</Channel>'
        f'<Computer>{device_name}</Computer>'
        f'<Security UserID="{user_sid}"/>'
        f'</System>'
        f'<EventData>'
        f'<Data Name="MessageNumber">1</Data>'
        f'<Data Name="MessageTotal">1</Data>'
        f'<Data Name="ScriptBlockText">{script_text.replace("<", "&lt;").replace(">", "&gt;").replace(chr(10), " ").replace(chr(13), " ")}</Data>'
        f'<Data Name="ScriptBlockId">{block_id}</Data>'
        f'</EventData>'
        f'</Event>'
    )

    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-PowerShell",
        event_id=4104,
        channel="Microsoft-Windows-PowerShell/Operational",
        computer=device_name,
        event_data=event_data,
        raw_xml=raw_xml,
        level=3 if is_suspicious else 5,
        user_id=user_sid,
        event_time=now_utc,
        scenario_id=scenario_id
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
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft-Windows-Sysmon Event ID 1 (Process Create).
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    p_guid = process_guid or f"{{{uuid.uuid4()}}}"
    parent_guid = f"{{{uuid.uuid4()}}}"
    hash_val = (sha256 or (uuid.uuid4().hex + uuid.uuid4().hex)).upper()

    event_data = {
        "RuleName": "-",
        "UtcTime": now_utc[:19].replace("T", " ") + ".000",
        "ProcessGuid": p_guid,
        "ProcessId": str(process_id),
        "Image": image,
        "FileVersion": "10.0.22621.2506 (WinBuild.160101.0800)",
        "Description": "Windows Process",
        "Product": "Microsoft Windows Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": image.split("\\")[-1],
        "CommandLine": command_line,
        "CurrentDirectory": f"C:\\Users\\{user_name}\\",
        "User": f"CORP\\{user_name}",
        "LogonGuid": f"{{{uuid.uuid4()}}}",
        "LogonId": "0xf1206",
        "TerminalSessionId": "1",
        "IntegrityLevel": "High",
        "Hashes": f"SHA256={hash_val}",
        "ParentProcessGuid": parent_guid,
        "ParentProcessId": str(parent_process_id),
        "ParentImage": parent_image,
        "ParentCommandLine": parent_command_line,
        "ParentUser": f"CORP\\{user_name}"
    }

    raw_xml = (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System>'
        f'<Provider Name="Microsoft-Windows-Sysmon"/>'
        f'<EventID>1</EventID><Version>0</Version>'
        f'<TimeCreated SystemTime="{now_utc}"/>'
        f'<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
        f'<Computer>{device_name}</Computer>'
        f'</System>'
        f'<EventData>'
        f'<Data Name="UtcTime">{event_data["UtcTime"]}</Data>'
        f'<Data Name="ProcessGuid">{p_guid}</Data>'
        f'<Data Name="ProcessId">{process_id}</Data>'
        f'<Data Name="Image">{image}</Data>'
        f'<Data Name="CommandLine">{command_line.replace("<", "&lt;").replace(">", "&gt;")}</Data>'
        f'<Data Name="User">CORP\\{user_name}</Data>'
        f'<Data Name="Hashes">SHA256={hash_val}</Data>'
        f'<Data Name="ParentImage">{parent_image}</Data>'
        f'</EventData>'
        f'</Event>'
    )

    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Sysmon",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=device_name,
        event_data=event_data,
        raw_xml=raw_xml,
        level=4,
        event_time=now_utc,
        scenario_id=scenario_id
    )

def generate_sysmon_network_event(
    device_name: str,
    user_name: str,
    image: str,
    destination_ip: str,
    destination_port: int,
    source_ip: str = "10.0.1.45",
    process_id: int = 4820,
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft-Windows-Sysmon Event ID 3 (Network Connect).
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    event_data = {
        "UtcTime": now_utc[:19].replace("T", " ") + ".000",
        "ProcessGuid": f"{{{uuid.uuid4()}}}",
        "ProcessId": process_id,
        "Image": image,
        "User": f"CORP\\{user_name}",
        "Protocol": "tcp",
        "Initiated": True,
        "SourceIp": source_ip,
        "SourcePort": random.randint(49152, 65535),
        "DestinationIp": destination_ip,
        "DestinationPort": destination_port
    }

    raw_xml = (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System>'
        f'<Provider Name="Microsoft-Windows-Sysmon"/>'
        f'<EventID>3</EventID><Version>5</Version>'
        f'<TimeCreated SystemTime="{now_utc}"/>'
        f'<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
        f'<Computer>{device_name}</Computer>'
        f'</System>'
        f'<EventData>'
        f'<Data Name="Image">{image}</Data>'
        f'<Data Name="SourceIp">{source_ip}</Data>'
        f'<Data Name="DestinationIp">{destination_ip}</Data>'
        f'<Data Name="DestinationPort">{destination_port}</Data>'
        f'</EventData>'
        f'</Event>'
    )

    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Sysmon",
        event_id=3,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=device_name,
        event_data=event_data,
        raw_xml=raw_xml,
        level=4,
        event_time=now_utc,
        scenario_id=scenario_id
    )

# -----------------------------------------------------------------------------
# 3. Windows Security Auditing (Event ID 4624 Logon, 4625 Failed Logon, 4688)
# -----------------------------------------------------------------------------
def generate_windows_security_logon_event(
    device_name: str,
    user_name: str,
    source_ip: str,
    is_success: bool = True,
    logon_type: int = 10,  # 2: Interactive, 3: Network, 10: RemoteInteractive (RDP)
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Windows Security Auditing Event ID 4624 (Logon) or 4625 (Failed Logon).
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    event_id = 4624 if is_success else 4625
    user_sid = f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}"

    event_data = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": f"{device_name}$",
        "SubjectDomainName": "CORP",
        "SubjectLogonId": "0x3e7",
        "TargetUserSid": user_sid,
        "TargetUserName": user_name,
        "TargetDomainName": "CORP",
        "TargetLogonId": "0xf1206",
        "LogonType": str(logon_type),
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "WorkstationName": device_name,
        "LogonGuid": f"{{{uuid.uuid4()}}}",
        "ProcessId": "0x2c4",
        "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
        "IpAddress": source_ip,
        "IpPort": str(random.randint(49152, 65535)),
        "ImpersonationLevel": "%%1833",
        "ElevatedToken": "%%1843"
    }
    if not is_success:
        event_data["Status"] = "0xc000006d"
        event_data["SubStatus"] = "0xc0000064"

    raw_xml = (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System>'
        f'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f'<EventID>{event_id}</EventID><Version>2</Version>'
        f'<TimeCreated SystemTime="{now_utc}"/>'
        f'<Channel>Security</Channel>'
        f'<Computer>{device_name}</Computer>'
        f'</System>'
        f'<EventData>'
        f'<Data Name="TargetUserName">{user_name}</Data>'
        f'<Data Name="TargetDomainName">CORP</Data>'
        f'<Data Name="LogonType">{logon_type}</Data>'
        f'<Data Name="IpAddress">{source_ip}</Data>'
        f'</EventData>'
        f'</Event>'
    )

    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_id=event_id,
        channel="Security",
        computer=device_name,
        event_data=event_data,
        raw_xml=raw_xml,
        level=4 if is_success else 3,
        user_id=user_sid,
        event_time=now_utc,
        scenario_id=scenario_id
    )

def generate_powershell_process_event(
    device_name: str,
    user_name: str,
    command_line: str,
    parent_process: str = "explorer.exe",
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Backwards-compatible wrapper: creates a Security 4688 process creation event.
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    event_data = {
        "SubjectUserName": user_name,
        "SubjectDomainName": "CORP",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessCommandLine": command_line,
        "ParentProcessName": f"C:\\Windows\\{parent_process}",
        "ProcessId": str(random.randint(1000, 9000))
    }
    raw_xml = (
        f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f'<System>'
        f'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f'<EventID>4688</EventID>'
        f'<TimeCreated SystemTime="{now_utc}"/>'
        f'<Channel>Security</Channel>'
        f'<Computer>{device_name}</Computer>'
        f'</System>'
        f'<EventData>'
        f'<Data Name="SubjectUserName">{user_name}</Data>'
        f'<Data Name="NewProcessName">{event_data["NewProcessName"]}</Data>'
        f'<Data Name="ProcessCommandLine">{command_line.replace("<", "&lt;").replace(">", "&gt;")}</Data>'
        f'</EventData>'
        f'</Event>'
    )
    return generate_windows_event_envelope(
        provider_name="Microsoft-Windows-Security-Auditing",
        event_id=4688,
        channel="Security",
        computer=device_name,
        event_data=event_data,
        raw_xml=raw_xml,
        event_time=now_utc,
        scenario_id=scenario_id
    )

# -----------------------------------------------------------------------------
# 4. Continuous Baseline Telemetry (Benign)
# -----------------------------------------------------------------------------
def generate_windows_baseline_event() -> Dict[str, Any]:
    """
    Generates a realistic benign host event (PowerShell admin query, Sysmon process creation, or Security logon).
    """
    user = get_random_user()
    device = get_device_for_user(user["username"])
    roll = random.random()

    if roll < 0.40:
        # Benign PowerShell admin command
        script = random.choice(BENIGN_PS_SCRIPTS)
        return generate_powershell_script_block_event(
            device_name=device["device_name"],
            user_name=user["username"],
            script_text=script,
            is_suspicious=False
        )
    elif roll < 0.75:
        # Benign Sysmon Process Creation (e.g. conhost.exe, svchost.exe)
        return generate_sysmon_process_event(
            device_name=device["device_name"],
            user_name=user["username"],
            image="C:\\Windows\\System32\\conhost.exe",
            command_line="\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c echo heartbeat"
        )
    else:
        # Benign interactive logon
        return generate_windows_security_logon_event(
            device_name=device["device_name"],
            user_name=user["username"],
            source_ip="127.0.0.1",
            is_success=True,
            logon_type=2
        )

# For legacy backwards compatibility
def generate_powershell_baseline_event() -> Dict[str, Any]:
    return generate_windows_baseline_event()
