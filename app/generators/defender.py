import uuid
import datetime
import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_device_for_user, get_random_normal_ip

BASELINE_PROCESSES = [
    {"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent": "explorer.exe", "cmd": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer'},
    {"name": "excel.exe", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "parent": "explorer.exe", "cmd": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Users\\Finance\\Q4_Budget.xlsx"'},
    {"name": "teams.exe", "path": "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "parent": "explorer.exe", "cmd": "Teams.exe --process-start-args"},
    {"name": "outlook.exe", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "parent": "explorer.exe", "cmd": "OUTLOOK.EXE"},
    {"name": "code.exe", "path": "C:\\Program Files\\Microsoft VS Code\\Code.exe", "parent": "explorer.exe", "cmd": "Code.exe ."}
]

def generate_defender_process_event(
    device_name: str,
    account_name: str,
    process_name: str,
    process_command_line: str,
    parent_process_name: str = "explorer.exe",
    sha256: Optional[str] = None,
    action_type: str = "ProcessCreated",
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceProcessEvents record.
    """
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
    report_id = f"DEF-{uuid.uuid4().hex[:12].upper()}"
    file_hash = sha256 or uuid.uuid4().hex + uuid.uuid4().hex[:32]

    sha1_val = (uuid.uuid4().hex + uuid.uuid4().hex[:8]).lower()
    event = {
        "DeviceId": (uuid.uuid4().hex + uuid.uuid4().hex[:8]).lower(),
        "DeviceName": device_name,
        "MachineGroup": "Workstations",
        "Timestamp": event_time,
        "ActionType": action_type,
        "ReportId": random.randint(10000, 99999),
        "FileName": process_name,
        "FolderPath": f"C:\\Windows\\System32\\{process_name}",
        "SHA1": sha1_val,
        "SHA256": file_hash,
        "MD5": uuid.uuid4().hex,
        "FileSize": 452096,
        "ProcessId": random.randint(1000, 9999),
        "ProcessCommandLine": process_command_line,
        "ProcessCreationTime": event_time,
        "ProcessIntegrityLevel": "High",
        "ProcessTokenElevation": "TokenElevationTypeFull",
        "ProcessVersionInfoCompanyName": "Microsoft Corporation",
        "ProcessVersionInfoProductName": "Microsoft Windows Operating System",
        "ProcessVersionInfoProductVersion": "10.0.22621.1",
        "ProcessVersionInfoOriginalFileName": process_name,
        "AccountDomain": "CORP",
        "AccountName": account_name,
        "AccountSid": f"S-1-5-21-111-222-333-{random.randint(1000, 9999)}",
        "AccountUpn": f"{account_name}@example.com",
        "AccountObjectId": str(uuid.uuid4()),
        "LogonId": 987654,
        "InitiatingProcessFileName": parent_process_name,
        "InitiatingProcessId": random.randint(500, 2000),
        "InitiatingProcessCommandLine": f"{parent_process_name} /n",
        "InitiatingProcessCreationTime": event_time,
        "InitiatingProcessSHA1": (uuid.uuid4().hex + uuid.uuid4().hex[:8]).lower(),
        "InitiatingProcessSHA256": file_hash,
        "InitiatingProcessMD5": uuid.uuid4().hex,
        "InitiatingProcessFileSize": 48201736,
        "InitiatingProcessAccountDomain": "CORP",
        "InitiatingProcessAccountName": account_name,
        "InitiatingProcessAccountSid": f"S-1-5-21-111-222-333-{random.randint(1000, 9999)}",
        "InitiatingProcessAccountUpn": f"{account_name}@example.com",
        "InitiatingProcessAccountObjectId": str(uuid.uuid4()),
        "InitiatingProcessLogonId": 987654,
        "InitiatingProcessIntegrityLevel": "Medium",
        "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
        "InitiatingProcessParentFileName": "explorer.exe",
        "InitiatingProcessParentId": 2284,
        "InitiatingProcessParentCreationTime": event_time
    }
    if scenario_id:
        event["ScenarioId"] = scenario_id
    return event

def generate_defender_network_event(
    device_name: str,
    account_name: str,
    remote_ip: str,
    remote_port: int,
    remote_url: str = "",
    initiating_process: str = "powershell.exe",
    action_type: str = "ConnectionSuccess",
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceNetworkEvents record.
    """
    t = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    event = {
        "DeviceId": (uuid.uuid4().hex + uuid.uuid4().hex[:8]).lower(),
        "DeviceName": device_name,
        "MachineGroup": "Workstations",
        "Timestamp": t,
        "ActionType": action_type,
        "ReportId": random.randint(1000, 99999),
        "LocalIP": "10.0.1.45",
        "LocalPort": random.randint(49152, 65535),
        "LocalIPType": "Private",
        "RemoteIP": remote_ip,
        "RemotePort": remote_port,
        "RemoteIPType": "Public",
        "RemoteUrl": remote_url or f"https://{remote_ip}:{remote_port}",
        "Protocol": "Tcp",
        "InitiatingProcessFileName": initiating_process,
        "InitiatingProcessId": random.randint(1000, 9999),
        "InitiatingProcessCommandLine": f"{initiating_process} -exec",
        "InitiatingProcessSHA256": (uuid.uuid4().hex + uuid.uuid4().hex[:32]).lower(),
        "InitiatingProcessAccountName": account_name,
        "InitiatingProcessLogonId": 987654
    }
    if scenario_id:
        event["ScenarioId"] = scenario_id
    return event

def generate_defender_file_event(
    device_name: str,
    account_name: str,
    file_name: str,
    folder_path: str,
    action_type: str = "FileCreated",
    sha256: Optional[str] = None,
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None,
    initiating_process: str = "powershell.exe"
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceFileEvents record.
    """
    t = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    event = {
        "DeviceId": (uuid.uuid4().hex + uuid.uuid4().hex[:8]).lower(),
        "DeviceName": device_name,
        "MachineGroup": "Workstations",
        "Timestamp": t,
        "ActionType": action_type,
        "ReportId": random.randint(1000, 99999),
        "FileName": file_name,
        "FolderPath": folder_path,
        "SHA1": (uuid.uuid4().hex + uuid.uuid4().hex[:8]).lower(),
        "SHA256": sha256 or (uuid.uuid4().hex + uuid.uuid4().hex[:32]).lower(),
        "FileSize": random.randint(10240, 524288),
        "InitiatingProcessFileName": initiating_process,
        "InitiatingProcessId": random.randint(1000, 9999),
        "InitiatingProcessAccountName": account_name
    }
    if scenario_id:
        event["ScenarioId"] = scenario_id
    return event

def generate_defender_baseline_event() -> Dict[str, Any]:
    """
    Generates a regular, non-malicious background endpoint event.
    """
    user = get_random_user()
    device = get_device_for_user(user["username"])
    proc = random.choice(BASELINE_PROCESSES)
    
    roll = random.random()
    if roll < 0.70:
        return generate_defender_process_event(
            device_name=device["device_name"],
            account_name=user["username"],
            process_name=proc["name"],
            process_command_line=proc["cmd"],
            parent_process_name=proc["parent"]
        )
    elif roll < 0.90:
        return generate_defender_network_event(
            device_name=device["device_name"],
            account_name=user["username"],
            remote_ip=get_random_normal_ip(),
            remote_port=443,
            remote_url="https://graph.microsoft.com/v1.0",
            initiating_process=proc["name"]
        )
    else:
        return generate_defender_file_event(
            device_name=device["device_name"],
            account_name=user["username"],
            file_name=f"document_{random.randint(100, 999)}.tmp",
            folder_path="C:\\Users\\AppData\\Local\\Temp\\"
        )
