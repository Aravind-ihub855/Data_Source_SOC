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

    event = {
        "Source": "Microsoft Defender for Endpoint",
        "Table": "DeviceProcessEvents",
        "Timestamp": event_time,
        "ReportId": report_id,
        "DeviceId": f"ms-dev-{uuid.uuid4().hex[:8]}",
        "DeviceName": device_name,
        "AccountName": account_name,
        "ActionType": action_type,
        "FileName": process_name,
        "FolderPath": f"C:\\Windows\\System32\\{process_name}",
        "ProcessCommandLine": process_command_line,
        "ProcessId": random.randint(1000, 9999),
        "InitiatingProcessFileName": parent_process_name,
        "InitiatingProcessId": random.randint(500, 2000),
        "SHA256": file_hash,
        "MD5": uuid.uuid4().hex,
        "Simulation": True
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
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceNetworkEvents record.
    """
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
    event = {
        "Source": "Microsoft Defender for Endpoint",
        "Table": "DeviceNetworkEvents",
        "Timestamp": event_time,
        "ReportId": f"DEF-NET-{uuid.uuid4().hex[:10].upper()}",
        "DeviceName": device_name,
        "AccountName": account_name,
        "ActionType": action_type,
        "RemoteIP": remote_ip,
        "RemotePort": remote_port,
        "RemoteUrl": remote_url or f"https://{remote_ip}:{remote_port}",
        "LocalIP": "10.0.1.45",
        "LocalPort": random.randint(49152, 65535),
        "InitiatingProcessFileName": initiating_process,
        "Protocol": "Tcp",
        "Simulation": True
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
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceFileEvents record.
    """
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
    event = {
        "Source": "Microsoft Defender for Endpoint",
        "Table": "DeviceFileEvents",
        "Timestamp": event_time,
        "ReportId": f"DEF-FILE-{uuid.uuid4().hex[:10].upper()}",
        "DeviceName": device_name,
        "AccountName": account_name,
        "ActionType": action_type,
        "FileName": file_name,
        "FolderPath": folder_path,
        "SHA256": uuid.uuid4().hex + uuid.uuid4().hex[:32],
        "Simulation": True
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
