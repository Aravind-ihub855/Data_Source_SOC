import uuid
import datetime
import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_device_for_user

BENIGN_SCRIPTS = [
    "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 10",
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5",
    "Test-Connection -ComputerName 10.0.1.1 -Count 2 -Quiet",
    "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'",
    "$PSVersionTable.PSVersion",
    "Get-ChildItem -Path C:\\Logs -Filter *.log | Measure-Object -Property Length -Sum",
    "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, OSArchitecture"
]

def generate_powershell_script_block_event(
    device_name: str,
    user_name: str,
    script_text: str,
    is_suspicious: bool = False,
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate a Windows PowerShell Event ID 4104 (ScriptBlockLogging) record.
    """
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
    activity_id = f"PS-{uuid.uuid4().hex[:8].upper()}"

    event = {
        "Source": "Microsoft-Windows-PowerShell",
        "EventID": 4104,
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "Computer": device_name,
        "TimeCreated": event_time,
        "ActivityId": activity_id,
        "ExecutionProcessId": random.randint(1200, 8900),
        "UserId": f"S-1-5-21-{random.randint(100000, 999999)}-500",
        "UserName": user_name,
        "ScriptBlockId": str(uuid.uuid4()),
        "Message": "Creating Scriptblock text (1 of 1)",
        "ScriptBlockText": script_text,
        "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "Level": "Warning" if is_suspicious else "Information",
        "Simulation": True
    }
    if scenario_id:
        event["ScenarioId"] = scenario_id
    return event

def generate_powershell_process_event(
    device_name: str,
    user_name: str,
    command_line: str,
    parent_process: str = "explorer.exe",
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate a Windows Security Event ID 4688 for PowerShell Process Execution.
    """
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
    event = {
        "Source": "Microsoft-Windows-Security-Auditing",
        "EventID": 4688,
        "Channel": "Security",
        "Computer": device_name,
        "TimeCreated": event_time,
        "SubjectUserName": user_name,
        "SubjectDomainName": "ACME",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ProcessCommandLine": command_line,
        "ParentProcessName": f"C:\\Windows\\{parent_process}",
        "ProcessId": random.randint(1500, 9200),
        "Simulation": True
    }
    if scenario_id:
        event["ScenarioId"] = scenario_id
    return event

def generate_powershell_baseline_event() -> Dict[str, Any]:
    """
    Generates a normal, non-malicious background PowerShell script block or command event.
    """
    user = get_random_user()
    device = get_device_for_user(user["username"])
    script = random.choice(BENIGN_SCRIPTS)

    if random.random() < 0.65:
        return generate_powershell_script_block_event(
            device_name=device["device_name"],
            user_name=user["username"],
            script_text=script,
            is_suspicious=False
        )
    else:
        return generate_powershell_process_event(
            device_name=device["device_name"],
            user_name=user["username"],
            command_line=f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{script}"'
        )
