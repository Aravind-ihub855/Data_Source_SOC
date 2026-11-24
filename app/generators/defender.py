import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_device_for_user, get_random_normal_ip, identity, device
from app.util import iso_now, stable_hex

BASELINE_PROCESSES = [
    {"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "parent": "explorer.exe", "cmd": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer'},
    {"name": "excel.exe", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "parent": "explorer.exe", "cmd": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Users\\Finance\\Q4_Budget.xlsx"'},
    {"name": "teams.exe", "path": "C:\\Users\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "parent": "explorer.exe", "cmd": "Teams.exe --process-start-args"},
    {"name": "outlook.exe", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "parent": "explorer.exe", "cmd": "OUTLOOK.EXE"},
    {"name": "code.exe", "path": "C:\\Program Files\\Microsoft VS Code\\Code.exe", "parent": "explorer.exe", "cmd": "Code.exe ."}
]


def _hashes(file_name: str, prefix: str = "") -> Dict[str, str]:
    """The same binary has the same hashes wherever and whenever it is seen."""
    n = file_name.lower()
    return {f"{prefix}SHA1": stable_hex(f"sha1:{n}", 40), f"{prefix}SHA256": stable_hex(f"sha256:{n}", 64),
            f"{prefix}MD5": stable_hex(f"md5:{n}", 32)}


def _device_fields(device_name: str) -> Dict[str, Any]:
    d = device(device_name)
    return {"DeviceId": d["mde_device_id"], "DeviceName": d["fqdn"],
            "MachineGroup": "Servers" if "Server" in d.get("os", "") else "Workstations"}


def generate_defender_process_event(
    device_name: str,
    account_name: str,
    process_name: str,
    process_command_line: str,
    parent_process_name: str = "explorer.exe",
    sha256: Optional[str] = None,
    action_type: str = "ProcessCreated",
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceProcessEvents record.
    """
    t = event_time or iso_now()
    who = identity(account_name)
    hashes = _hashes(process_name)
    if sha256:
        hashes["SHA256"] = sha256
    return {
        **_device_fields(device_name),
        "Timestamp": t,
        "ActionType": action_type,
        "ReportId": random.randint(10000, 99999),
        "FileName": process_name,
        "FolderPath": f"C:\\Windows\\System32\\{process_name}",
        **hashes,
        "FileSize": 452096,
        "ProcessId": random.randint(1000, 9999),
        "ProcessCommandLine": process_command_line,
        "ProcessCreationTime": t,
        "ProcessIntegrityLevel": "High",
        "ProcessTokenElevation": "TokenElevationTypeFull",
        "ProcessVersionInfoCompanyName": "Microsoft Corporation",
        "ProcessVersionInfoProductName": "Microsoft Windows Operating System",
        "ProcessVersionInfoProductVersion": "10.0.22621.1",
        "ProcessVersionInfoOriginalFileName": process_name,
        "AccountDomain": who["domain"],
        "AccountName": who["sam"],
        "AccountSid": who["sid"],
        "AccountUpn": who["upn"],
        "AccountObjectId": who["object_id"],
        "LogonId": 987654,
        "InitiatingProcessFileName": parent_process_name,
        "InitiatingProcessId": random.randint(500, 2000),
        "InitiatingProcessCommandLine": f"{parent_process_name} /n",
        "InitiatingProcessCreationTime": t,
        **_hashes(parent_process_name, "InitiatingProcess"),
        "InitiatingProcessFileSize": 48201736,
        "InitiatingProcessAccountDomain": who["domain"],
        "InitiatingProcessAccountName": who["sam"],
        "InitiatingProcessAccountSid": who["sid"],
        "InitiatingProcessAccountUpn": who["upn"],
        "InitiatingProcessAccountObjectId": who["object_id"],
        "InitiatingProcessLogonId": 987654,
        "InitiatingProcessIntegrityLevel": "Medium",
        "InitiatingProcessTokenElevation": "TokenElevationTypeDefault",
        "InitiatingProcessParentFileName": "explorer.exe",
        "InitiatingProcessParentId": 2284,
        "InitiatingProcessParentCreationTime": t
    }

def generate_defender_network_event(
    device_name: str,
    account_name: str,
    remote_ip: str,
    remote_port: int,
    remote_url: str = "",
    initiating_process: str = "powershell.exe",
    action_type: str = "ConnectionSuccess",
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceNetworkEvents record.
    """
    t = event_time or iso_now()
    return {
        **_device_fields(device_name),
        "Timestamp": t,
        "ActionType": action_type,
        "ReportId": random.randint(1000, 99999),
        "LocalIP": device(device_name)["ip_address"] or "10.0.1.45",
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
        "InitiatingProcessSHA256": _hashes(initiating_process)["SHA256"],
        "InitiatingProcessAccountName": identity(account_name)["sam"],
        "InitiatingProcessLogonId": 987654
    }

def generate_defender_file_event(
    device_name: str,
    account_name: str,
    file_name: str,
    folder_path: str,
    action_type: str = "FileCreated",
    sha256: Optional[str] = None,
    event_time: Optional[str] = None,
    initiating_process: str = "powershell.exe"
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Defender DeviceFileEvents record.
    """
    t = event_time or iso_now()
    hashes = _hashes(folder_path + file_name)
    return {
        **_device_fields(device_name),
        "Timestamp": t,
        "ActionType": action_type,
        "ReportId": random.randint(1000, 99999),
        "FileName": file_name,
        "FolderPath": folder_path,
        "SHA1": hashes["SHA1"],
        "SHA256": sha256 or hashes["SHA256"],
        "FileSize": random.randint(10240, 524288),
        "InitiatingProcessFileName": initiating_process,
        "InitiatingProcessId": random.randint(1000, 9999),
        "InitiatingProcessAccountName": identity(account_name)["sam"]
    }

def generate_defender_baseline_event() -> Dict[str, Any]:
    """
    Generates a regular, non-malicious background endpoint event.
    """
    user = get_random_user()
    dev = get_device_for_user(user["username"])
    proc = random.choice(BASELINE_PROCESSES)

    roll = random.random()
    if roll < 0.70:
        return generate_defender_process_event(
            device_name=dev["device_name"],
            account_name=user["username"],
            process_name=proc["name"],
            process_command_line=proc["cmd"],
            parent_process_name=proc["parent"]
        )
    elif roll < 0.90:
        return generate_defender_network_event(
            device_name=dev["device_name"],
            account_name=user["username"],
            remote_ip=get_random_normal_ip(),
            remote_port=443,
            remote_url="https://graph.microsoft.com/v1.0",
            initiating_process=proc["name"]
        )
    else:
        return generate_defender_file_event(
            device_name=dev["device_name"],
            account_name=user["username"],
            file_name=f"document_{random.randint(100, 999)}.tmp",
            folder_path=f"C:\\Users\\{identity(user['username'])['sam']}\\AppData\\Local\\Temp\\"
        )
