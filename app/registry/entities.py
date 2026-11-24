import random
from typing import Dict, Any, List, Optional

# =============================================================================
# Acme Financial Services: Enterprise Entity, Identity & Asset Graph
# =============================================================================

USERS = [
    {
        "user_id": "USR-001",
        "username": "david.miller",
        "ad_samaccount": "ACME\\dmiller",
        "email": "d.miller@acmefinancial.com",
        "first_name": "David",
        "last_name": "Miller",
        "department": "Finance",
        "role": "Senior Financial Analyst",
        "assigned_device": "FINANCE-PC-01",
        "aws_role": "arn:aws:iam::123456789012:role/FinancialDataViewer",
        "local_account": "david",
        "privileged": False,
        "is_executive": False,
        "access_scope": ["SOX", "Internal_Financials"],
        "peer_group": "Corporate_Finance",
        "normal_hours": "08:00-18:00 EST",
        "normal_locations": ["New York, US", "Boston, US"],
        "active_travel_approval": None
    },
    {
        "user_id": "USR-002",
        "username": "sarah.johnson",
        "ad_samaccount": "ACME\\sjohnson",
        "email": "s.johnson@acmefinancial.com",
        "first_name": "Sarah",
        "last_name": "Johnson",
        "department": "Human Resources",
        "role": "HR Director",
        "assigned_device": "SARAH-LAPTOP-02",
        "aws_role": "arn:aws:iam::123456789012:role/HRRecordsAccess",
        "local_account": "sarah",
        "privileged": False,
        "is_executive": False,
        "access_scope": ["GDPR", "PII_Employee_Records"],
        "peer_group": "HR_Management",
        "normal_hours": "09:00-17:00 EST",
        "normal_locations": ["New York, US"],
        "active_travel_approval": None
    },
    {
        "user_id": "USR-003",
        "username": "michael.anderson",
        "ad_samaccount": "ACME\\manderson",
        "email": "m.anderson@acmefinancial.com",
        "first_name": "Michael",
        "last_name": "Anderson",
        "department": "IT Operations",
        "role": "Senior Cloud Infrastructure Administrator",
        "assigned_device": "IT-ADMIN-01",
        "aws_role": "arn:aws:iam::123456789012:role/CloudDevOpsAdmin",
        "local_account": "admin_manderson",
        "privileged": True,
        "is_executive": False,
        "access_scope": ["Tier-0_Infrastructure", "AWS_Global_Admin", "Active_Directory_Admin"],
        "peer_group": "Domain_Admins",
        "normal_hours": "24x7_OnCall",
        "normal_locations": ["New York, US", "New Jersey, US"],
        "active_travel_approval": None,
        "active_change_ticket": "CR-8821: Approved Sunday Patch Maintenance"
    },
    {
        "user_id": "USR-004",
        "username": "robert.wilson",
        "ad_samaccount": "ACME\\rwilson",
        "email": "r.wilson@acmefinancial.com",
        "first_name": "Robert",
        "last_name": "Wilson",
        "department": "Engineering",
        "role": "Lead Backend Engineer",
        "assigned_device": "APP-SERVER-03",
        "aws_role": "arn:aws:iam::123456789012:role/AppDeveloperRole",
        "local_account": "rwilson",
        "privileged": False,
        "is_executive": False,
        "access_scope": ["Source_Code", "Dev_Database"],
        "peer_group": "Core_Engineering",
        "normal_hours": "10:00-19:00 EST",
        "normal_locations": ["Austin, US", "Remote_US"],
        "active_travel_approval": None
    },
    {
        "user_id": "USR-005",
        "username": "emma.davis",
        "ad_samaccount": "ACME\\edavis",
        "email": "e.davis@acmefinancial.com",
        "first_name": "Emma",
        "last_name": "Davis",
        "department": "Cybersecurity",
        "role": "Lead Incident Response Analyst",
        "assigned_device": "SEC-ANALYST-01",
        "aws_role": "arn:aws:iam::123456789012:role/SecurityAuditRole",
        "local_account": "sec_edavis",
        "privileged": True,
        "is_executive": False,
        "access_scope": ["SIEM_Admin", "EDR_Admin", "Forensics_Evidence"],
        "peer_group": "SecOps_Tier3",
        "normal_hours": "08:00-17:00 EST",
        "normal_locations": ["New York, US"],
        "active_travel_approval": None
    },
    {
        "user_id": "USR-006",
        "username": "jennifer.brown",
        "ad_samaccount": "ACME\\jbrown",
        "email": "j.brown@acmefinancial.com",
        "first_name": "Jennifer",
        "last_name": "Brown",
        "department": "Executive Leadership",
        "role": "Chief Financial Officer (CFO)",
        "assigned_device": "EXEC-LAPTOP-01",
        "aws_role": "arn:aws:iam::123456789012:role/ExecutiveFinancialReports",
        "local_account": "jennifer",
        "privileged": True,
        "is_executive": True,
        "access_scope": ["SEC_Reporting", "Corporate_Treasury", "M&A_Confidential", "KYC_Master"],
        "peer_group": "C_Suite_Executives",
        "normal_hours": "Flexible_Global",
        "normal_locations": ["New York, US", "London, UK", "Geneva, Switzerland"],
        "active_travel_approval": "TRAVEL-2026-UK: London Investor Summit (Nov 18-24, 2026)"
    },
    {
        "user_id": "USR-SVC-01",
        "username": "svc-backup-daemon",
        "ad_samaccount": "ACME\\svc_backup",
        "email": "svc-backup@acmefinancial.com",
        "first_name": "Service",
        "last_name": "Account (Backup)",
        "department": "IT Operations",
        "role": "Automated Backup Daemon",
        "assigned_device": "DB-PROD-01",
        "aws_role": "arn:aws:iam::123456789012:role/S3BackupAutomationRole",
        "local_account": "svc_backup",
        "privileged": True,
        "is_executive": False,
        "is_service_account": True,
        "access_scope": ["Disaster_Recovery", "S3_Encrypted_Snapshots"],
        "peer_group": "Automated_Service_Principals",
        "normal_hours": "01:00-05:00 UTC",
        "normal_locations": ["Internal_Subnet_10.0.4.0/24"],
        "active_travel_approval": None
    }
]

DEVICES = [
    {
        "device_id": "DEV-001",
        "device_name": "FINANCE-PC-01",
        "assigned_user": "david.miller",
        "ip_address": "10.0.1.45",
        "mac_address": "00:1B:44:11:3A:B7",
        "os": "Windows 11 Enterprise 23H2",
        "tier": "Tier-2",
        "criticality": "Medium",
        "business_function": "Quarterly Financial Reporting",
        "regulatory_impact": ["SOX"],
        "isolation_risk": "LOW (Standard Workstation, no production dependencies)"
    },
    {
        "device_id": "DEV-002",
        "device_name": "SARAH-LAPTOP-02",
        "assigned_user": "sarah.johnson",
        "ip_address": "10.0.1.78",
        "mac_address": "00:1B:44:11:3A:C2",
        "os": "Windows 11 Enterprise 23H2",
        "tier": "Tier-2",
        "criticality": "Low",
        "business_function": "HR & Employee Onboarding",
        "regulatory_impact": ["GDPR"],
        "isolation_risk": "LOW (Standard Laptop)"
    },
    {
        "device_id": "DEV-003",
        "device_name": "IT-ADMIN-01",
        "assigned_user": "michael.anderson",
        "ip_address": "10.0.1.15",
        "mac_address": "00:1B:44:11:3A:D9",
        "os": "Windows 11 Enterprise 23H2",
        "tier": "Tier-1",
        "criticality": "High",
        "business_function": "Administrative Jumpbox",
        "regulatory_impact": ["SOC2", "PCI-DSS"],
        "isolation_risk": "MEDIUM (Admin access disruption)"
    },
    {
        "device_id": "DEV-004",
        "device_name": "FINANCE-SRV-01",
        "assigned_user": "david.miller",
        "ip_address": "10.0.4.12",
        "mac_address": "00:1B:44:22:8C:01",
        "os": "Windows Server 2022 Datacenter",
        "tier": "Tier-1",
        "criticality": "High",
        "business_function": "Financial Ledger Batch Processor",
        "regulatory_impact": ["SOX", "DORA"],
        "isolation_risk": "HIGH (Disrupts end-of-day ledger reconciliation)"
    },
    {
        "device_id": "DEV-005",
        "device_name": "APP-SERVER-03",
        "assigned_user": "robert.wilson",
        "ip_address": "10.0.4.55",
        "mac_address": "00:1B:44:22:8C:33",
        "os": "Ubuntu Linux 22.04 LTS",
        "tier": "Tier-1",
        "criticality": "High",
        "business_function": "Customer API Gateway",
        "regulatory_impact": ["PCI-DSS", "DORA"],
        "isolation_risk": "HIGH (Customer service downtime)"
    },
    {
        "device_id": "DEV-006",
        "device_name": "DB-PROD-01",
        "assigned_user": "michael.anderson",
        "ip_address": "10.0.4.99",
        "mac_address": "00:1B:44:22:8C:99",
        "os": "Windows Server 2022 Datacenter",
        "tier": "Tier-0",
        "criticality": "Mission_Critical",
        "business_function": "Core Transactional Database & Customer KYC Store",
        "regulatory_impact": ["PCI-DSS", "GDPR", "SOX", "SEC_Materiality"],
        "isolation_risk": "CRITICAL (Immediate global transaction outage; requires VP sign-off)"
    },
    {
        "device_id": "DEV-007",
        "device_name": "EXEC-LAPTOP-01",
        "assigned_user": "jennifer.brown",
        "ip_address": "10.0.1.5",
        "mac_address": "00:1B:44:11:3A:EE",
        "os": "Windows 11 Enterprise 23H2 (Secured-Core)",
        "tier": "Tier-0",
        "criticality": "Executive_Critical",
        "business_function": "CFO Workstation - M&A & Treasury Authorizations",
        "regulatory_impact": ["SEC_Materiality", "SOX"],
        "isolation_risk": "CRITICAL (Executive disruption; requires CISO / Legal alert)"
    }
]

# Threat Actor Infrastructure & Benign Scanning Pools
NORMAL_EXTERNAL_IPS = [
    {"ip": "198.51.100.10", "reputation": "CLEAN", "category": "Microsoft 365 Exchange Gateway"},
    {"ip": "198.51.100.14", "reputation": "CLEAN", "category": "Corporate AWS DirectConnect VPN"},
    {"ip": "203.0.113.15", "reputation": "BENIGN_SCANNER", "category": "Internal Nessus Vulnerability Scanner"},
    {"ip": "81.2.69.142", "reputation": "CLEAN", "category": "London Corporate Branch Gateway"}
]

SUSPICIOUS_EXTERNAL_IPS = [
    {"ip": "194.26.29.112", "location": "Kyiv, Ukraine", "category": "Tor Exit Node / Cobalt Strike C2", "confidence": 0.98},
    {"ip": "185.220.101.5", "location": "Frankfurt, Germany", "category": "Bulletproof Proxy / AiTM Proxy", "confidence": 0.88},
    {"ip": "45.33.32.156", "location": "Amsterdam, Netherlands", "category": "Fast Flux Staging Server", "confidence": 0.92}
]

AWS_ACCOUNTS = [
    {
        "account_id": "123456789012",
        "account_alias": "acme-financial-prod",
        "region": "us-east-1",
        "s3_buckets": [
            {"name": "acme-financial-exports-prod", "classification": "CONFIDENTIAL", "regulatory": "SOX"},
            {"name": "acme-payroll-data-encrypted", "classification": "RESTRICTED_PII", "regulatory": "GDPR"},
            {"name": "acme-customer-kyc-documents", "classification": "HIGHLY_RESTRICTED", "regulatory": "PCI_DSS"}
        ]
    }
]

# -------------------------------------------------------------
# Entity Resolution & Cross-Platform Pivot Functions
# -------------------------------------------------------------

def resolve_identity(identifier: str) -> Optional[Dict[str, Any]]:
    """
    Performs identity resolution across Entra UPN, Active Directory SAM account,
    AWS IAM ARN, and local OS account names.
    """
    if not identifier:
        return None
    raw = identifier.lower().strip()
    for u in USERS:
        if (
            raw == u["username"].lower()
            or raw == u["email"].lower()
            or raw == u["ad_samaccount"].lower()
            or raw == u["ad_samaccount"].split("\\")[-1].lower()
            or raw == u["local_account"].lower()
            or raw == u["aws_role"].lower()
            or raw in u["aws_role"].lower()
        ):
            return u
    return None

def resolve_device(device_id_or_name: str) -> Optional[Dict[str, Any]]:
    if not device_id_or_name:
        return None
    raw = device_id_or_name.lower().strip()
    for d in DEVICES:
        if raw == d["device_name"].lower() or raw == d["device_id"].lower() or raw == d["ip_address"].lower():
            return d
    return None

def get_all_users() -> List[Dict[str, Any]]:
    return USERS

def get_random_user() -> Dict[str, Any]:
    return random.choice(USERS)

def get_all_devices() -> List[Dict[str, Any]]:
    return DEVICES

def get_random_normal_ip() -> str:
    item = random.choice(NORMAL_EXTERNAL_IPS)
    return item["ip"] if isinstance(item, dict) else item

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    for u in USERS:
        if u.get("user_id") == user_id:
            return u
    return None

def get_device_by_id(device_id: str) -> Optional[Dict[str, Any]]:
    for d in DEVICES:
        if d.get("device_id") == device_id:
            return d
    return None

def get_device_by_name(device_name: str) -> Optional[Dict[str, Any]]:
    return resolve_device(device_name)

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    return resolve_identity(username)

def get_device_for_user(username: str) -> Dict[str, Any]:
    u = resolve_identity(username)
    if u and u.get("assigned_device"):
        dev = resolve_device(u["assigned_device"])
        if dev:
            return dev
    return DEVICES[0]

def get_suspicious_ip(index: int = 0) -> Dict[str, Any]:
    return SUSPICIOUS_EXTERNAL_IPS[index % len(SUSPICIOUS_EXTERNAL_IPS)]

def get_primary_aws_account() -> Dict[str, Any]:
    return AWS_ACCOUNTS[0]
