import random
from typing import Dict, Any, List, Optional

# Fictional Enterprise Entity Database: Acme Financial Services
USERS = [
    {
        "user_id": "USR-001",
        "username": "david.miller",
        "email": "d.miller@acmefinancial.com",
        "first_name": "David",
        "last_name": "Miller",
        "department": "Finance",
        "role": "Senior Financial Analyst",
        "assigned_device": "FINANCE-PC-01",
        "aws_role": "arn:aws:iam::123456789012:role/FinancialDataViewer",
        "privileged": False
    },
    {
        "user_id": "USR-002",
        "username": "sarah.johnson",
        "email": "s.johnson@acmefinancial.com",
        "first_name": "Sarah",
        "last_name": "Johnson",
        "department": "Human Resources",
        "role": "HR Director",
        "assigned_device": "SARAH-LAPTOP-02",
        "aws_role": "arn:aws:iam::123456789012:role/HRRecordsAccess",
        "privileged": False
    },
    {
        "user_id": "USR-003",
        "username": "michael.anderson",
        "email": "m.anderson@acmefinancial.com",
        "first_name": "Michael",
        "last_name": "Anderson",
        "department": "IT Operations",
        "role": "Senior Cloud Infrastructure Administrator",
        "assigned_device": "IT-ADMIN-01",
        "aws_role": "arn:aws:iam::123456789012:role/CloudDevOpsAdmin",
        "privileged": True
    },
    {
        "user_id": "USR-004",
        "username": "robert.wilson",
        "email": "r.wilson@acmefinancial.com",
        "first_name": "Robert",
        "last_name": "Wilson",
        "department": "Engineering",
        "role": "Lead Backend Engineer",
        "assigned_device": "APP-SERVER-03",
        "aws_role": "arn:aws:iam::123456789012:role/AppDeveloperRole",
        "privileged": False
    },
    {
        "user_id": "USR-005",
        "username": "emma.davis",
        "email": "e.davis@acmefinancial.com",
        "first_name": "Emma",
        "last_name": "Davis",
        "department": "Cybersecurity",
        "role": "Lead Incident Response Analyst",
        "assigned_device": "SEC-ANALYST-01",
        "aws_role": "arn:aws:iam::123456789012:role/SecurityAuditRole",
        "privileged": True
    },
    {
        "user_id": "USR-006",
        "username": "jennifer.brown",
        "email": "j.brown@acmefinancial.com",
        "first_name": "Jennifer",
        "last_name": "Brown",
        "department": "Executive",
        "role": "Chief Financial Officer",
        "assigned_device": "EXEC-LAPTOP-01",
        "aws_role": "arn:aws:iam::123456789012:role/ExecutiveExecutiveReports",
        "privileged": True
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
        "criticality": "Medium"
    },
    {
        "device_id": "DEV-002",
        "device_name": "SARAH-LAPTOP-02",
        "assigned_user": "sarah.johnson",
        "ip_address": "10.0.1.78",
        "mac_address": "00:1B:44:11:3A:C2",
        "os": "Windows 11 Enterprise 23H2",
        "criticality": "Low"
    },
    {
        "device_id": "DEV-003",
        "device_name": "IT-ADMIN-01",
        "assigned_user": "michael.anderson",
        "ip_address": "10.0.1.15",
        "mac_address": "00:1B:44:11:3A:D9",
        "os": "Windows 11 Enterprise 23H2",
        "criticality": "Critical"
    },
    {
        "device_id": "DEV-004",
        "device_name": "FINANCE-SRV-01",
        "assigned_user": "david.miller",
        "ip_address": "10.0.4.12",
        "mac_address": "00:1B:44:22:8C:01",
        "os": "Windows Server 2022 Datacenter",
        "criticality": "High"
    },
    {
        "device_id": "DEV-005",
        "device_name": "APP-SERVER-03",
        "assigned_user": "robert.wilson",
        "ip_address": "10.0.4.55",
        "mac_address": "00:1B:44:22:8C:33",
        "os": "Ubuntu Linux 22.04 LTS",
        "criticality": "High"
    },
    {
        "device_id": "DEV-006",
        "device_name": "DB-PROD-01",
        "assigned_user": "michael.anderson",
        "ip_address": "10.0.4.99",
        "mac_address": "00:1B:44:22:8C:99",
        "os": "Windows Server 2022 Datacenter",
        "criticality": "Critical"
    }
]

# Synthetic Safe External IP Pools (RFC 5737 documentation test addresses)
NORMAL_EXTERNAL_IPS = [
    "198.51.100.10",
    "198.51.100.14",
    "198.51.100.50",
    "203.0.113.15",
    "203.0.113.88"
]

SUSPICIOUS_EXTERNAL_IPS = [
    {"ip": "194.26.29.112", "location": "Kyiv, Ukraine", "category": "Tor Exit Node / Cobalt Strike C2"},
    {"ip": "198.51.100.25", "location": "Bucharest, Romania", "category": "Bulletproof Proxy / Credential Stuffing"},
    {"ip": "203.0.113.200", "location": "St. Petersburg, Russia", "category": "APT29 Known Scanning Range"}
]

AWS_ACCOUNTS = [
    {
        "account_id": "123456789012",
        "account_alias": "acme-financial-prod",
        "region": "us-east-1",
        "s3_buckets": [
            "acme-financial-exports-prod",
            "acme-payroll-data-encrypted",
            "acme-customer-kyc-documents"
        ]
    }
]

# -------------------------------------------------------------
# Reusable Getter Functions
# -------------------------------------------------------------

def get_all_users() -> List[Dict[str, Any]]:
    return USERS

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    for u in USERS:
        if u["username"].lower() == username.lower():
            return u
    return None

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    for u in USERS:
        if u["user_id"] == user_id:
            return u
    return None

def get_random_user(only_privileged: bool = False) -> Dict[str, Any]:
    pool = [u for u in USERS if u.get("privileged")] if only_privileged else USERS
    return random.choice(pool)

def get_all_devices() -> List[Dict[str, Any]]:
    return DEVICES

def get_device_by_name(device_name: str) -> Optional[Dict[str, Any]]:
    for d in DEVICES:
        if d["device_name"].upper() == device_name.upper():
            return d
    return None

def get_device_for_user(username: str) -> Dict[str, Any]:
    user = get_user_by_username(username)
    if user and user.get("assigned_device"):
        device = get_device_by_name(user["assigned_device"])
        if device:
            return device
    return DEVICES[0]

def get_random_device() -> Dict[str, Any]:
    return random.choice(DEVICES)

def get_random_normal_ip() -> str:
    return random.choice(NORMAL_EXTERNAL_IPS)

def get_suspicious_ip(index: int = 0) -> Dict[str, str]:
    return SUSPICIOUS_EXTERNAL_IPS[index % len(SUSPICIOUS_EXTERNAL_IPS)]

def get_primary_aws_account() -> Dict[str, Any]:
    return AWS_ACCOUNTS[0]
