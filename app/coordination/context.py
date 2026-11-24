import uuid
import datetime
import random
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from app.registry.entities import (
    USERS,
    DEVICES,
    SUSPICIOUS_EXTERNAL_IPS,
    NORMAL_EXTERNAL_IPS,
    get_primary_aws_account,
    resolve_identity,
    resolve_device
)

@dataclass
class ScenarioContext:
    """
    Centralized, consistent entity binding for scenario runs.
    Ensures all 5 sources reference the exact same users, devices, IPs, and cloud principals.
    """
    scenario_id: str
    correlation_id: str = field(default_factory=lambda: f"corr-{uuid.uuid4().hex[:12]}")
    execution_id: str = field(default_factory=lambda: f"run-{uuid.uuid4().hex[:8]}")
    start_time: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    
    # Target User & Host Entities
    target_user: Dict[str, Any] = field(default_factory=dict)
    target_device: Dict[str, Any] = field(default_factory=dict)
    
    # Network Infrastructure
    internal_ip: str = "10.0.1.45"
    attacker_ip: str = "198.51.100.77"
    normal_ip: str = "203.0.113.10"
    c2_domain: str = "updates-corporate-sync.org"
    
    # Cloud Principal
    aws_account_id: str = "123456789012"
    aws_region: str = "us-east-1"
    user_arn: str = "arn:aws:iam::123456789012:user/j.doe"
    role_arn: str = "arn:aws:iam::123456789012:role/AdministratorAccess"
    
    # Process Identifiers
    process_guid: str = field(default_factory=lambda: f"{{{uuid.uuid4()}}}")
    parent_process_guid: str = field(default_factory=lambda: f"{{{uuid.uuid4()}}}")
    session_id: str = field(default_factory=lambda: str(random.randint(1000000, 9999999)))

def build_scenario_context(
    scenario_id: str,
    username: Optional[str] = None,
    device_name: Optional[str] = None,
    suspicious_ip_index: int = 0
) -> ScenarioContext:
    """
    Dynamically binds a scenario to realistic, internally consistent entities.
    """
    # 1. Resolve User
    if username:
        user = resolve_identity(username)
    else:
        # Pick from active users, biasing towards realistic departmental roles
        user = random.choice([u for u in USERS if not u.get("is_service_account")])
    if not user:
        user = USERS[0]

    # 2. Resolve Device for this User
    assigned_device_name = device_name or user.get("assigned_device") or "FINANCE-PC-01"
    device = resolve_device(assigned_device_name)
    if not device:
        device = DEVICES[0]

    # 3. Resolve Threat Actor Infrastructure
    suspicious = SUSPICIOUS_EXTERNAL_IPS[suspicious_ip_index % len(SUSPICIOUS_EXTERNAL_IPS)]
    normal_item = random.choice(NORMAL_EXTERNAL_IPS)
    normal_ip = normal_item["ip"] if isinstance(normal_item, dict) else normal_item

    # 4. Resolve Cloud Account
    aws_info = get_primary_aws_account()

    # 5. Extract Real Account Names
    u_name = user["username"]
    upn = user["email"]
    account_name = user.get("local_account") or u_name.split(".")[0]

    return ScenarioContext(
        scenario_id=scenario_id,
        correlation_id=f"corr-{uuid.uuid4().hex[:12]}",
        execution_id=f"run-{uuid.uuid4().hex[:8]}",
        target_user=user,
        target_device=device,
        internal_ip=device.get("ip_address", "10.0.1.45"),
        attacker_ip=suspicious["ip"],
        normal_ip=normal_ip,
        aws_account_id=aws_info["account_id"],
        aws_region=aws_info["region"],
        user_arn=f"arn:aws:iam::{aws_info['account_id']}:user/{u_name}",
        role_arn=user.get("aws_role") or "arn:aws:iam::123456789012:role/AdministratorAccess",
        process_guid=f"{{{uuid.uuid4()}}}",
        parent_process_guid=f"{{{uuid.uuid4()}}}",
        session_id=str(random.randint(1000000, 9999999))
    )
