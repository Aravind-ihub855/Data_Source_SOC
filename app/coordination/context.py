import random
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from app.registry.entities import (
    users,
    devices,
    tenant,
    SUSPICIOUS_EXTERNAL_IPS,
    NORMAL_EXTERNAL_IPS,
    get_primary_aws_account,
    resolve_identity,
    resolve_device
)
from app.util import iso_now, new_uuid


@dataclass
class ScenarioContext:
    """
    Centralized, consistent entity binding for scenario runs.
    Ensures all 5 sources reference the exact same users, devices, IPs, and cloud principals.
    """
    scenario_id: str
    tenant_id: str = "tnt-acme"
    correlation_id: str = field(default_factory=lambda: f"corr-{new_uuid()[:12]}")
    execution_id: str = field(default_factory=lambda: f"run-{new_uuid()[:8]}")
    start_time: str = field(default_factory=iso_now)

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
    process_guid: str = field(default_factory=lambda: f"{{{new_uuid()}}}")
    parent_process_guid: str = field(default_factory=lambda: f"{{{new_uuid()}}}")
    session_id: str = field(default_factory=lambda: str(random.randint(1000000, 9999999)))


def build_scenario_context(
    scenario_id: str,
    username: Optional[str] = None,
    device_name: Optional[str] = None,
    suspicious_ip_index: Optional[int] = None
) -> ScenarioContext:
    """
    Binds a scenario to realistic, internally consistent entities of the current tenant.
    One attacker IP, one user and one device are chosen here and reused by every step.
    """
    user = resolve_identity(username) if username else random.choice(
        [u for u in users() if not u.get("is_service_account")])
    user = user or users()[0]
    device = resolve_device(device_name or user.get("assigned_device") or "") or devices()[0]
    suspicious = SUSPICIOUS_EXTERNAL_IPS[random.randrange(len(SUSPICIOUS_EXTERNAL_IPS))
                                         if suspicious_ip_index is None else suspicious_ip_index % len(SUSPICIOUS_EXTERNAL_IPS)]
    aws_info = get_primary_aws_account()

    return ScenarioContext(
        scenario_id=scenario_id,
        tenant_id=tenant()["tenant_id"],
        target_user=user,
        target_device=device,
        internal_ip=device["ip_address"],
        attacker_ip=suspicious["ip"],
        normal_ip=random.choice(NORMAL_EXTERNAL_IPS)["ip"],
        aws_account_id=aws_info["account_id"],
        aws_region=aws_info["region"],
        user_arn=f"arn:aws:iam::{aws_info['account_id']}:user/{user['username']}",
        role_arn=user.get("aws_role") or f"arn:aws:iam::{aws_info['account_id']}:role/AdministratorAccess",
    )
