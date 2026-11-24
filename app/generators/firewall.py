import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_normal_ip, get_suspicious_ip, identity, tenant, devices
from app.util import iso_now, parse_iso

COMMON_RULES = [
    {"name": "Outbound-Web-Traffic", "port": 443, "proto": "TCP", "app": "ssl", "zone_src": "trust", "zone_dst": "untrust"},
    {"name": "Outbound-DNS", "port": 53, "proto": "UDP", "app": "dns", "zone_src": "trust", "zone_dst": "untrust"},
    {"name": "Inbound-DMZ-HTTPS", "port": 443, "proto": "TCP", "app": "ssl", "zone_src": "untrust", "zone_dst": "dmz"},
    {"name": "Default-Interzone-Deny", "port": 22, "proto": "TCP", "app": "ssh", "zone_src": "untrust", "zone_dst": "trust"}
]


def _cef_value(v: Any) -> str:
    """CEF extension escaping: backslash, equals sign and line breaks."""
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def generate_firewall_cef_event(
    device_name: Optional[str] = None,
    device_vendor: str = "ExampleVendor",
    device_product: str = "ExampleNGFW",
    device_version: str = "10.2",
    signature_id: str = "8001",
    name: str = "Outbound connection",
    severity: int = 5,
    source_ip: str = "10.20.4.15",
    source_port: int = 53122,
    destination_ip: str = "198.51.100.77",
    destination_port: int = 443,
    protocol: str = "TCP",
    action: str = "allow",
    rule_name: str = "Outbound-Web",
    direction: str = "outbound",
    log_type: str = "traffic",
    application: str = "ssl",
    bytes_out: int = 2048,
    bytes_in: int = 8192,
    packets_out: int = 12,
    packets_in: int = 18,
    session_id: Optional[str] = None,
    threat_name: Optional[str] = None,
    threat_category: Optional[str] = None,
    user: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a vendor-neutral Next-Gen Firewall record conforming to 05_firewall.schema.json.
    Includes both raw_message (CEF format) and structured parsed_fields.
    """
    now_utc = event_time or iso_now()
    fw = device_name or tenant()["firewall"]
    sess_id = session_id or str(random.randint(1000000, 9999999))
    suser = None
    if user:
        who = identity(user)
        suser = f"{who['domain']}\\{who['sam']}"

    extensions = [
        ("rt", int(parse_iso(now_utc).timestamp() * 1000)),
        ("src", source_ip), ("spt", source_port), ("dst", destination_ip), ("dpt", destination_port),
        ("proto", protocol), ("act", action), ("deviceExternalId", fw),
        ("cs1", rule_name), ("cs1Label", "RuleName"),
        ("out", bytes_out), ("in", bytes_in), ("app", application), ("externalId", sess_id),
    ]
    if direction == "outbound":
        extensions.append(("sourceTranslatedAddress", tenant()["egress_ip"]))
    if threat_name:
        extensions += [("cs2", threat_name), ("cs2Label", "ThreatName")]
    if suser:
        extensions.append(("suser", suser))

    raw_message = (
        f"CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|"
        f"{name}|{severity}|{' '.join(f'{k}={_cef_value(v)}' for k, v in extensions)}"
    )

    parsed_fields: Dict[str, Any] = {
        "log_type": log_type,
        "device_vendor": device_vendor,
        "device_product": device_product,
        "device_version": device_version,
        "device_id": fw,
        "device_name": fw,
        "signature_id": str(signature_id),
        "name": name,
        "severity": severity,
        "event_time": now_utc,
        "event_start_time": now_utc,
        "event_end_time": now_utc,
        "duration_seconds": 12,
        "source_ip": source_ip,
        "source_port": source_port,
        "source_nat_ip": tenant()["egress_ip"],
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "action": action,
        "rule_name": rule_name,
        "direction": direction,
        "session_id": sess_id,
        "source_zone": "trust" if direction == "outbound" else "untrust",
        "destination_zone": "untrust" if direction == "outbound" else ("dmz" if "DMZ" in rule_name else "trust"),
        "application": application,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "packets_out": packets_out,
        "packets_in": packets_in,
        "session_end_reason": "tcp-fin" if action == "allow" else "policy-deny"
    }
    if threat_name:
        parsed_fields["threat_name"] = threat_name
        parsed_fields["threat_category"] = threat_category or "command-and-control"
        parsed_fields["threat_id"] = str(signature_id)
    if suser:
        parsed_fields["user"] = suser

    return {"format": "CEF", "raw_message": raw_message, "parsed_fields": parsed_fields}

def generate_firewall_threat_event(
    source_ip: str,
    destination_ip: str,
    destination_port: int = 443,
    threat_name: str = "Suspicious TLS destination",
    action: str = "alert",
    user: Optional[str] = None,
    device_name: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a security threat match event (C2 beacon / malicious domain / exploit signature).
    """
    return generate_firewall_cef_event(
        device_name=device_name,
        signature_id="9052",
        name="Threat signature match",
        severity=8,
        source_ip=source_ip,
        source_port=random.randint(49152, 65535),
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol="TCP",
        action=action,
        rule_name="Outbound-Web",
        direction="outbound",
        log_type="threat",
        application="ssl",
        bytes_out=1420,
        bytes_in=5430,
        threat_name=threat_name,
        threat_category="command-and-control",
        user=user,
        event_time=event_time
    )

def generate_firewall_deny_event(
    device_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_port: int = 22,
    rule_name: str = "Default-Interzone-Deny",
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates an inbound blocked scanning or policy deny event.
    """
    return generate_firewall_cef_event(
        device_name=device_name,
        signature_id="3001",
        name="Traffic Dropped by Policy",
        severity=4,
        source_ip=source_ip or get_suspicious_ip(1)["ip"],
        source_port=random.randint(1024, 65535),
        destination_ip=destination_ip or random.choice(devices())["ip_address"],
        destination_port=destination_port,
        protocol="TCP",
        action="deny",
        rule_name=rule_name,
        direction="inbound",
        log_type="traffic",
        application="ssh",
        bytes_out=0,
        bytes_in=64,
        packets_out=0,
        packets_in=1,
        event_time=event_time
    )

def generate_firewall_baseline_event() -> Dict[str, Any]:
    """
    Generates realistic benign traffic flow through perimeter firewall (95% allowed outbound, 5% blocked scan).
    """
    if random.random() >= 0.95:
        return generate_firewall_deny_event()
    normal_rule = random.choice(COMMON_RULES[:2])
    host = random.choice(devices())
    return generate_firewall_cef_event(
        signature_id="8001",
        name="Outbound connection",
        severity=1,
        source_ip=host["ip_address"],
        source_port=random.randint(49152, 65535),
        destination_ip=get_random_normal_ip(),
        destination_port=normal_rule["port"],
        protocol=normal_rule["proto"],
        action="allow",
        rule_name=normal_rule["name"],
        direction="outbound",
        log_type="traffic",
        application=normal_rule["app"],
        bytes_out=random.randint(500, 15000),
        bytes_in=random.randint(1000, 50000),
        user=host["assigned_user"]
    )
