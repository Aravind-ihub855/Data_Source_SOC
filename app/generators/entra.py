import uuid
import datetime
import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_random_normal_ip

ENTERPRISE_APPS = [
    "Microsoft 365 Exchange Online",
    "SharePoint Online",
    "AWS IAM Identity Center",
    "Slack Enterprise Grid",
    "Salesforce CRM",
    "Workday HCM",
    "GitHub Enterprise Cloud"
]

def generate_entra_signin_event(
    user_principal_name: str,
    ip_address: str,
    app_display_name: str = "Microsoft 365 Exchange Online",
    is_success: bool = True,
    error_code: int = 0,
    failure_reason: str = "None",
    risk_level: str = "none",
    city: str = "New York",
    country: str = "US",
    mfa_required: bool = True,
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic Microsoft Entra ID Sign-In record.
    """
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
    record_id = str(uuid.uuid4())

    event = {
        "Source": "Microsoft Entra ID",
        "Category": "SignInLogs",
        "id": record_id,
        "createdDateTime": event_time,
        "userDisplayName": user_principal_name.split("@")[0].replace(".", " ").title(),
        "userPrincipalName": user_principal_name,
        "userId": f"entra-usr-{uuid.uuid4().hex[:8]}",
        "appId": f"app-{uuid.uuid4().hex[:8]}",
        "appDisplayName": app_display_name,
        "ipAddress": ip_address,
        "clientAppUsed": "Browser",
        "location": {
            "city": city,
            "state": "NY" if country == "US" else "",
            "countryOrRegion": country,
            "geoCoordinates": {"latitude": 40.7128, "longitude": -74.0060} if country == "US" else {"latitude": 50.4501, "longitude": 30.5234}
        },
        "status": {
            "errorCode": error_code if not is_success else 0,
            "failureReason": failure_reason if not is_success else "None",
            "additionalDetails": "Authentication requirement satisfied" if is_success else "Invalid password or token"
        },
        "riskLevelAggregated": risk_level,
        "riskState": "atRisk" if risk_level in ("medium", "high") else "none",
        "mfaDetail": {
            "authMethod": "Microsoft Authenticator App" if is_success and mfa_required else None,
            "authDetail": "Number match confirmed" if is_success and mfa_required else "MFA challenge not completed"
        },
        "isInteractive": True,
        "simulation": True
    }

    if scenario_id:
        event["scenarioId"] = scenario_id

    return event

def generate_entra_baseline_event() -> Dict[str, Any]:
    """
    Generates a normal, non-malicious background Entra ID sign-in event.
    """
    user = get_random_user()
    app = random.choice(ENTERPRISE_APPS)
    ip = get_random_normal_ip()

    # 96% success rate in normal enterprise environment
    if random.random() < 0.96:
        return generate_entra_signin_event(
            user_principal_name=user["email"],
            ip_address=ip,
            app_display_name=app,
            is_success=True,
            risk_level="none",
            city="New York",
            country="US"
        )
    else:
        # Occasional benign password typo
        return generate_entra_signin_event(
            user_principal_name=user["email"],
            ip_address=ip,
            app_display_name=app,
            is_success=False,
            error_code=50126,
            failure_reason="Invalid username or password or Invalid on-premise username or password.",
            risk_level="low",
            city="New York",
            country="US"
        )
