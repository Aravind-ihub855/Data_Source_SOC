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
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft Entra ID Sign-In record conforming to 02_microsoft_entra_id.schema.json
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    record_id = str(uuid.uuid4())
    user_id = f"entra-usr-{uuid.uuid4().hex[:8]}"

    event = {
        "id": record_id,
        "createdDateTime": now_utc,
        "userId": user_id,
        "userDisplayName": user_principal_name.split("@")[0].replace(".", " ").title(),
        "userPrincipalName": user_principal_name,
        "userType": "member",
        "appId": str(uuid.uuid4()),
        "appDisplayName": app_display_name,
        "resourceId": "resource-01",
        "resourceDisplayName": "Corporate Gateway",
        "ipAddress": ip_address,
        "autonomousSystemNumber": 15169,
        "clientAppUsed": "Browser",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "isInteractive": True,
        "correlationId": str(uuid.uuid4()),
        "uniqueTokenIdentifier": str(uuid.uuid4()),
        "status": {
            "errorCode": error_code if not is_success else 0,
            "failureReason": failure_reason if not is_success else None,
            "additionalDetails": "Authentication requirement satisfied" if is_success else "Invalid password or token"
        },
        "deviceDetail": {
            "deviceId": str(uuid.uuid4()),
            "displayName": "CORP-WORKSTATION",
            "operatingSystem": "Windows 11",
            "browser": "Edge",
            "isCompliant": is_success,
            "isManaged": True
        },
        "location": {
            "city": city,
            "state": "NY" if country == "US" else "",
            "countryOrRegion": country
        },
        "conditionalAccessStatus": "success" if is_success else "failure",
        "appliedConditionalAccessPolicies": [
            {
                "id": "ca-policy-01",
                "displayName": "Require MFA for Cloud Management",
                "result": "success" if is_success else "failure"
            }
        ],
        "authenticationRequirement": "multiFactorAuthentication" if mfa_required else "singleFactorAuthentication",
        "authenticationDetails": [
            {
                "authenticationMethod": "Password",
                "succeeded": is_success
            }
        ],
        "authenticationMethodsUsed": ["Password"],
        "riskDetail": "none",
        "riskLevelDuringSignIn": risk_level,
        "riskLevelAggregated": risk_level,
        "riskState": "atRisk" if risk_level in ("medium", "high") else "none",
        "riskEventTypes_v2": ["unfamiliarFeatures"] if risk_level in ("medium", "high") else [],
        "signInEventTypes": ["interactiveUser"]
    }

    if scenario_id:
        event["scenarioId"] = scenario_id

    return event

def generate_entra_directory_audit_event(
    user_principal_name: str,
    ip_address: str,
    activity_name: str = "Add member to role",
    role_name: str = "Privileged Role Administrator",
    category: str = "RoleManagement",
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a Microsoft Entra ID DirectoryAudit event conforming to 02_microsoft_entra_id.schema.json
    """
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    user_id = f"entra-usr-{uuid.uuid4().hex[:8]}"

    event = {
        "id": f"Directory_{uuid.uuid4()}",
        "category": category,
        "correlationId": str(uuid.uuid4()),
        "result": "success",
        "resultReason": "",
        "activityDisplayName": activity_name,
        "activityDateTime": now_utc,
        "loggedByService": "Core Directory",
        "operationType": "Add",
        "initiatedBy": {
            "user": {
                "id": user_id,
                "displayName": user_principal_name.split("@")[0].replace(".", " ").title(),
                "userPrincipalName": user_principal_name,
                "ipAddress": ip_address
            }
        },
        "targetResources": [
            {
                "id": f"role-{role_name.lower().replace(' ', '-')}",
                "displayName": role_name,
                "type": "Role",
                "modifiedProperties": [
                    {
                        "displayName": "Role.DisplayName",
                        "oldValue": None,
                        "newValue": f'"{role_name}"'
                    }
                ]
            }
        ],
        "additionalDetails": []
    }

    if scenario_id:
        event["scenarioId"] = scenario_id

    return event

def generate_entra_baseline_event() -> Dict[str, Any]:
    user = get_random_user()
    app = random.choice(ENTERPRISE_APPS)
    ip = get_random_normal_ip()

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
        return generate_entra_signin_event(
            user_principal_name=user["email"],
            ip_address=ip,
            app_display_name=app,
            is_success=False,
            error_code=50126,
            failure_reason="Invalid username or password",
            risk_level="low",
            city="New York",
            country="US"
        )
