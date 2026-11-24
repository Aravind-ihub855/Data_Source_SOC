import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_random_normal_ip, get_device_for_user, identity, resolve_identity
from app.util import iso_now, new_uuid, stable_uuid

ENTERPRISE_APPS = [
    "Microsoft 365 Exchange Online",
    "SharePoint Online",
    "AWS IAM Identity Center",
    "Slack Enterprise Grid",
    "Salesforce CRM",
    "Workday HCM",
    "GitHub Enterprise Cloud"
]


def _display_name(upn: str) -> str:
    u = resolve_identity(upn)
    return f"{u['first_name']} {u['last_name']}" if u else upn.split("@")[0].replace(".", " ").title()


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
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates Microsoft Entra ID Sign-In record conforming to 02_microsoft_entra_id.schema.json
    """
    now_utc = event_time or iso_now()
    who = identity(user_principal_name)
    # The user's own managed device, unless the sign-in comes from outside (attacker / travel).
    dev = get_device_for_user(user_principal_name) if is_success and risk_level in ("none", "low") else None

    return {
        "id": new_uuid(),
        "createdDateTime": now_utc,
        "userId": who["object_id"],
        "userDisplayName": _display_name(user_principal_name),
        "userPrincipalName": user_principal_name,
        "userType": "member",
        "appId": stable_uuid(f"app:{app_display_name}"),
        "appDisplayName": app_display_name,
        "resourceId": "resource-01",
        "resourceDisplayName": "Corporate Gateway",
        "ipAddress": ip_address,
        "autonomousSystemNumber": 15169,
        "clientAppUsed": "Browser",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "isInteractive": True,
        "correlationId": new_uuid(),
        "uniqueTokenIdentifier": new_uuid(),
        "status": {
            "errorCode": error_code if not is_success else 0,
            "failureReason": failure_reason if not is_success else None,
            "additionalDetails": "Authentication requirement satisfied" if is_success else "Invalid password or token"
        },
        "deviceDetail": {
            "deviceId": dev["entra_device_id"] if dev else "",
            "displayName": dev["device_name"] if dev else "",
            "operatingSystem": "Windows 11" if dev else "Windows 10",
            "browser": "Edge",
            "isCompliant": dev is not None,
            "isManaged": dev is not None
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

def generate_entra_directory_audit_event(
    user_principal_name: str,
    ip_address: str,
    activity_name: str = "Add member to role",
    role_name: str = "Privileged Role Administrator",
    category: str = "RoleManagement",
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a Microsoft Entra ID DirectoryAudit event conforming to 02_microsoft_entra_id.schema.json
    """
    now_utc = event_time or iso_now()
    return {
        "id": f"Directory_{new_uuid()}",
        "category": category,
        "correlationId": new_uuid(),
        "result": "success",
        "resultReason": "",
        "activityDisplayName": activity_name,
        "activityDateTime": now_utc,
        "loggedByService": "Core Directory",
        "operationType": "Add",
        "initiatedBy": {
            "user": {
                "id": identity(user_principal_name)["object_id"],
                "displayName": _display_name(user_principal_name),
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
