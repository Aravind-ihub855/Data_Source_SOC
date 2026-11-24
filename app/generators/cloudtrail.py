import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_primary_aws_account, get_random_normal_ip, identity
from app.util import iso_now, new_uuid

BENIGN_ACTIONS = [
    {
        "source": "s3.amazonaws.com",
        "name": "GetObject",
        "read_only": True,
        "params": {"bucketName": "{bucket}", "key": "reports/daily_summary.csv"}
    },
    {
        "source": "ec2.amazonaws.com",
        "name": "DescribeInstances",
        "read_only": True,
        "params": {"filter": [{"name": "instance-state-name", "values": ["running"]}]}
    },
    {
        "source": "monitoring.amazonaws.com",
        "name": "GetMetricData",
        "read_only": True,
        "params": {"metricDataQueries": [{"id": "m1", "metricStat": {"metric": {"namespace": "AWS/EC2", "metricName": "CPUUtilization"}}}]}
    },
    {
        "source": "sts.amazonaws.com",
        "name": "GetCallerIdentity",
        "read_only": True,
        "params": {}
    },
    {
        "source": "signin.amazonaws.com",
        "name": "ConsoleLogin",
        "read_only": False,
        "params": None
    }
]

def generate_cloudtrail_event(
    event_name: str,
    event_source: str,
    user_name: str,
    source_ip: str,
    request_parameters: Optional[Dict[str, Any]] = None,
    response_elements: Optional[Dict[str, Any]] = None,
    error_code: Optional[str] = None,
    read_only: bool = False,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic AWS CloudTrail audit log event.
    """
    aws_info = get_primary_aws_account()
    console_login = event_name == "ConsoleLogin"
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": identity(user_name)["aws_principal_id"],
            "arn": f"arn:aws:iam::{aws_info['account_id']}:user/{user_name}",
            "accountId": aws_info["account_id"],
            "userName": user_name
        },
        "eventTime": event_time or iso_now(),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": aws_info["region"],
        "sourceIPAddress": source_ip,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AWSConsole/1.0",
        "requestParameters": None if console_login else (request_parameters or {}),
        "responseElements": ({"ConsoleLogin": "Failure" if error_code else "Success"} if console_login
                             else (response_elements if error_code is None else None)),
        "requestID": new_uuid(),
        "eventID": new_uuid(),
        "readOnly": read_only,
        "eventType": "AwsConsoleSignIn" if console_login else "AwsApiCall",
        "eventCategory": "Management",
        "managementEvent": True,
        "recipientAccountId": aws_info["account_id"]
    }
    if console_login:
        event["additionalEventData"] = {
            "LoginTo": f"https://console.aws.amazon.com/console/home?region={aws_info['region']}",
            "MobileVersion": "No",
            "MFAUsed": "Yes"
        }
    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = f"Request denied due to {error_code}"
    return event

def generate_cloudtrail_stop_logging_event(
    user_name: str,
    source_ip: str,
    trail_name: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a high-severity StopLogging evasion event in CloudTrail.
    """
    aws_info = get_primary_aws_account()
    return generate_cloudtrail_event(
        event_name="StopLogging",
        event_source="cloudtrail.amazonaws.com",
        user_name=user_name,
        source_ip=source_ip,
        request_parameters={"name": trail_name or
                            f"arn:aws:cloudtrail:{aws_info['region']}:{aws_info['account_id']}:trail/corp-security-audit"},
        read_only=False,
        event_time=event_time
    )

def generate_cloudtrail_policy_event(
    user_name: str,
    source_ip: str,
    policy_arn: str = "arn:aws:iam::aws:policy/AdministratorAccess",
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates an AttachUserPolicy event in CloudTrail.
    """
    return generate_cloudtrail_event(
        event_name="AttachUserPolicy",
        event_source="iam.amazonaws.com",
        user_name=user_name,
        source_ip=source_ip,
        request_parameters={
            "userName": user_name,
            "policyArn": policy_arn
        },
        read_only=False,
        event_time=event_time
    )

def generate_cloudtrail_baseline_event() -> Dict[str, Any]:
    """
    Generates a normal, non-malicious background AWS CloudTrail event.
    """
    user = get_random_user()
    action = random.choice(BENIGN_ACTIONS)
    params = action["params"]
    if params and params.get("bucketName") == "{bucket}":
        params = dict(params, bucketName=get_primary_aws_account()["s3_buckets"][0]["name"])
    return generate_cloudtrail_event(
        event_name=action["name"],
        event_source=action["source"],
        user_name=user["username"],
        source_ip=get_random_normal_ip(),
        request_parameters=params,
        read_only=action["read_only"]
    )
