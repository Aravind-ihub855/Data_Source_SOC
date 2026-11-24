import uuid
import datetime
import random
from typing import Dict, Any, Optional
from app.registry.entities import get_random_user, get_primary_aws_account, get_random_normal_ip

BENIGN_ACTIONS = [
    {
        "source": "s3.amazonaws.com",
        "name": "GetObject",
        "read_only": True,
        "params": {"bucketName": "acme-financial-exports-prod", "key": "reports/daily_summary.csv"}
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
        "params": {"loginType": "PasswordWithMFA", "consoleState": "Success"}
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
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic AWS CloudTrail audit log event.
    """
    aws_info = get_primary_aws_account()
    now_utc = event_time or datetime.datetime.utcnow().isoformat() + "Z"
    event_id = str(uuid.uuid4())

    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDA{uuid.uuid4().hex[:16].upper()}",
            "arn": f"arn:aws:iam::{aws_info['account_id']}:user/{user_name}",
            "accountId": aws_info["account_id"],
            "userName": user_name
        },
        "eventTime": now_utc,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": aws_info["region"],
        "sourceIPAddress": source_ip,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AWSConsole/1.0",
        "requestParameters": request_parameters or {},
        "responseElements": response_elements if error_code is None else None,
        "requestID": str(uuid.uuid4()),
        "eventID": event_id,
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "eventCategory": "Management",
        "managementEvent": True,
        "recipientAccountId": aws_info["account_id"]
    }

    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = f"Request denied due to {error_code}"

    if scenario_id:
        event["scenarioId"] = scenario_id

    return event

def generate_cloudtrail_stop_logging_event(
    user_name: str,
    source_ip: str,
    trail_name: str = "arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-security-audit",
    scenario_id: Optional[str] = None,
    event_time: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a high-severity StopLogging evasion event in CloudTrail.
    """
    return generate_cloudtrail_event(
        event_name="StopLogging",
        event_source="cloudtrail.amazonaws.com",
        user_name=user_name,
        source_ip=source_ip,
        request_parameters={"name": trail_name},
        response_elements=None,
        error_code=None,
        read_only=False,
        scenario_id=scenario_id,
        event_time=event_time
    )

def generate_cloudtrail_policy_event(
    user_name: str,
    source_ip: str,
    policy_arn: str = "arn:aws:iam::aws:policy/AdministratorAccess",
    scenario_id: Optional[str] = None,
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
        scenario_id=scenario_id,
        event_time=event_time
    )

def generate_cloudtrail_baseline_event() -> Dict[str, Any]:
    """
    Generates a normal, non-malicious background AWS CloudTrail event.
    """
    user = get_random_user()
    action = random.choice(BENIGN_ACTIONS)
    source_ip = get_random_normal_ip()

    return generate_cloudtrail_event(
        event_name=action["name"],
        event_source=action["source"],
        user_name=user["username"],
        source_ip=source_ip,
        request_parameters=action.get("params"),
        read_only=action.get("read_only", True)
    )
