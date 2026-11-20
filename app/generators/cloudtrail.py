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
    scenario_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reusable function to generate an authentic AWS CloudTrail audit log event.
    """
    aws_info = get_primary_aws_account()
    event_time = datetime.datetime.utcnow().isoformat() + "Z"
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
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": aws_info["region"],
        "sourceIPAddress": source_ip,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AWSConsole/1.0",
        "requestParameters": request_parameters or {},
        "responseElements": response_elements or {"status": "Success"},
        "requestID": str(uuid.uuid4()),
        "eventID": event_id,
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": aws_info["account_id"],
        "simulation": True
    }

    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = f"Request denied due to {error_code}"
        event["responseElements"] = None

    if scenario_id:
        event["scenarioId"] = scenario_id

    return event

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
