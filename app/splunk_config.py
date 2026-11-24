import os
import time
from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class SplunkConfig(BaseSettings):
    """
    Separate Splunk Connection Configuration.
    Can be configured via environment variables or loaded from .env.
    """
    HEC_URL: str = os.getenv("SPLUNK_HEC_URL", "http://localhost:8088/services/collector/event")
    HEC_TOKEN: str = os.getenv("SPLUNK_HEC_TOKEN", "")
    VERIFY_SSL: bool = os.getenv("SPLUNK_HEC_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
    
    # Target Indexes for the 5 Sources
    INDEX_ENDPOINT: str = os.getenv("SPLUNK_INDEX_ENDPOINT", "endpoint")
    INDEX_CLOUD: str = os.getenv("SPLUNK_INDEX_CLOUD", "cloud")
    INDEX_AUTH: str = os.getenv("SPLUNK_INDEX_AUTH", "authentication")
    INDEX_NETWORK: str = os.getenv("SPLUNK_INDEX_NETWORK", "network")
    
    # Sourcetypes for the 5 Sources
    SOURCETYPE_DEFENDER: str = "aetheris:defender"
    SOURCETYPE_ENTRA: str = "aetheris:entra"
    SOURCETYPE_CLOUDTRAIL: str = "aetheris:cloudtrail"
    SOURCETYPE_WINDOWS: str = "aetheris:windows"
    SOURCETYPE_FIREWALL: str = "aetheris:firewall"
    SOURCETYPE_POWERSHELL: str = "aetheris:windows" # legacy compatibility
    
    # Delivery Engine settings
    BATCH_SIZE: int = int(os.getenv("SPLUNK_BATCH_SIZE", "10"))
    FLUSH_INTERVAL_SEC: float = float(os.getenv("SPLUNK_FLUSH_INTERVAL_SEC", "2.0"))
    TIMEOUT_SEC: float = float(os.getenv("SPLUNK_TIMEOUT_SEC", "5.0"))
    MAX_RETRIES: int = int(os.getenv("SPLUNK_MAX_RETRIES", "3"))

    class Config:
        env_file = ".env"
        extra = "ignore"

splunk_config = SplunkConfig()

def get_splunk_config() -> SplunkConfig:
    """Returns current Splunk configuration instance."""
    return splunk_config

def is_splunk_enabled() -> bool:
    """Checks whether a valid Splunk HEC Token and URL are set."""
    return bool(splunk_config.HEC_TOKEN and splunk_config.HEC_URL)

def get_index_for_source(source: str) -> str:
    """Returns target Splunk index according to telemetry source."""
    src = source.lower()
    if "cloudtrail" in src or "aws" in src:
        return splunk_config.INDEX_CLOUD
    elif "entra" in src or "identity" in src or "auth" in src:
        return splunk_config.INDEX_AUTH
    elif "firewall" in src or "network" in src or "palo" in src or "fortinet" in src:
        return splunk_config.INDEX_NETWORK
    # All Windows / Endpoint / Defender / PowerShell / Security-Auditing goes to endpoint index
    return splunk_config.INDEX_ENDPOINT

def get_sourcetype_for_source(source: str) -> str:
    """Returns official Splunk sourcetype for the telemetry source."""
    src = source.lower()
    if "defender" in src:
        return splunk_config.SOURCETYPE_DEFENDER
    elif "entra" in src:
        return splunk_config.SOURCETYPE_ENTRA
    elif "cloudtrail" in src or "aws" in src:
        return splunk_config.SOURCETYPE_CLOUDTRAIL
    elif "firewall" in src:
        return splunk_config.SOURCETYPE_FIREWALL
    elif "windows" in src or "powershell" in src or "sysmon" in src or "security" in src:
        return splunk_config.SOURCETYPE_WINDOWS
    return f"aetheris:{src}"

def format_hec_envelope(
    event: Dict[str, Any],
    source: str,
    host: Optional[str] = None,
    index: Optional[str] = None,
    sourcetype: Optional[str] = None,
    timestamp: Optional[float] = None
) -> Dict[str, Any]:
    """
    Reusable function to package any raw security event into the standard Splunk HEC envelope.
    """
    event_time = timestamp or time.time()
    target_index = index or get_index_for_source(source)
    target_sourcetype = sourcetype or get_sourcetype_for_source(source)
    target_host = host or event.get("device_name") or event.get("DeviceName") or event.get("host") or "acme-corp"

    return {
        "time": round(event_time, 3),
        "host": target_host,
        "source": source,
        "sourcetype": target_sourcetype,
        "index": target_index,
        "event": event
    }
