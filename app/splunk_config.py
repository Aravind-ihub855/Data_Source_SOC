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
    
    # Target Indexes
    INDEX_ENDPOINT: str = os.getenv("SPLUNK_INDEX_ENDPOINT", "endpoint")
    INDEX_CLOUD: str = os.getenv("SPLUNK_INDEX_CLOUD", "cloud")
    INDEX_AUTH: str = os.getenv("SPLUNK_INDEX_AUTH", "authentication")
    
    # Sourcetypes
    SOURCETYPE_DEFENDER: str = "aetheris:defender"
    SOURCETYPE_POWERSHELL: str = "aetheris:powershell"
    SOURCETYPE_CLOUDTRAIL: str = "aetheris:cloudtrail"
    SOURCETYPE_ENTRA: str = "aetheris:entra"
    
    # Delivery Engine settings
    BATCH_SIZE: int = int(os.getenv("SPLUNK_BATCH_SIZE", "10"))
    FLUSH_INTERVAL_SEC: float = float(os.getenv("SPLUNK_FLUSH_INTERVAL_SEC", "2.0"))
    TIMEOUT_SEC: float = float(os.getenv("SPLUNK_TIMEOUT_SEC", "5.0"))
    MAX_RETRIES: int = int(os.getenv("SPLUNK_MAX_RETRIES", "3"))

    class Config:
        env_file = ".env"
        extra = "ignore"

splunk_config = SplunkConfig()

# Reusable Splunk helper functions
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
    # All Windows / Endpoint / Defender / PowerShell / Security-Auditing goes to endpoint index
    return splunk_config.INDEX_ENDPOINT

def get_sourcetype_for_source(source: str) -> str:
    """Returns official Splunk sourcetype for the telemetry source."""
    src = source.lower()
    if "defender" in src:
        return splunk_config.SOURCETYPE_DEFENDER
    elif "powershell" in src:
        return splunk_config.SOURCETYPE_POWERSHELL
    elif "cloudtrail" in src:
        return splunk_config.SOURCETYPE_CLOUDTRAIL
    elif "entra" in src:
        return splunk_config.SOURCETYPE_ENTRA
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
