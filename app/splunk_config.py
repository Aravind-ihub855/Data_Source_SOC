import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class SplunkConfig(BaseSettings):
    """
    Separate Splunk Connection Configuration.
    Can be configured via environment variables or loaded from .env.
    Sourcetypes and wire formats per source live in app/sources.py.
    """
    HEC_URL: str = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
    HEC_TOKEN: str = os.getenv("SPLUNK_HEC_TOKEN", "")
    VERIFY_SSL: bool = os.getenv("SPLUNK_HEC_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    # Target Indexes for the 5 Sources
    INDEX_ENDPOINT: str = os.getenv("SPLUNK_INDEX_ENDPOINT", "security_endpoint")
    INDEX_CLOUD: str = os.getenv("SPLUNK_INDEX_CLOUD", "security_cloud")
    INDEX_AUTH: str = os.getenv("SPLUNK_INDEX_AUTH", "security_identity")
    INDEX_NETWORK: str = os.getenv("SPLUNK_INDEX_NETWORK", "security_network")

    # Delivery Engine settings
    BATCH_SIZE: int = int(os.getenv("SPLUNK_BATCH_SIZE", "50"))
    FLUSH_INTERVAL_SEC: float = float(os.getenv("SPLUNK_FLUSH_INTERVAL_SEC", "2.0"))
    TIMEOUT_SEC: float = float(os.getenv("SPLUNK_TIMEOUT_SEC", "5.0"))
    MAX_RETRIES: int = int(os.getenv("SPLUNK_MAX_RETRIES", "5"))
    # Indexer acknowledgement: used automatically when the token has it enabled (HEC returns an ackId).
    ACK_TIMEOUT_SEC: float = float(os.getenv("SPLUNK_ACK_TIMEOUT_SEC", "30"))

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

splunk_config = SplunkConfig()

def get_splunk_config() -> SplunkConfig:
    """Returns current Splunk configuration instance."""
    return splunk_config

def is_splunk_enabled() -> bool:
    """Checks whether a valid Splunk HEC Token and URL are set."""
    return bool(splunk_config.HEC_TOKEN and splunk_config.HEC_URL)
