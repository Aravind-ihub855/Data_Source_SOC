import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class AppSettings(BaseSettings):
    APP_NAME: str = "Aetheris Synthetic Security Data Generator"
    APP_VERSION: str = "2.1.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8002"))
    RELOAD: bool = False  # uvicorn auto-reload: development only

    # Event generation rates for the 5 sources (events per minute at peak working hours)
    DEFENDER_RATE_PER_MIN: int = int(os.getenv("DEFENDER_RATE_PER_MIN", "30"))
    ENTRA_RATE_PER_MIN: int = int(os.getenv("ENTRA_RATE_PER_MIN", "20"))
    CLOUDTRAIL_RATE_PER_MIN: int = int(os.getenv("CLOUDTRAIL_RATE_PER_MIN", "10"))
    WINDOWS_RATE_PER_MIN: int = int(os.getenv("WINDOWS_RATE_PER_MIN", "20"))
    FIREWALL_RATE_PER_MIN: int = int(os.getenv("FIREWALL_RATE_PER_MIN", "15"))

    # Legacy alias
    @property
    def POWERSHELL_RATE_PER_MIN(self) -> int:
        return self.WINDOWS_RATE_PER_MIN

    STREAM_AUTO_START: bool = os.getenv("STREAM_AUTO_START", "true").lower() in ("true", "1", "yes")
    BUFFER_MAX_SIZE: int = int(os.getenv("BUFFER_MAX_SIZE", "2000"))
    SCENARIO_PACER_ENABLED: bool = os.getenv("SCENARIO_PACER_ENABLED", "true").lower() in ("true", "1", "yes")
    SCENARIO_INTERVAL_MIN: float = float(os.getenv("SCENARIO_INTERVAL_MIN", "4.0"))

    # Tenants that baseline traffic and the scenario pacer spread across (first = default for triggers)
    TENANTS: str = "tnt-acme,tnt-globex"
    # Seeds every random choice and id; a backfill with the same seed is byte-for-byte repeatable
    SEED: int = 20261124
    # Working-hours traffic curve in the business's local time (Acme is in New York, UTC-5)
    DIURNAL_CURVE: bool = True
    BUSINESS_UTC_OFFSET_HOURS: float = -5.0

    # Data-quality faults injected into delivery (fractions of all events), recorded in ground truth
    FAULT_DUPLICATE_RATE: float = 0.015
    FAULT_LATE_RATE: float = 0.02
    FAULT_TRUNCATED_RATE: float = 0.003
    FAULT_SCHEMA_DRIFT_RATE: float = 0.001

    # Labels and undeliverable batches (never sent to Splunk)
    GROUND_TRUTH_PATH: str = "out/ground_truth.jsonl"
    DEAD_LETTER_PATH: str = "out/dead_letter.jsonl"
    # Optional copy of every delivered HEC batch, e.g. http://localhost:8000/api/pipeline/ingest-splunk
    MIRROR_URL: str = ""
    # Browser origins allowed to call this API (comma separated)
    CORS_ORIGINS: str = "http://localhost:3000"

    @property
    def tenant_list(self) -> List[str]:
        return [t.strip() for t in self.TENANTS.split(",") if t.strip()]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = AppSettings()
