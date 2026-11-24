import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class AppSettings(BaseSettings):
    APP_NAME: str = "Aetheris Synthetic Security Data Generator"
    APP_VERSION: str = "2.0.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8002"))
    
    # Event generation rates for the 5 sources (events per 1-minute window)
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
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = AppSettings()
