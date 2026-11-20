import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class AppSettings(BaseSettings):
    APP_NAME: str = "Aetheris Synthetic Security Data Generator"
    APP_VERSION: str = "1.0.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8002"))
    
    # Event generation rates (events per 1-minute window)
    DEFENDER_RATE_PER_MIN: int = int(os.getenv("DEFENDER_RATE_PER_MIN", "30"))
    ENTRA_RATE_PER_MIN: int = int(os.getenv("ENTRA_RATE_PER_MIN", "20"))
    CLOUDTRAIL_RATE_PER_MIN: int = int(os.getenv("CLOUDTRAIL_RATE_PER_MIN", "10"))
    POWERSHELL_RATE_PER_MIN: int = int(os.getenv("POWERSHELL_RATE_PER_MIN", "15"))
    
    STREAM_AUTO_START: bool = os.getenv("STREAM_AUTO_START", "true").lower() in ("true", "1", "yes")
    BUFFER_MAX_SIZE: int = int(os.getenv("BUFFER_MAX_SIZE", "2000"))
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = AppSettings()
