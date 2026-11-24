import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.coordination.scheduler import start_stream, stop_stream
from app.api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("synthetic_generator")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"✨ Starting {settings.APP_NAME} v{settings.APP_VERSION} on port {settings.PORT}...")
    if settings.STREAM_AUTO_START:
        await start_stream()
    yield
    logger.info("🛑 Shutting down 5-Source Synthetic Security Data Generator...")
    await stop_stream()

app = FastAPI(
    title=settings.APP_NAME,
    description="Autonomous 5-Source Synthetic Telemetry Generator simulating Microsoft Defender, Microsoft Entra ID, AWS CloudTrail, Windows Event Logs (OS, PowerShell, Sysmon), and Network Firewall logs with Splunk HEC delivery.",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# CORS Middleware (allows local testing and frontend inspection)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(router)
