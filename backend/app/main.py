import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import get_engine, SessionLocal, Base
from app.models import Alert, Asset, User
from app.seed_data import seed_database
from app.routers import alerts_router, metrics_router
from app.services.websocket_manager import ws_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("soc_main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure database tables are created & pre-seeded
    logger.info("Initializing AegisSOC database schema...")
    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    # Ensure newly added columns exist in existing deployments
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            if "postgresql" in settings.DATABASE_URL:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(50);"))
                conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(100);"))
                conn.commit()
    except Exception as e:
        logger.info(f"Schema column check: {e}")
    
    # Pre-populate seed data if tables are empty
    db = SessionLocal()
    try:
        await seed_database(db)
    finally:
        db.close()
    
    logger.info("AegisSOC Alert Enrichment System online & ready.")
    yield
    logger.info("Shutting down AegisSOC services...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-grade Alert Enrichment & First Response SOC Orchestration Platform",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket Endpoint for Live Incident Stream
@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for ping or analyst heartbeat
            data = await websocket.receive_text()
            # Echo or process if needed
            if data == "ping":
                await websocket.send_text('{"event": "pong"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket session error: {e}")
        ws_manager.disconnect(websocket)

# Routers
app.include_router(alerts_router, prefix=settings.API_V1_PREFIX)
app.include_router(metrics_router, prefix=settings.API_V1_PREFIX)

@app.get("/")
def root():
    return {
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "docs_url": "/docs",
        "endpoints": {
            "alerts": f"{settings.API_V1_PREFIX}/alerts",
            "metrics": f"{settings.API_V1_PREFIX}/metrics",
            "websocket": "/ws/alerts"
        }
    }

@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy", "timestamp": str(logging.Formatter().formatTime(logging.LogRecord('', 0, '', 0, '', (), None)))}
