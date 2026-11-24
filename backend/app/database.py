import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger("soc_database")
logging.basicConfig(level=logging.INFO)

engine = None
SessionLocal = None

def get_engine():
    global engine, SessionLocal
    if engine is not None:
        return engine
    
    # Try configured database (PostgreSQL by default)
    try:
        test_engine = create_engine(
            settings.DATABASE_URL,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 3} if "postgresql" in settings.DATABASE_URL else {}
        )
        # Test connection
        with test_engine.connect() as conn:
            logger.info("Successfully connected to PostgreSQL database.")
        engine = test_engine
    except Exception as e:
        logger.warning(
            f"Could not connect to configured DATABASE_URL ({settings.DATABASE_URL}). Error: {e}. "
            f"Falling back to local SQLite engine ({settings.SQLITE_FALLBACK_URL}) for seamless local execution."
        )
        engine = create_engine(
            settings.SQLITE_FALLBACK_URL,
            connect_args={"check_same_thread": False}
        )
        
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine

get_engine()
Base = declarative_base()

def get_db():
    if SessionLocal is None:
        get_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
