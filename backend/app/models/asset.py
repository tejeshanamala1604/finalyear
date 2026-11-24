from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from app.database import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), unique=True, index=True, nullable=False)
    ip_address = Column(String(50), index=True, nullable=False)
    mac_address = Column(String(50), nullable=True)
    os = Column(String(100), nullable=False)
    department = Column(String(100), nullable=False)
    owner = Column(String(100), nullable=False)
    criticality_tier = Column(String(50), nullable=False, default="Tier 2 - Standard") 
    # e.g., "Tier 0 - Crown Jewel (DC/Core DB)", "Tier 1 - Mission Critical", "Tier 2 - Standard"
    environment = Column(String(50), nullable=False, default="Production")
    network_zone = Column(String(50), nullable=False, default="Corporate LAN")
    is_isolated = Column(Boolean, default=False)
    isolation_timestamp = Column(DateTime, nullable=True)
    last_patched = Column(DateTime, default=datetime.utcnow)
