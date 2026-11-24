from sqlalchemy import Column, Integer, String, Boolean
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    full_name = Column(String(150), nullable=False)
    department = Column(String(100), nullable=False)
    role = Column(String(100), nullable=False)
    privilege_level = Column(String(50), nullable=False, default="Standard User")
    # e.g., "Domain Admin", "Enterprise Admin", "DevOps Admin", "Finance Privileged", "Standard User"
    mfa_enabled = Column(Boolean, default=True)
    account_status = Column(String(50), default="Active") # "Active", "Suspended", "Credentials_Revoked"
    last_login_ip = Column(String(50), nullable=True)
