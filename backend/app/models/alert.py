from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from datetime import datetime
from app.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), index=True, nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String(100), nullable=False, default="EDR Agent") # CrowdStrike, Suricata, GuardDuty, Wazuh, etc.
    raw_severity = Column(String(50), nullable=False, default="Medium") # Critical, High, Medium, Low
    current_severity = Column(String(50), nullable=False, default="Medium")
    status = Column(String(50), nullable=False, default="New") # New, Triaged, In Progress, Mitigated, Dismissed
    
    # Target Indicators (IOCs)
    src_ip = Column(String(50), nullable=True, index=True)
    dest_ip = Column(String(50), nullable=True, index=True)
    dest_port = Column(Integer, nullable=True)
    file_hash = Column(String(128), nullable=True, index=True)
    domain = Column(String(255), nullable=True, index=True)
    
    # MITRE ATT&CK Framework Mapping
    mitre_technique_id = Column(String(50), nullable=True, index=True) # e.g. T1059.001, T1003.001
    mitre_tactic = Column(String(100), nullable=True, index=True) # e.g. Execution, Credential Access
    
    # Internal Entities
    affected_user = Column(String(100), nullable=True, index=True)
    affected_host = Column(String(100), nullable=True, index=True)
    
    # Enrichment & Scoring
    dynamic_risk_score = Column(Integer, default=0) # 0 - 100
    enrichment_data = Column(JSON, nullable=True) # Full enrichment payload (internal context + threat intel)
    playbook_actions = Column(JSON, nullable=True) # Recommended mitigation playbooks
    audit_log = Column(JSON, default=list) # [{timestamp, analyst, action, note}]
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
