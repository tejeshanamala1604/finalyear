from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class AlertCreate(BaseModel):
    title: str = Field(..., example="Suspicious PowerShell C2 Beaconing Detected")
    description: str = Field(..., example="Process powershell.exe initiated encrypted outbound connection to untrusted foreign IP.")
    source: str = Field(default="CrowdStrike Falcon", example="CrowdStrike Falcon")
    raw_severity: str = Field(default="High", example="High") # Critical, High, Medium, Low
    src_ip: Optional[str] = Field(None, example="192.168.10.45")
    dest_ip: Optional[str] = Field(None, example="185.220.101.5")
    dest_port: Optional[int] = Field(None, example=443)
    file_hash: Optional[str] = Field(None, example="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    domain: Optional[str] = Field(None, example="c2-evil-update.com")
    mitre_technique_id: Optional[str] = Field(None, example="T1059.001")
    mitre_tactic: Optional[str] = Field(None, example="Execution")
    affected_user: Optional[str] = Field(None, example="j.smith")
    affected_host: Optional[str] = Field(None, example="WKST-FIN-04")

class AlertActionRequest(BaseModel):
    action: str = Field(..., example="Isolate Host") # Isolate Host, Block IP, Reset Credentials, Acknowledge, Dismiss
    analyst: str = Field(default="SOC Analyst", example="Analyst Alex")
    note: Optional[str] = Field(None, example="Isolated host pending forensic memory dump.")

class AlertActionResponse(BaseModel):
    success: bool
    alert_id: int
    action_taken: str
    status: str
    message: str
    audit_entry: Dict[str, Any]

class AlertSummary(BaseModel):
    id: int
    title: str
    description: str
    source: str
    raw_severity: str
    current_severity: str
    status: str
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    affected_user: Optional[str] = None
    affected_host: Optional[str] = None
    dynamic_risk_score: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class AlertDetail(AlertSummary):
    enrichment_data: Optional[Dict[str, Any]] = None
    playbook_actions: Optional[List[Dict[str, Any]]] = None
    audit_log: Optional[List[Dict[str, Any]]] = []

class AlertListResponse(BaseModel):
    total: int
    page: int
    limit: int
    alerts: List[AlertSummary]
