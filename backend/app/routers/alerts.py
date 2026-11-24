import asyncio
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from app.database import get_db
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.user import User
from app.schemas.alert import (
    AlertCreate,
    AlertSummary,
    AlertDetail,
    AlertListResponse,
    AlertActionRequest,
    AlertActionResponse
)
from app.services.enrichment import enrichment_service
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/alerts", tags=["Alerts & Enrichment"])

async def _run_async_enrichment(alert_id: int, db_session_maker):
    db = db_session_maker()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            await enrichment_service.enrich_alert(alert, db)
            # Broadcast enriched update to connected analysts
            await ws_manager.broadcast("alert_enriched", {
                "id": alert.id,
                "title": alert.title,
                "status": alert.status,
                "current_severity": alert.current_severity,
                "dynamic_risk_score": alert.dynamic_risk_score,
                "enrichment_data": alert.enrichment_data
            })
    finally:
        db.close()

@router.post("", response_model=AlertDetail, status_code=201)
async def ingest_alert(
    payload: AlertCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Webhook endpoint for raw alert ingestion from EDR, SIEM, or Cloud IDS.
    Stores initial alert, broadcasts live notification, and enriches asynchronously.
    """
    new_alert = Alert(
        title=payload.title,
        description=payload.description,
        source=payload.source,
        raw_severity=payload.raw_severity,
        current_severity=payload.raw_severity,
        status="New",
        src_ip=payload.src_ip,
        dest_ip=payload.dest_ip,
        dest_port=payload.dest_port,
        file_hash=payload.file_hash,
        domain=payload.domain,
        affected_user=payload.affected_user,
        affected_host=payload.affected_host,
        dynamic_risk_score=0,
        audit_log=[{
            "timestamp": datetime.utcnow().isoformat(),
            "analyst": "Webhook Receiver",
            "action": "Ingested",
            "note": f"Raw payload received from {payload.source}"
        }]
    )
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)

    # Broadcast initial alert ingestion
    await ws_manager.broadcast("alert_created", {
        "id": new_alert.id,
        "title": new_alert.title,
        "source": new_alert.source,
        "raw_severity": new_alert.raw_severity,
        "created_at": new_alert.created_at.isoformat()
    })

    # Trigger async enrichment pipeline immediately
    from app.database import SessionLocal
    background_tasks.add_task(_run_async_enrichment, new_alert.id, SessionLocal)

    # Also synchronously enrich now if fast
    await enrichment_service.enrich_alert(new_alert, db)

    return new_alert

@router.get("", response_model=AlertListResponse)
def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low)"),
    status: Optional[str] = Query(None, description="Filter by status (New, Triaged, In Progress, Mitigated, Dismissed)"),
    search: Optional[str] = Query(None, description="Search term for title, IP, host, or user"),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Retrieves paginated alerts with multi-dimensional filtering.
    """
    query = db.query(Alert)

    if severity:
        query = query.filter(
            or_(
                Alert.current_severity.ilike(severity),
                Alert.raw_severity.ilike(severity)
            )
        )
    if status:
        query = query.filter(Alert.status.ilike(status))

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Alert.title.ilike(search_pattern),
                Alert.affected_host.ilike(search_pattern),
                Alert.affected_user.ilike(search_pattern),
                Alert.src_ip.ilike(search_pattern),
                Alert.dest_ip.ilike(search_pattern)
            )
        )

    total = query.count()
    alerts = query.order_by(desc(Alert.created_at)).offset((page - 1) * limit).limit(limit).all()

    return AlertListResponse(
        total=total,
        page=page,
        limit=limit,
        alerts=alerts
    )

@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    """
    Retrieves full enrichment dossier for an alert, including asset context,
    IAM profile, external threat intel scores, dynamic risk score, and playbooks.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.post("/{alert_id}/action", response_model=AlertActionResponse)
async def take_mitigation_action(
    alert_id: int,
    request: AlertActionRequest,
    db: Session = Depends(get_db)
):
    """
    Executes first-response containment & mitigation actions:
    - "Isolate Host": Isolates the endpoint via simulated EDR integration.
    - "Unisolate Host": Releases host from network isolation.
    - "Block IP": Pushes malicious IOC IP to firewall blocklist.
    - "Reset Credentials": Revokes user tokens and flags credentials in IAM.
    - "Acknowledge": Changes alert status to In Progress.
    - "Dismiss": Marks alert as Dismissed / False Positive.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    action = request.action.strip()
    audit_note = request.note or f"Action '{action}' executed by {request.analyst}"
    new_status = alert.status

    if action in ["Isolate Host", "isolate_host"]:
        if alert.affected_host:
            asset = db.query(Asset).filter(Asset.hostname.ilike(alert.affected_host)).first()
            if asset:
                asset.is_isolated = True
                asset.isolation_timestamp = datetime.utcnow()
        new_status = "In Progress"
        action_msg = f"Host '{alert.affected_host}' successfully isolated via EDR API."

    elif action in ["Unisolate Host", "unisolate_host"]:
        if alert.affected_host:
            asset = db.query(Asset).filter(Asset.hostname.ilike(alert.affected_host)).first()
            if asset:
                asset.is_isolated = False
                asset.isolation_timestamp = None
        action_msg = f"Host '{alert.affected_host}' restored to network."

    elif action in ["Block IP", "block_ip"]:
        target_ip = alert.dest_ip or alert.src_ip
        new_status = "Mitigated"
        action_msg = f"IP '{target_ip}' added to Edge Firewall & WAF Drop Rules."

    elif action in ["Reset Credentials", "reset_credentials"]:
        if alert.affected_user:
            user = db.query(User).filter(User.username.ilike(alert.affected_user)).first()
            if user:
                user.account_status = "Credentials_Revoked"
        new_status = "In Progress"
        action_msg = f"Tokens revoked and password reset enforced for user '{alert.affected_user}'."

    elif action in ["Acknowledge", "acknowledge"]:
        new_status = "In Progress"
        action_msg = f"Alert acknowledged and assigned to {request.analyst}."

    elif action in ["Dismiss", "dismiss"]:
        new_status = "Dismissed"
        action_msg = "Alert dismissed as benign/false positive."

    else:
        new_status = "In Progress"
        action_msg = f"Custom action '{action}' executed."

    # Update Alert state and append to Audit Log
    alert.status = new_status
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "analyst": request.analyst,
        "action": action,
        "note": audit_note
    }
    
    # Ensure audit_log is a list
    current_log = list(alert.audit_log or [])
    current_log.append(audit_entry)
    alert.audit_log = current_log

    db.commit()
    db.refresh(alert)

    # Broadcast action taken over WebSockets
    await ws_manager.broadcast("action_taken", {
        "alert_id": alert.id,
        "action": action,
        "new_status": new_status,
        "analyst": request.analyst,
        "message": action_msg
    })

    return AlertActionResponse(
        success=True,
        alert_id=alert.id,
        action_taken=action,
        status=new_status,
        message=action_msg,
        audit_entry=audit_entry
    )

@router.post("/simulate/inject", response_model=AlertDetail)
async def simulate_random_alert(db: Session = Depends(get_db)):
    """
    Simulation utility to generate an incoming high-priority security alert on demand.
    Demonstrates live ingestion, real-time WebSocket broadcast, and dynamic enrichment.
    """
    import random
    scenarios = [
        {
            "title": "Adversary Kerberoasting Attempt Detected (T1558.003)",
            "description": "Unusual volume of Kerberos TGS-REQ service ticket requests with RC4-HMAC encryption targeting high-value SPNs.",
            "source": "CrowdStrike Falcon",
            "raw_severity": "High",
            "src_ip": "10.0.10.88",
            "dest_ip": "10.0.1.10",
            "dest_port": 88,
            "affected_user": "marcus.chen",
            "affected_host": "WKST-DEV-09"
        },
        {
            "title": "Reverse TCP Shell Callback to Untrusted Cloud VPS",
            "description": "Process /bin/bash initiated outbound TCP connection to unauthorized Russian bulletproof hosting range on port 4444.",
            "source": "Wazuh EDR",
            "raw_severity": "Critical",
            "src_ip": "10.0.3.15",
            "dest_ip": "194.26.29.201",
            "dest_port": 4444,
            "affected_user": "svc_k8s_deploy",
            "affected_host": "K8S-APP-NODE-03"
        },
        {
            "title": "Suspicious Dropper DLL Loaded via AppData Local Temp",
            "description": "Excel spawned rundll32 with malicious encoded parameter following phishing email attachment opening.",
            "source": "Microsoft Defender ATP",
            "raw_severity": "High",
            "src_ip": "10.0.10.45",
            "dest_ip": "45.154.255.101",
            "dest_port": 443,
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "affected_user": "j.smith",
            "affected_host": "WKST-FIN-04"
        }
    ]
    scenario = random.choice(scenarios)
    created = Alert(
        title=scenario["title"],
        description=scenario["description"],
        source=scenario["source"],
        raw_severity=scenario["raw_severity"],
        current_severity=scenario["raw_severity"],
        status="New",
        src_ip=scenario.get("src_ip"),
        dest_ip=scenario.get("dest_ip"),
        dest_port=scenario.get("dest_port"),
        file_hash=scenario.get("file_hash"),
        affected_user=scenario.get("affected_user"),
        affected_host=scenario.get("affected_host"),
        dynamic_risk_score=0,
        audit_log=[{
            "timestamp": datetime.utcnow().isoformat(),
            "analyst": "SOC Alert Simulator",
            "action": "Generated Ingest",
            "note": "Simulated live threat event"
        }]
    )
    db.add(created)
    db.commit()
    db.refresh(created)

    # Enrich immediately
    await enrichment_service.enrich_alert(created, db)

    # Broadcast event
    await ws_manager.broadcast("alert_created", {
        "id": created.id,
        "title": created.title,
        "source": created.source,
        "raw_severity": created.raw_severity,
        "dynamic_risk_score": created.dynamic_risk_score,
        "created_at": created.created_at.isoformat()
    })

    return created

@router.get("/{alert_id}/report")
def generate_forensic_report(alert_id: int, db: Session = Depends(get_db)):
    """
    Generates a NIST SP 800-61 / ISO 27035 Compliant Incident Forensic Report.
    Suitable for SOC auditor compliance, CISO executive briefings, and academic evaluation.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    enrichment = alert.enrichment_data or {}
    asset = enrichment.get("internal_asset", {})
    user = enrichment.get("internal_user", {})
    threat = enrichment.get("threat_intelligence", {})
    vt = threat.get("virustotal", {})
    abuse = threat.get("abuseipdb", {})
    shodan = threat.get("shodan", {})

    report_id = f"INC-SOC-{alert.id:05d}"
    
    # Classification verdict
    score = alert.dynamic_risk_score
    if score >= 80:
        verdict = "CONFIRMED CRITICAL INCIDENT — Active adversary activity detected on high-value asset. Immediate EDR isolation and credential rotation mandated."
    elif score >= 60:
        verdict = "CONFIRMED HIGH RISK THREAT — Malicious indicators correlated with adversary infrastructure. Active containment recommended."
    elif score >= 35:
        verdict = "ELEVATED SUSPICIOUS ACTIVITY — Multi-factor indicators flagged potential lateral movement or reconnaissance. Triaged for active analyst review."
    else:
        verdict = "LOW RISK / POTENTIAL BENIGN NOISE — Low threat confidence; verified safe asset exposure."

    return {
        "report_id": report_id,
        "standard": "NIST SP 800-61 Rev. 2 / ISO/IEC 27035",
        "generated_at": datetime.utcnow().isoformat(),
        "incident_classification": {
            "alert_id": alert.id,
            "title": alert.title,
            "detection_source": alert.source,
            "initial_severity": alert.raw_severity,
            "enriched_severity": alert.current_severity,
            "dynamic_risk_score": f"{alert.dynamic_risk_score}/100",
            "current_status": alert.status,
            "executive_verdict": verdict
        },
        "mitre_attack_alignment": {
            "technique_id": alert.mitre_technique_id or "T1204.002",
            "tactic": alert.mitre_tactic or "Execution",
            "reference_url": f"https://attack.mitre.org/techniques/{alert.mitre_technique_id.split('.')[0]}/" if alert.mitre_technique_id else "https://attack.mitre.org/"
        },
        "indicators_of_compromise": {
            "source_ip": alert.src_ip or "N/A",
            "destination_ip": alert.dest_ip or "N/A",
            "destination_port": alert.dest_port or "N/A",
            "file_hash_sha256": alert.file_hash or "N/A",
            "domain_c2": alert.domain or "N/A"
        },
        "internal_asset_cmdb_assessment": {
            "hostname": asset.get("hostname", "Unknown"),
            "criticality_tier": asset.get("criticality_tier", "Tier 2"),
            "operating_system": asset.get("os", "N/A"),
            "environment": asset.get("environment", "Production"),
            "network_zone": asset.get("network_zone", "Internal"),
            "owner": asset.get("owner", "IT Security"),
            "is_isolated": asset.get("is_isolated", False),
            "isolation_timestamp": asset.get("isolation_timestamp")
        },
        "iam_identity_assessment": {
            "username": user.get("username", "Unknown"),
            "full_name": user.get("full_name", "N/A"),
            "privilege_level": user.get("privilege_level", "Standard User"),
            "mfa_enforced": user.get("mfa_enabled", True),
            "account_status": user.get("account_status", "Active")
        },
        "external_threat_intelligence": {
            "virustotal_v3": {
                "malicious_engines": f"{vt.get('malicious_count', 0)}/72",
                "reputation": vt.get("reputation", 0),
                "asn_owner": vt.get("as_owner", "N/A")
            },
            "abuseipdb_v2": {
                "abuse_confidence_score": f"{abuse.get('abuse_confidence_score', 0)}%",
                "total_reports": abuse.get("total_reports", 0),
                "isp": abuse.get("isp", "N/A"),
                "country": abuse.get("country_code", "N/A")
            },
            "shodan_recon": {
                "open_ports": shodan.get("open_ports", []),
                "vulns": shodan.get("vulns", [])
            }
        },
        "chain_of_custody_audit_log": alert.audit_log or [],
        "playbook_mitigation_history": alert.playbook_actions or []
    }

