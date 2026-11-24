import asyncio
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.user import User
from app.models.alert import Alert
from app.services.threat_intel import threat_intel_service
from app.services.risk_score import risk_scoring_engine

logger = logging.getLogger("enrichment_service")

class EnrichmentService:
    @classmethod
    async def enrich_alert(cls, alert: Alert, db: Session) -> Alert:
        """
        Orchestrates parallel enrichment across:
        1. Internal Asset CMDB
        2. Internal IAM Identity Directory
        3. External Threat Intel (VirusTotal, AbuseIPDB, Shodan)
        Computes dynamic risk score and populates actionable SOC playbooks.
        """
        logger.info(f"Initiating enrichment pipeline for Alert ID={alert.id}, Title='{alert.title}'")

        # 1. Internal Asset Lookup
        asset_info = cls._get_internal_asset_context(alert, db)

        # 2. Internal IAM User Lookup
        user_info = cls._get_internal_user_context(alert, db)

        # 3. External Threat Intelligence (Parallel Execution)
        threat_intel = await cls._fetch_threat_intelligence(alert)

        # 4. Resolve MITRE ATT&CK Matrix Mapping
        if not alert.mitre_technique_id or not alert.mitre_tactic:
            tid, tactic = cls._resolve_mitre_attack(alert)
            alert.mitre_technique_id = tid
            alert.mitre_tactic = tactic

        # 5. Synthesize Risk Score and Playbook Suggestions
        score, enriched_severity, playbooks = risk_scoring_engine.calculate(
            raw_severity=alert.raw_severity,
            asset_info=asset_info,
            user_info=user_info,
            threat_intel=threat_intel
        )

        # 6. Populate Alert Model
        alert.dynamic_risk_score = score
        alert.current_severity = enriched_severity
        alert.enrichment_data = {
            "internal_asset": asset_info,
            "internal_user": user_info,
            "threat_intelligence": threat_intel,
            "mitre_attack": {
                "technique_id": alert.mitre_technique_id,
                "tactic": alert.mitre_tactic,
                "url": f"https://attack.mitre.org/techniques/{alert.mitre_technique_id.split('.')[0]}/" if alert.mitre_technique_id else None
            }
        }
        alert.playbook_actions = playbooks

        # If alert is still 'New', update status to 'Triaged' once enriched
        if alert.status == "New":
            alert.status = "Triaged"

        db.commit()
        db.refresh(alert)
        logger.info(f"Enrichment completed for Alert ID={alert.id}. Dynamic Risk Score: {score}/100 ({enriched_severity})")
        return alert

    @classmethod
    def _get_internal_asset_context(cls, alert: Alert, db: Session) -> Dict[str, Any]:
        asset = None
        if alert.affected_host:
            asset = db.query(Asset).filter(Asset.hostname.ilike(alert.affected_host)).first()
        if not asset and alert.src_ip:
            asset = db.query(Asset).filter(Asset.ip_address == alert.src_ip).first()

        if asset:
            return {
                "found": True,
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "mac_address": asset.mac_address,
                "os": asset.os,
                "department": asset.department,
                "owner": asset.owner,
                "criticality_tier": asset.criticality_tier,
                "environment": asset.environment,
                "network_zone": asset.network_zone,
                "is_isolated": asset.is_isolated,
                "isolation_timestamp": asset.isolation_timestamp.isoformat() if asset.isolation_timestamp else None,
                "last_patched": asset.last_patched.isoformat() if asset.last_patched else None
            }
        
        return {
            "found": False,
            "hostname": alert.affected_host or "Unknown Host",
            "ip_address": alert.src_ip or "Unknown IP",
            "criticality_tier": "Tier 2 - Unmanaged / Ephemeral",
            "environment": "External / Unregistered",
            "network_zone": "Untrusted Subnet",
            "is_isolated": False
        }

    @classmethod
    def _get_internal_user_context(cls, alert: Alert, db: Session) -> Dict[str, Any]:
        user = None
        if alert.affected_user:
            user = db.query(User).filter(User.username.ilike(alert.affected_user)).first()

        if user:
            return {
                "found": True,
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "department": user.department,
                "role": user.role,
                "privilege_level": user.privilege_level,
                "mfa_enabled": user.mfa_enabled,
                "account_status": user.account_status,
                "last_login_ip": user.last_login_ip
            }

        return {
            "found": False,
            "username": alert.affected_user or "System / Service Account",
            "full_name": "Unregistered / Service Identity",
            "privilege_level": "Standard User",
            "mfa_enabled": True,
            "account_status": "Unknown"
        }

    @classmethod
    async def _fetch_threat_intelligence(cls, alert: Alert) -> Dict[str, Any]:
        tasks = []
        target_ip = alert.dest_ip or alert.src_ip

        # Concurrently query external APIs with caching
        async def fetch_vt_ip():
            if target_ip:
                return "virustotal", await threat_intel_service.query_virustotal_ip(target_ip)
            return "virustotal", {}

        async def fetch_abuseipdb():
            if target_ip:
                return "abuseipdb", await threat_intel_service.query_abuseipdb(target_ip)
            return "abuseipdb", {}

        async def fetch_shodan():
            if target_ip:
                return "shodan", await threat_intel_service.query_shodan(target_ip)
            return "shodan", {}

        async def fetch_vt_hash():
            if alert.file_hash:
                return "virustotal_file", await threat_intel_service.query_virustotal_hash(alert.file_hash)
            return "virustotal_file", {}

        tasks = [fetch_vt_ip(), fetch_abuseipdb(), fetch_shodan()]
        if alert.file_hash:
            tasks.append(fetch_vt_hash())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        threat_intel = {"target_ip": target_ip}
        for item in results:
            if isinstance(item, tuple) and len(item) == 2:
                key, val = item
                threat_intel[key] = val
            elif isinstance(item, Exception):
                logger.error(f"Threat intel task error: {item}")

        return threat_intel

    @classmethod
    def _resolve_mitre_attack(cls, alert: Alert) -> tuple[str, str]:
        """
        Classifies the threat indicator and title into the MITRE ATT&CK Matrix taxonomy.
        Returns (Technique ID, Tactic Name).
        """
        text = f"{alert.title} {alert.description} {alert.source}".lower()

        if any(w in text for w in ["beacon", "cobalt strike", "c2", "command and control"]):
            return ("T1071.001", "Command and Control")
        if any(w in text for w in ["lsass", "mimikatz", "credential dump", "kerberos"]):
            return ("T1003.001", "Credential Access")
        if any(w in text for w in ["kerberoast", "tgs-req"]):
            return ("T1558.003", "Credential Access")
        if any(w in text for w in ["winrm", "wmi", "lateral movement"]):
            return ("T1047", "Lateral Movement")
        if any(w in text for w in ["ransomware", "lockbit", "canary", "encrypt"]):
            return ("T1486", "Impact")
        if any(w in text for w in ["dns tunnel", "exfil", "data exfiltration"]):
            return ("T1071.004", "Exfiltration")
        if any(w in text for w in ["brute-force", "password spray", "failed authentication"]):
            return ("T1110.003", "Credential Access")
        if any(w in text for w in ["powershell", "rundll32", "command line", "script"]):
            return ("T1059.001", "Execution")
        if any(w in text for w in ["dropper", "dll", "trojan"]):
            return ("T1204.002", "Execution")

        return ("T1204.002", "Execution")

enrichment_service = EnrichmentService()

