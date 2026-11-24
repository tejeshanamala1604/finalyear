import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.user import User
from app.models.alert import Alert
from app.services.enrichment import enrichment_service

logger = logging.getLogger("soc_seed")

async def seed_database(db: Session):
    # Check if data already exists
    if db.query(Alert).first():
        logger.info("Database already seeded. Skipping initial seed.")
        return

    logger.info("Initializing enterprise SOC seed dataset...")

    # 1. Assets
    assets_data = [
        Asset(
            hostname="DC-CORP-01",
            ip_address="10.0.1.10",
            mac_address="00:1A:2B:3C:4D:10",
            os="Windows Server 2022 Datacenter",
            department="IT Infrastructure & Identity",
            owner="alex.ross",
            criticality_tier="Tier 0 - Crown Jewel (Active Directory DC)",
            environment="Production",
            network_zone="Core Identity VLAN 10",
            is_isolated=False,
            last_patched=datetime.utcnow() - timedelta(days=5)
        ),
        Asset(
            hostname="DB-PROD-CORE-01",
            ip_address="10.0.2.50",
            mac_address="00:1A:2B:3C:4D:50",
            os="Ubuntu 22.04 LTS (Kernel 5.15)",
            department="Core Banking Systems",
            owner="marcus.chen",
            criticality_tier="Tier 0 - Crown Jewel (Financial Ledger DB)",
            environment="Production",
            network_zone="PCI-DSS Regulated Zone",
            is_isolated=False,
            last_patched=datetime.utcnow() - timedelta(days=12)
        ),
        Asset(
            hostname="K8S-APP-NODE-03",
            ip_address="10.0.3.15",
            mac_address="00:1A:2B:3C:4D:15",
            os="Red Hat Enterprise Linux 9",
            department="Cloud Platform Engineering",
            owner="marcus.chen",
            criticality_tier="Tier 1 - Mission Critical (Customer API Cluster)",
            environment="Production",
            network_zone="Production DMZ",
            is_isolated=False,
            last_patched=datetime.utcnow() - timedelta(days=3)
        ),
        Asset(
            hostname="WKST-FIN-04",
            ip_address="10.0.10.45",
            mac_address="00:50:56:C0:00:45",
            os="Windows 11 Enterprise 23H2",
            department="Treasury & Finance",
            owner="j.smith",
            criticality_tier="Tier 2 - Operational Endpoint",
            environment="Corporate Office",
            network_zone="Finance Subnet 40",
            is_isolated=False,
            last_patched=datetime.utcnow() - timedelta(days=22)
        ),
        Asset(
            hostname="WKST-DEV-09",
            ip_address="10.0.10.88",
            mac_address="00:50:56:C0:00:88",
            os="macOS Sonoma 14.4",
            department="Software Engineering",
            owner="marcus.chen",
            criticality_tier="Tier 2 - Developer Endpoint",
            environment="Corporate Office",
            network_zone="Dev LAN",
            is_isolated=False,
            last_patched=datetime.utcnow() - timedelta(days=8)
        )
    ]
    db.add_all(assets_data)
    db.commit()

    # 2. Users
    users_data = [
        User(
            username="alex.ross",
            email="alex.ross@aegis-defense.internal",
            full_name="Alex Ross",
            department="Cybersecurity & IAM",
            role="Principal Security Architect",
            privilege_level="Enterprise Admin / Domain Admin",
            mfa_enabled=True,
            account_status="Active",
            last_login_ip="10.0.1.10"
        ),
        User(
            username="marcus.chen",
            email="marcus.chen@aegis-defense.internal",
            full_name="Marcus Chen",
            department="Site Reliability Engineering",
            role="Staff Cloud Architect",
            privilege_level="DevOps Admin / Root",
            mfa_enabled=True,
            account_status="Active",
            last_login_ip="10.0.10.88"
        ),
        User(
            username="j.smith",
            email="j.smith@aegis-defense.internal",
            full_name="John Smith",
            department="Accounts Payable",
            role="Senior Billing Specialist",
            privilege_level="Standard User",
            mfa_enabled=False,
            account_status="Active",
            last_login_ip="10.0.10.45"
        ),
        User(
            username="sarah.jenkins",
            email="sarah.jenkins@aegis-defense.internal",
            full_name="Sarah Jenkins",
            department="Finance & Treasury",
            role="VP of Finance",
            privilege_level="Finance Privileged / Approver",
            mfa_enabled=True,
            account_status="Active",
            last_login_ip="10.0.10.99"
        )
    ]
    db.add_all(users_data)
    db.commit()

    # 3. Raw Alerts
    raw_alerts = [
        Alert(
            title="Suspicious Cobalt Strike C2 Beaconing to Hostile Foreign IP",
            description="CrowdStrike EDR detected rundll32.exe initiating regular interval HTTPS beaconing to known adversary command-and-control server with self-signed SSL certificate.",
            source="CrowdStrike Falcon",
            raw_severity="Critical",
            status="New",
            src_ip="10.0.10.45",
            dest_ip="185.220.101.5",
            dest_port=443,
            file_hash="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            domain="cdn-sysupdate-auth.com",
            affected_user="j.smith",
            affected_host="WKST-FIN-04",
            audit_log=[
                {"timestamp": datetime.utcnow().isoformat(), "analyst": "System Pipeline", "action": "Ingested via Webhook", "note": "Webhook received from CrowdStrike API"}
            ]
        ),
        Alert(
            title="Privileged Credential Dumping via LSASS Memory Injection (Mimikatz)",
            description="Wazuh agent detected unauthorized process injecting into lsass.exe to extract Kerberos TGT and NTLM hashes. Potential Tier 0 lateral movement attempt.",
            source="Wazuh EDR",
            raw_severity="Critical",
            status="New",
            src_ip="10.0.1.10",
            dest_ip="194.26.29.112",
            dest_port=4444,
            file_hash="cca92080a2489c92257973c714d68d0ee5df2d72f22b7c4d57c79e6ff2e4313f",
            affected_user="alex.ross",
            affected_host="DC-CORP-01",
            audit_log=[
                {"timestamp": datetime.utcnow().isoformat(), "analyst": "System Pipeline", "action": "Ingested via Webhook", "note": "High-priority EDR signal"}
            ]
        ),
        Alert(
            title="Anomalous Lateral Movement over WinRM & WMI Execution",
            description="Suricata IDS triggered signature ET EXPLOIT Remote WMI Process Creation. Source host spawned powershell script block targeting corporate SQL cluster.",
            source="Suricata IDS",
            raw_severity="High",
            status="New",
            src_ip="10.0.10.88",
            dest_ip="10.0.2.50",
            dest_port=5985,
            affected_user="marcus.chen",
            affected_host="WKST-DEV-09",
            audit_log=[
                {"timestamp": datetime.utcnow().isoformat(), "analyst": "System Pipeline", "action": "Ingested via Webhook", "note": "Suricata signature matched"}
            ]
        ),
        Alert(
            title="Potential Ransomware Canary File Renamed (.lockbit extension)",
            description="SentinelOne file integrity monitor detected batch renaming of decoy documents in shared file repository. Decryption note README_RESTORE_FILES.txt dropped.",
            source="SentinelOne",
            raw_severity="Critical",
            status="In Progress",
            src_ip="10.0.10.45",
            dest_ip="91.240.118.172",
            dest_port=8080,
            file_hash="9f83c605d4c82b3dd53f3cd190b8c56c2f6e3b83d8e8748b944269f24297f740",
            affected_user="j.smith",
            affected_host="WKST-FIN-04",
            audit_log=[
                {"timestamp": (datetime.utcnow() - timedelta(minutes=45)).isoformat(), "analyst": "System Pipeline", "action": "Ingested via Webhook", "note": "Ingested"},
                {"timestamp": (datetime.utcnow() - timedelta(minutes=30)).isoformat(), "analyst": "Analyst Sarah", "action": "Investigating", "note": "Correlating with endpoint backup logs"}
            ]
        ),
        Alert(
            title="Mass Outbound Data Exfiltration over Encrypted DNS Tunnel",
            description="GuardDuty flagged unusually high volume of TXT query requests directed toward authoritative nameserver ns1.evil-exfil-sink.net. Size: 1.4 GB transferred.",
            source="AWS GuardDuty",
            raw_severity="High",
            status="New",
            src_ip="10.0.3.15",
            dest_ip="193.106.191.24",
            dest_port=53,
            domain="evil-exfil-sink.net",
            affected_user="marcus.chen",
            affected_host="K8S-APP-NODE-03",
            audit_log=[
                {"timestamp": datetime.utcnow().isoformat(), "analyst": "System Pipeline", "action": "Ingested via Webhook", "note": "GuardDuty finding"}
            ]
        ),
        Alert(
            title="Brute-Force SSH Password Spray Against DMZ Gateway",
            description="Splunk correlation rule detected 4,200 failed authentication attempts within 5 minutes originating from multiple European proxy nodes.",
            source="Splunk SIEM",
            raw_severity="Medium",
            status="Mitigated",
            src_ip="45.154.255.89",
            dest_ip="10.0.3.15",
            dest_port=22,
            affected_host="K8S-APP-NODE-03",
            audit_log=[
                {"timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(), "analyst": "System Pipeline", "action": "Ingested via Webhook", "note": "Ingested"},
                {"timestamp": (datetime.utcnow() - timedelta(hours=1, minutes=45)).isoformat(), "analyst": "Analyst Alex", "action": "Block IP", "note": "Blocked at border firewall"}
            ]
        ),
        Alert(
            title="Unusual After-Hours PowerShell Execution via Task Scheduler",
            description="Scheduled task triggered base64 encoded powershell command executing hidden download cradle from remote web server.",
            source="Microsoft Defender ATP",
            raw_severity="Medium",
            status="Triaged",
            src_ip="10.0.10.45",
            dest_ip="103.208.220.122",
            dest_port=80,
            affected_user="j.smith",
            affected_host="WKST-FIN-04",
            audit_log=[
                {"timestamp": (datetime.utcnow() - timedelta(minutes=15)).isoformat(), "analyst": "System Pipeline", "action": "Ingested via Webhook", "note": "Ingested"}
            ]
        )
    ]

    db.add_all(raw_alerts)
    db.commit()

    # Enrich each alert cleanly while the session is active
    for alert in raw_alerts:
        await enrichment_service.enrich_alert(alert, db)

    logger.info("Seed dataset successfully initialized and enriched.")
