from typing import Dict, Any, List, Tuple
import logging

logger = logging.getLogger("risk_scoring")

class RiskScoringEngine:
    """
    Principal SOC Dynamic Risk Scoring Engine (0 - 100)
    
    Synthesizes:
    1. Base Alert Severity Weight (0-40)
    2. External Threat Intel Signals (VirusTotal, AbuseIPDB, Shodan) (0-35)
    3. Internal Context Factors (Asset Criticality Tier, Network Zone, User IAM Privileges, MFA status) (0-25)
    
    Also generates prescriptive SOC Playbook Action Recommendations.
    """

    @classmethod
    def calculate(
        cls,
        raw_severity: str,
        asset_info: Dict[str, Any],
        user_info: Dict[str, Any],
        threat_intel: Dict[str, Any]
    ) -> Tuple[int, str, List[Dict[str, Any]]]:
        score = 0.0

        # --- 1. Base Severity Weight ---
        severity_weights = {
            "critical": 35.0,
            "high": 25.0,
            "medium": 15.0,
            "low": 5.0
        }
        score += severity_weights.get(raw_severity.lower(), 15.0)

        # --- 2. External Threat Intelligence Impact (Max ~35 pts) ---
        vt_data = threat_intel.get("virustotal", {})
        abuse_data = threat_intel.get("abuseipdb", {})
        shodan_data = threat_intel.get("shodan", {})

        # VirusTotal: up to 15 points
        vt_malicious = vt_data.get("malicious_count", 0)
        if vt_malicious > 0:
            vt_points = min(15.0, (vt_malicious / 50.0) * 15.0)
            score += vt_points

        # AbuseIPDB: up to 12 points
        abuse_score = abuse_data.get("abuse_confidence_score", 0)
        if abuse_score > 0:
            abuse_points = (abuse_score / 100.0) * 12.0
            score += abuse_points

        # Shodan: open risky ports / vulnerabilities (up to 8 points)
        open_ports = shodan_data.get("open_ports", [])
        risky_ports = {22, 23, 445, 3389, 4444, 8080}
        if any(p in risky_ports for p in open_ports):
            score += 4.0
        if shodan_data.get("vulns"):
            score += 4.0

        # --- 3. Internal Context (Asset & IAM) Impact (Max ~30 pts) ---
        # Asset Criticality
        asset_tier = asset_info.get("criticality_tier", "")
        if "Tier 0" in asset_tier: # Crown Jewel (Domain Controller, Core DB)
            score += 15.0
        elif "Tier 1" in asset_tier: # Mission Critical
            score += 8.0
        elif "Tier 2" in asset_tier:
            score += 3.0

        # Asset Environment / Network Zone
        env = asset_info.get("environment", "")
        if env.lower() == "production":
            score += 5.0
        if "DMZ" in asset_info.get("network_zone", ""):
            score += 5.0

        # User IAM Privilege Level
        priv_level = user_info.get("privilege_level", "")
        if "Admin" in priv_level or "Enterprise" in priv_level:
            score += 10.0
        elif "DevOps" in priv_level or "Privileged" in priv_level:
            score += 5.0

        # MFA disabled increases exposure
        if user_info.get("found") and not user_info.get("mfa_enabled", True):
            score += 8.0

        # Clamp score between 0 and 100
        final_score = int(min(100.0, max(0.0, round(score))))

        # Determine enriched severity
        if final_score >= 80:
            enriched_severity = "Critical"
        elif final_score >= 60:
            enriched_severity = "High"
        elif final_score >= 35:
            enriched_severity = "Medium"
        else:
            enriched_severity = "Low"

        # Generate contextual playbook actions
        playbooks = cls._generate_playbooks(final_score, asset_info, user_info, threat_intel)

        return final_score, enriched_severity, playbooks

    @classmethod
    def _generate_playbooks(
        cls,
        score: int,
        asset_info: Dict[str, Any],
        user_info: Dict[str, Any],
        threat_intel: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        playbooks = []

        host = asset_info.get("hostname")
        is_isolated = asset_info.get("is_isolated", False)
        dest_ip = threat_intel.get("dest_ip") or threat_intel.get("abuseipdb", {}).get("ip_address")
        username = user_info.get("username")
        account_status = user_info.get("account_status", "Active")

        # 1. Endpoint Containment Playbook
        if host and not is_isolated:
            playbooks.append({
                "action_id": "isolate_host",
                "title": "Isolate Host via EDR",
                "category": "Containment",
                "recommended": score >= 60,
                "urgency": "Immediate" if score >= 80 else "Standard",
                "description": f"Sever network interfaces on host '{host}' preserving SOC telemetry socket.",
                "target": host
            })
        elif host and is_isolated:
            playbooks.append({
                "action_id": "unisolate_host",
                "title": "Restore Host Connectivity",
                "category": "Containment",
                "recommended": False,
                "urgency": "Low",
                "description": f"Remove network quarantine lock on host '{host}'.",
                "target": host
            })

        # 2. Perimeter Firewall IP Blocking Playbook
        if dest_ip and not dest_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            playbooks.append({
                "action_id": "block_ip",
                "title": f"Block Threat Actor IP ({dest_ip})",
                "category": "Perimeter Defense",
                "recommended": score >= 50 or threat_intel.get("abuseipdb", {}).get("abuse_confidence_score", 0) > 60,
                "urgency": "Immediate" if score >= 75 else "Standard",
                "description": f"Push {dest_ip} to Palo Alto / Fortinet perimeter drop list and AWS WAF.",
                "target": dest_ip
            })

        # 3. Identity Credential Revocation Playbook
        if username and account_status == "Active":
            playbooks.append({
                "action_id": "reset_credentials",
                "title": f"Revoke Sessions & Reset MFA for '{username}'",
                "category": "Identity (IAM)",
                "recommended": score >= 70 or "Admin" in user_info.get("privilege_level", ""),
                "urgency": "Immediate" if "Admin" in user_info.get("privilege_level", "") else "Standard",
                "description": f"Revoke Entra ID / Okta active refresh tokens and enforce password reset on next login.",
                "target": username
            })

        # 4. Standard SOC Triage Actions
        playbooks.append({
            "action_id": "acknowledge",
            "title": "Acknowledge & Assign to Analyst",
            "category": "Triage",
            "recommended": True,
            "urgency": "Low",
            "description": "Mark alert as Triaged under your operational queue.",
            "target": "alert"
        })

        playbooks.append({
            "action_id": "dismiss",
            "title": "Dismiss as Benign / False Positive",
            "category": "Resolution",
            "recommended": score < 30,
            "urgency": "Low",
            "description": "Close alert with FP tagging and suppress future identical noise.",
            "target": "alert"
        })

        return playbooks

risk_scoring_engine = RiskScoringEngine()
