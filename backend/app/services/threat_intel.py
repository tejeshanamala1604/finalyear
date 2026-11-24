import httpx
import logging
import hashlib
from typing import Dict, Any, Optional
from app.config import settings
from app.services.cache import cache_service

logger = logging.getLogger("threat_intel")

class ThreatIntelService:
    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.abuse_api_key = settings.ABUSEIPDB_API_KEY
        self.shodan_api_key = settings.SHODAN_API_KEY

    # ---------------- VirusTotal ---------------- #
    async def query_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        cache_key = f"vt:ip:{ip}"
        cached = cache_service.get(cache_key)
        if cached:
            return cached

        if self.vt_api_key:
            try:
                headers = {"x-apikey": self.vt_api_key}
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers=headers
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {}).get("attributes", {})
                        stats = data.get("last_analysis_stats", {})
                        result = {
                            "source": "VirusTotal v3",
                            "queried_target": ip,
                            "malicious_count": stats.get("malicious", 0),
                            "suspicious_count": stats.get("suspicious", 0),
                            "harmless_count": stats.get("harmless", 0),
                            "reputation": data.get("reputation", 0),
                            "as_owner": data.get("as_owner", "Unknown ASN"),
                            "country": data.get("country", "Unknown"),
                            "is_mock": False
                        }
                        cache_service.set(cache_key, result)
                        return result
            except Exception as e:
                logger.warning(f"VT API call failed: {e}. Falling back to mock engine.")

        # Realistic High-Fidelity Mock
        result = self._mock_vt_ip(ip)
        cache_service.set(cache_key, result)
        return result

    async def query_virustotal_hash(self, file_hash: str) -> Dict[str, Any]:
        cache_key = f"vt:hash:{file_hash}"
        cached = cache_service.get(cache_key)
        if cached:
            return cached

        if self.vt_api_key:
            try:
                headers = {"x-apikey": self.vt_api_key}
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/files/{file_hash}",
                        headers=headers
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {}).get("attributes", {})
                        stats = data.get("last_analysis_stats", {})
                        result = {
                            "source": "VirusTotal v3",
                            "queried_target": file_hash,
                            "malicious_count": stats.get("malicious", 0),
                            "suspicious_count": stats.get("suspicious", 0),
                            "undetected_count": stats.get("undetected", 0),
                            "total_engines": sum(stats.values()) if stats else 72,
                            "popular_threat_name": data.get("popular_threat_classification", {}).get("suggested_threat_label", "Trojan.Generic"),
                            "file_type": data.get("type_description", "Win32 Executable"),
                            "meaningful_name": data.get("meaningful_name", "unknown_sample.exe"),
                            "is_mock": False
                        }
                        cache_service.set(cache_key, result)
                        return result
            except Exception as e:
                logger.warning(f"VT Hash API call failed: {e}. Falling back to mock engine.")

        result = self._mock_vt_hash(file_hash)
        cache_service.set(cache_key, result)
        return result

    # ---------------- AbuseIPDB ---------------- #
    async def query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        cache_key = f"abuseipdb:{ip}"
        cached = cache_service.get(cache_key)
        if cached:
            return cached

        if self.abuse_api_key:
            try:
                headers = {
                    "Key": self.abuse_api_key,
                    "Accept": "application/json"
                }
                params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers=headers,
                        params=params
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        result = {
                            "source": "AbuseIPDB v2",
                            "ip_address": ip,
                            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                            "total_reports": data.get("totalReports", 0),
                            "isp": data.get("isp", "Unknown ISP"),
                            "domain": data.get("domain", ""),
                            "country_code": data.get("countryCode", "US"),
                            "usage_type": data.get("usageType", "Data Center/Web Hosting"),
                            "is_whitelisted": data.get("isWhitelisted", False),
                            "is_mock": False
                        }
                        cache_service.set(cache_key, result)
                        return result
            except Exception as e:
                logger.warning(f"AbuseIPDB call failed: {e}. Using mock engine.")

        result = self._mock_abuseipdb(ip)
        cache_service.set(cache_key, result)
        return result

    # ---------------- Shodan ---------------- #
    async def query_shodan(self, ip: str) -> Dict[str, Any]:
        cache_key = f"shodan:{ip}"
        cached = cache_service.get(cache_key)
        if cached:
            return cached

        if self.shodan_api_key:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        result = {
                            "source": "Shodan",
                            "ip_address": ip,
                            "open_ports": data.get("ports", []),
                            "hostnames": data.get("hostnames", []),
                            "asn": data.get("asn", "Unknown"),
                            "organization": data.get("org", "Unknown"),
                            "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
                            "city": data.get("city", "Unknown"),
                            "country": data.get("country_name", "Unknown"),
                            "is_mock": False
                        }
                        cache_service.set(cache_key, result)
                        return result
            except Exception as e:
                logger.warning(f"Shodan call failed: {e}. Using mock engine.")

        result = self._mock_shodan(ip)
        cache_service.set(cache_key, result)
        return result

    # ---------------- Realistic Mock Engines ---------------- #
    def _mock_vt_ip(self, ip: str) -> Dict[str, Any]:
        # Deterministic variation based on IP
        seed = int(hashlib.md5(ip.encode()).hexdigest()[:6], 16)
        is_private = ip.startswith(("10.", "172.16.", "192.168.", "127."))
        
        if is_private:
            return {
                "source": "VirusTotal v3 (Simulation)",
                "queried_target": ip,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 72,
                "reputation": 0,
                "as_owner": "RFC1918 Private Enterprise Network",
                "country": "INTERNAL",
                "top_detecting_engines": [],
                "is_mock": True
            }
            
        malicious = 42 if seed % 2 == 0 else (18 if seed % 3 == 0 else 3)
        return {
            "source": "VirusTotal v3 (Simulation)",
            "queried_target": ip,
            "malicious_count": malicious,
            "suspicious_count": 4,
            "harmless_count": 72 - (malicious + 4),
            "reputation": - (malicious * 2),
            "as_owner": "AS14061 DigitalOcean, LLC" if seed % 2 == 0 else "AS9009 M247 Europe Ltd",
            "country": "RU" if seed % 4 == 0 else ("CN" if seed % 4 == 1 else "NL"),
            "top_detecting_engines": ["Kaspersky", "CrowdStrike Falcon", "Microsoft Defender", "SentinelOne", "Sophos"] if malicious > 10 else ["Fortinet"],
            "is_mock": True
        }

    def _mock_vt_hash(self, file_hash: str) -> Dict[str, Any]:
        seed = int(hashlib.md5(file_hash.encode()).hexdigest()[:6], 16)
        malicious = 61 if seed % 2 == 0 else (34 if seed % 3 == 0 else 8)
        threat_families = ["CobaltStrike.Stager", "Trojan.Mimikatz.Gen", "Ransomware.LockBit.3", "Backdoor.Sliver.Agent", "Exploit.CVE-2024-21413"]
        return {
            "source": "VirusTotal v3 (Simulation)",
            "queried_target": file_hash,
            "malicious_count": malicious,
            "suspicious_count": 3,
            "undetected_count": 72 - (malicious + 3),
            "total_engines": 72,
            "popular_threat_name": threat_families[seed % len(threat_families)],
            "file_type": "PE32+ Executable (GUI) x86-64",
            "meaningful_name": f"stage2_payload_{seed % 999}.exe",
            "first_seen": "2026-03-12T04:22:10Z",
            "top_detecting_engines": ["Kaspersky", "CrowdStrike Falcon", "BitDefender", "Symantec", "ESET-NOD32"],
            "is_mock": True
        }

    def _mock_abuseipdb(self, ip: str) -> Dict[str, Any]:
        is_private = ip.startswith(("10.", "172.16.", "192.168.", "127."))
        if is_private:
            return {
                "source": "AbuseIPDB v2 (Simulation)",
                "ip_address": ip,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "isp": "Local Enterprise Infrastructure",
                "domain": "internal.lan",
                "country_code": "INTERNAL",
                "usage_type": "Private Subnet",
                "is_whitelisted": True,
                "is_mock": True
            }

        seed = int(hashlib.md5(ip.encode()).hexdigest()[:6], 16)
        score = 98 if seed % 2 == 0 else (75 if seed % 3 == 0 else 22)
        return {
            "source": "AbuseIPDB v2 (Simulation)",
            "ip_address": ip,
            "abuse_confidence_score": score,
            "total_reports": 314 if score > 70 else 18,
            "isp": "HostKey B.V. Bulletproof Hosting" if score > 70 else "Cloudflare Transit",
            "domain": "badhost-c2.net" if score > 70 else "cdn-edge-node.org",
            "country_code": "RU" if seed % 3 == 0 else "NL",
            "usage_type": "Data Center / Web Hosting / Transit",
            "is_whitelisted": False,
            "last_reported_at": "2026-09-28T09:12:00Z",
            "is_mock": True
        }

    def _mock_shodan(self, ip: str) -> Dict[str, Any]:
        is_private = ip.startswith(("10.", "172.16.", "192.168.", "127."))
        if is_private:
            return {
                "source": "Shodan (Simulation)",
                "ip_address": ip,
                "open_ports": [135, 445, 3389],
                "hostnames": [f"int-host-{ip.replace('.', '-')}.corp.internal"],
                "asn": "AS-PRIVATE-ENTERPRISE",
                "organization": "Corporate Internal Network",
                "vulns": [],
                "city": "Private Datacenter",
                "country": "Corporate LAN",
                "is_mock": True
            }

        seed = int(hashlib.md5(ip.encode()).hexdigest()[:6], 16)
        ports = [22, 80, 443, 4444, 8080, 3389] if seed % 2 == 0 else [80, 443, 8443]
        vulns = ["CVE-2023-38606", "CVE-2024-21413", "CVE-2021-44228 (Log4Shell)"] if seed % 2 == 0 else []
        return {
            "source": "Shodan (Simulation)",
            "ip_address": ip,
            "open_ports": ports,
            "hostnames": [f"c2-node-{seed % 100}.anon-network.org"],
            "asn": "AS49981 WorldStream B.V.",
            "organization": "WorldStream VPS Hosting",
            "vulns": vulns,
            "city": "Amsterdam",
            "country": "Netherlands",
            "is_mock": True
        }

threat_intel_service = ThreatIntelService()
