import os
import json
import redis
import httpx
from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class ThreatIntelResult(BaseModel):
    ip: Optional[str] = None
    reputation_score: int = 50          # 0=clean, 100=malicious
    country: str = "unknown"
    asn: str = "unknown"
    abuse_confidence: int = 0           # AbuseIPDB confidence %
    malware_families: List[str] = []
    tags: List[str] = []
    virustotal_positives: Optional[int] = None
    is_tor: bool = False
    is_vpn: bool = False
    cached: bool = False


class ThreatIntelEnricher:
    def __init__(self):
        redis_host = os.getenv("REDIS_HOST", "redis")
        self.redis = redis.Redis(host=redis_host, port=6379, db=1, decode_responses=True)
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.cache_ttl = 21600  # 6 hours

    def enrich_ip(self, ip: str) -> ThreatIntelResult:
        """Enrich IP address using AbuseIPDB, VirusTotal, and local cache."""
        cache_key = f"ti:ip:{ip}"

        # Check Redis cache first
        cached_raw = self.redis.get(cache_key)
        if cached_raw:
            result = ThreatIntelResult.model_validate_json(cached_raw)
            result.cached = True
            return result

        result = ThreatIntelResult(ip=ip)

        # AbuseIPDB lookup
        if self.abuseipdb_key:
            try:
                with httpx.Client(timeout=10) as client:
                    resp = client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        result.abuse_confidence = data.get("abuseConfidenceScore", 0)
                        result.country = data.get("countryCode", "unknown")
                        result.asn = data.get("isp", "unknown")
                        result.is_tor = data.get("isTor", False)
                        result.reputation_score = min(100, result.abuse_confidence)
                        usage = data.get("usageType", "")
                        if usage:
                            result.tags.append(usage)
            except Exception:
                pass  # Fail gracefully — use defaults

        # VirusTotal lookup
        if self.virustotal_key:
            try:
                with httpx.Client(timeout=10) as client:
                    resp = client.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": self.virustotal_key},
                    )
                    if resp.status_code == 200:
                        attrs = resp.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        positives = stats.get("malicious", 0)
                        result.virustotal_positives = positives
                        if positives > 0:
                            result.reputation_score = max(result.reputation_score, min(100, positives * 5))
                            result.tags.append(f"vt_malicious:{positives}")
            except Exception:
                pass

        # Cache result
        self.redis.setex(cache_key, self.cache_ttl, result.model_dump_json())
        return result

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Basic domain reputation lookup."""
        cache_key = f"ti:domain:{domain}"
        cached_raw = self.redis.get(cache_key)
        if cached_raw:
            return json.loads(cached_raw)

        result: Dict[str, Any] = {"domain": domain, "reputation": "unknown", "cached": False}

        if self.virustotal_key:
            try:
                with httpx.Client(timeout=10) as client:
                    resp = client.get(
                        f"https://www.virustotal.com/api/v3/domains/{domain}",
                        headers={"x-apikey": self.virustotal_key},
                    )
                    if resp.status_code == 200:
                        attrs = resp.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        positives = stats.get("malicious", 0)
                        result["virustotal_positives"] = positives
                        result["reputation"] = "malicious" if positives > 2 else "clean"
            except Exception:
                pass

        self.redis.setex(cache_key, self.cache_ttl, json.dumps(result))
        return result

    def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """File hash reputation lookup via VirusTotal."""
        cache_key = f"ti:hash:{file_hash}"
        cached_raw = self.redis.get(cache_key)
        if cached_raw:
            return json.loads(cached_raw)

        result: Dict[str, Any] = {"hash": file_hash, "reputation": "unknown"}

        if self.virustotal_key:
            try:
                with httpx.Client(timeout=10) as client:
                    resp = client.get(
                        f"https://www.virustotal.com/api/v3/files/{file_hash}",
                        headers={"x-apikey": self.virustotal_key},
                    )
                    if resp.status_code == 200:
                        attrs = resp.json().get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        positives = stats.get("malicious", 0)
                        result["virustotal_positives"] = positives
                        result["reputation"] = "malicious" if positives > 2 else "clean"
                        names = attrs.get("meaningful_name", "")
                        if names:
                            result["filename"] = names
            except Exception:
                pass

        self.redis.setex(cache_key, self.cache_ttl, json.dumps(result))
        return result
