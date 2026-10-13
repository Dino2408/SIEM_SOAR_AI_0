"""
Security Event Analyzer using Gemini AI.

Analyzes security events, correlates attack patterns, and generates
structured threat intelligence using Gemini gemini-3.8-flash model.
"""
import os
import json
import time
from typing import List, Optional

from pydantic import BaseModel, Field
from google import genai
import redis
import structlog

logger = structlog.get_logger(__name__)

# ─── Prompts ──────────────────────────────────────────────────────────────────

SYSTEM_INSTRUCTION = """You are an expert cybersecurity analyst specialized in SIEM and threat intelligence.
Your expertise covers:
- MITRE ATT&CK framework (techniques, tactics, sub-techniques)
- Network security and intrusion detection
- Malware behavior analysis
- Incident response best practices
- False positive identification

Always provide accurate, actionable analysis based on the actual event data provided.
Classify severity as: LOW, MEDIUM, HIGH, or CRITICAL.
Identify MITRE technique IDs (e.g., T1110, T1059.001) and tactics (e.g., Initial Access, Execution)."""

ANALYZE_EVENT_PROMPT = """Analyze the following security event and provide a complete threat assessment:

Security Event Data:
{event_data}

Provide:
1. Severity level (LOW/MEDIUM/HIGH/CRITICAL) based on potential impact
2. Confidence score (0.0-1.0) for this assessment
3. MITRE ATT&CK technique ID (e.g., T1110.001)
4. MITRE ATT&CK tactic (e.g., Credential Access)
5. Specific threat type (e.g., brute_force, sql_injection, port_scan)
6. False positive probability (0.0-1.0)
7. Recommended actions (specific, actionable SOC steps)
8. Detailed technical explanation
9. IoC indicators extracted (IPs, domains, hashes)"""

CORRELATE_EVENTS_PROMPT = """Analyze these {count} security events and identify the attack chain:

Events:
{events_data}

Provide:
1. Complete attack chain (ordered steps)
2. All affected assets (IPs, hosts, users)
3. Severity escalation recommendation (SAME/ESCALATE_TO_HIGH/ESCALATE_TO_CRITICAL)
4. Response playbook to trigger (brute_force_response/malware_response/data_breach_response)

Look for: reconnaissance → initial access → persistence → lateral movement → exfiltration"""


# ─── Pydantic Models ──────────────────────────────────────────────────────────

class AnalysisResult(BaseModel):
    severity: str = Field(description="Severity level: LOW, MEDIUM, HIGH, or CRITICAL")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    mitre_technique: str = Field(description="MITRE ATT&CK technique ID, e.g. T1110.001")
    mitre_tactic: str = Field(description="MITRE ATT&CK tactic, e.g. Credential Access")
    threat_type: str = Field(description="Specific threat category, e.g. brute_force")
    is_false_positive_probability: float = Field(ge=0.0, le=1.0)
    recommended_actions: List[str] = Field(description="Actionable response steps")
    explanation: str = Field(description="Detailed technical explanation")
    ioc_indicators: List[str] = Field(description="Extracted IoC indicators")


class CorrelationResult(BaseModel):
    attack_chain: List[str] = Field(description="Ordered attack steps")
    affected_assets: List[str] = Field(description="Affected IPs, hosts, users")
    severity_escalation: str = Field(
        description="SAME, ESCALATE_TO_HIGH, or ESCALATE_TO_CRITICAL"
    )
    recommended_playbook: str = Field(description="Playbook name to execute")


# ─── Analyzer ─────────────────────────────────────────────────────────────────

class EventAnalyzer:
    """AI-powered security event analyzer using Gemini gemini-3.8-flash."""

    MAX_RETRIES = 3
    RETRY_BASE_DELAY = 1.0  # seconds

    def __init__(self):
        self.client = genai.Client()
        self.model = "gemini-3.8-flash"
        self._redis = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=0,
            decode_responses=True,
        )

    def _get_cache(self, key: str) -> Optional[str]:
        """Get cached analysis result from Redis."""
        try:
            return self._redis.get(key)
        except redis.RedisError as e:
            logger.warning("redis_cache_get_error", error=str(e))
            return None

    def _set_cache(self, key: str, value: str, ttl: int = 3600) -> None:
        """Cache analysis result with TTL."""
        try:
            self._redis.setex(key, ttl, value)
        except redis.RedisError as e:
            logger.warning("redis_cache_set_error", error=str(e))

    def _call_gemini_with_retry(self, prompt: str, output_schema) -> str:
        """Call Gemini API with exponential backoff retry."""
        for attempt in range(self.MAX_RETRIES):
            try:
                interaction = self.client.interactions.create(
                    model=self.model,
                    system_instruction=SYSTEM_INSTRUCTION,
                    input=prompt,
                    response_format=[
                        {
                            "type": "text",
                            "mime_type": "application/json",
                            "schema": output_schema.model_json_schema(),
                        }
                    ],
                )
                return interaction.output_text
            except Exception as e:
                if attempt == self.MAX_RETRIES - 1:
                    raise
                delay = self.RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "gemini_retry",
                    attempt=attempt + 1,
                    delay=delay,
                    error=str(e),
                )
                time.sleep(delay)

    def analyze_event(self, event_data: dict) -> AnalysisResult:
        """Analyze a single security event with Gemini AI."""
        event_str = json.dumps(event_data, indent=2)
        cache_key = f"event_analysis:{hash(event_str)}"

        # Check cache first
        cached = self._get_cache(cache_key)
        if cached:
            return AnalysisResult.model_validate_json(cached)

        prompt = ANALYZE_EVENT_PROMPT.format(event_data=event_str)

        try:
            result_text = self._call_gemini_with_retry(prompt, AnalysisResult)
            result = AnalysisResult.model_validate_json(result_text)
            self._set_cache(cache_key, result.model_dump_json(), ttl=3600)
            logger.info(
                "event_analyzed",
                threat_type=result.threat_type,
                severity=result.severity,
                mitre_technique=result.mitre_technique,
            )
            return result
        except Exception as e:
            logger.error("analyze_event_error", error=str(e))
            raise

    def analyze_batch(self, events: List[dict]) -> List[AnalysisResult]:
        """Analyze multiple events with rate limiting."""
        results = []
        for i, event in enumerate(events):
            try:
                result = self.analyze_event(event)
                results.append(result)
            except Exception as e:
                logger.error("batch_event_error", index=i, error=str(e))
                results.append(AnalysisResult(
                    severity="MEDIUM",
                    confidence=0.3,
                    mitre_technique="T0000",
                    mitre_tactic="Unknown",
                    threat_type="analysis_failed",
                    is_false_positive_probability=0.5,
                    recommended_actions=["Manual review required"],
                    explanation=f"AI analysis failed: {str(e)}",
                    ioc_indicators=[],
                ))
            if i < len(events) - 1:
                time.sleep(0.5)  # rate limiting
        return results

    def correlate_events(self, events: List[dict]) -> CorrelationResult:
        """Correlate multiple events to identify attack chains."""
        events_str = json.dumps(events, indent=2)
        cache_key = f"correlation:{hash(events_str)}"

        cached = self._get_cache(cache_key)
        if cached:
            return CorrelationResult.model_validate_json(cached)

        prompt = CORRELATE_EVENTS_PROMPT.format(
            count=len(events),
            events_data=events_str,
        )

        try:
            result_text = self._call_gemini_with_retry(prompt, CorrelationResult)
            result = CorrelationResult.model_validate_json(result_text)
            self._set_cache(cache_key, result.model_dump_json(), ttl=1800)
            logger.info(
                "events_correlated",
                event_count=len(events),
                severity_escalation=result.severity_escalation,
                recommended_playbook=result.recommended_playbook,
            )
            return result
        except Exception as e:
            logger.error("correlate_events_error", error=str(e))
            raise

