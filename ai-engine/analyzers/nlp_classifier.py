import re
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from google import genai


class LogClassification(BaseModel):
    parsed_fields: Dict[str, Any] = Field(default_factory=dict)
    event_type: str = Field(description="e.g. brute_force, sql_injection, port_scan, privilege_escalation, data_exfil")
    confidence: float = Field(ge=0.0, le=1.0)
    raw_log: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    username: Optional[str] = None
    severity: Optional[str] = None


# Pre-compiled regex patterns for common log formats
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user|username|for)\s+(\S+)", re.IGNORECASE)
_FAIL_RE = re.compile(r"(?:failed|failure|invalid|refused)", re.IGNORECASE)


class LogClassifier:
    def __init__(self):
        self.client = genai.Client()
        self.model = "gemini-3.8-flash"

    def _quick_extract(self, raw_log: str) -> Dict[str, Any]:
        """Fast regex pre-extraction before calling Gemini."""
        ips = _IP_RE.findall(raw_log)
        user_match = _USER_RE.search(raw_log)
        return {
            "source_ip": ips[0] if ips else None,
            "dest_ip": ips[1] if len(ips) > 1 else None,
            "username": user_match.group(1) if user_match else None,
            "is_failure": bool(_FAIL_RE.search(raw_log)),
        }

    def classify_log(self, raw_log: str) -> LogClassification:
        # Quick pre-extraction
        quick = self._quick_extract(raw_log)

        prompt = (
            "You are a log analysis expert. Parse and classify this security log entry.\n"
            "Identify: event_type (brute_force/sql_injection/port_scan/privilege_escalation/"
            "data_exfil/malware/c2_beacon/normal), severity (LOW/MEDIUM/HIGH/CRITICAL), "
            "and extract key fields.\n\n"
            f"Log entry:\n{raw_log}"
        )
        interaction = self.client.interactions.create(
            model=self.model,
            input=prompt,
            response_format=[
                {
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": LogClassification.model_json_schema(),
                }
            ],
        )
        result = LogClassification.model_validate_json(interaction.output_text)
        # Merge quick-extracted IPs if Gemini missed them
        if not result.source_ip and quick.get("source_ip"):
            result.source_ip = quick["source_ip"]
        if not result.dest_ip and quick.get("dest_ip"):
            result.dest_ip = quick["dest_ip"]
        return result
