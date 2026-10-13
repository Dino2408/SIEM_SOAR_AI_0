from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from google import genai
import os


class PlaybookStep(BaseModel):
    action: str = Field(description="Action to execute e.g. block_ip, notify_team")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    conditions: Optional[str] = Field(default=None)
    on_success: Optional[str] = Field(default="continue")
    on_failure: Optional[str] = Field(default="abort")


class PlaybookDefinition(BaseModel):
    name: str
    trigger: str
    description: Optional[str] = None
    steps: List[PlaybookStep]
    estimated_duration_minutes: Optional[int] = None


class PlaybookGenerator:
    def __init__(self):
        self.client = genai.Client()
        self.model = "gemini-3.8-flash"

    def generate_playbook(
        self,
        incident_description: str,
        event_type: str,
        affected_assets: List[str],
    ) -> PlaybookDefinition:
        prompt = (
            f"You are a cybersecurity SOAR specialist. Generate a detailed incident response playbook.\n"
            f"Event Type: {event_type}\n"
            f"Incident Description: {incident_description}\n"
            f"Affected Assets: {', '.join(affected_assets) if affected_assets else 'unknown'}\n\n"
            f"Include steps for: containment, eradication, recovery, and notification. "
            f"Use concrete actions like block_ip, isolate_host, notify_soc, collect_forensics, reset_password."
        )
        interaction = self.client.interactions.create(
            model=self.model,
            input=prompt,
            response_format=[
                {
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": PlaybookDefinition.model_json_schema(),
                }
            ],
        )
        return PlaybookDefinition.model_validate_json(interaction.output_text)

    def adapt_playbook(self, playbook_id: str, feedback: str) -> PlaybookDefinition:
        prompt = (
            f"Improve incident response playbook '{playbook_id}' based on this post-incident feedback:\n"
            f"{feedback}\n\n"
            f"Return a revised playbook with improved steps."
        )
        interaction = self.client.interactions.create(
            model=self.model,
            input=prompt,
            response_format=[
                {
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": PlaybookDefinition.model_json_schema(),
                }
            ],
        )
        return PlaybookDefinition.model_validate_json(interaction.output_text)
