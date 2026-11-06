"""Decoy form field (honeypot input) generator strategy."""
from __future__ import annotations

import secrets
from typing import Any

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator


class FormFieldGenerator(BaseGenerator):
    """Generates realistic decoy hidden form fields / honeypot inputs."""

    def generate(self, project_domain: str, params: dict[str, Any]) -> GeneratedTokenData:
        field_names = [
            "csrf_token",
            "xsrf_token",
            "_authenticity_token",
            "form_signature",
            "anti_bot_id",
            "verify_token",
        ]
        field_name = secrets.choice(field_names)
        random_suffix = secrets.token_hex(16)
        token_value = f"ff_{random_suffix}"

        return GeneratedTokenData(
            token_value=token_value,
            label=f"Decoy Form Field: {field_name}",
            metadata={
                "field_name": field_name,
                "html_tag": f'<input type="hidden" name="{field_name}" value="{token_value}" autocomplete="off" />',
                "collection_path": f"/collect/{token_value}",
                "domain_context": project_domain,
            },
        )
