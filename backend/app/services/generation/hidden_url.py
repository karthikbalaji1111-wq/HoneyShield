"""Hidden URL generator strategy."""
from __future__ import annotations

import secrets
from typing import Any

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator


class HiddenUrlGenerator(BaseGenerator):
    """Generates realistic hidden administration and configuration paths."""

    def generate(self, project_domain: str, params: dict[str, Any]) -> GeneratedTokenData:
        slug_prefixes = [
            "admin-portal",
            "internal-console",
            "backup-archive",
            "debug-metrics",
            "private-api",
            "config-dump",
            "auth-session",
            "db-export",
        ]
        
        prefix = secrets.choice(slug_prefixes)
        random_suffix = secrets.token_hex(8)
        token_value = f"{prefix}-{random_suffix}"
        path = f"/t/{token_value}"
        url = f"https://{project_domain}{path}" if project_domain else path

        return GeneratedTokenData(
            token_value=token_value,
            label=f"Hidden URL: {prefix}",
            metadata={
                "path": path,
                "url": url,
                "decoy_category": prefix.split("-")[0],
                "domain_context": project_domain,
            },
        )
