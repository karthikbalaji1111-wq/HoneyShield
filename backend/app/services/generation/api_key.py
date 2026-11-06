"""Fake API key generator strategy."""
from __future__ import annotations

import secrets
import string
from typing import Any

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator


class ApiKeyGenerator(BaseGenerator):
    """Generates realistic high-entropy API keys."""

    def generate(self, project_domain: str, params: dict[str, Any]) -> GeneratedTokenData:
        provider = params.get("provider_style", "generic").lower()
        
        # 32 characters of randomness encoded in base62-ish characters
        alphabet = string.ascii_letters + string.digits
        random_suffix = "".join(secrets.choice(alphabet) for _ in range(32))
        
        if provider == "stripe":
            prefix = secrets.choice(["sk_live_", "sk_test_"])
            token_value = f"{prefix}{random_suffix}"
            label = "Stripe API Key"
        elif provider == "openai":
            prefix = "sk-"
            token_value = f"{prefix}{random_suffix}"
            label = "OpenAI API Key"
        else:
            prefix = secrets.choice(["ak_", "key_", "prod_", "live_"])
            token_value = f"{prefix}{random_suffix}"
            label = "Generic API Key"

        return GeneratedTokenData(
            token_value=token_value,
            label=label,
            metadata={"provider_style": provider, "entropy_bytes": 32},
        )
