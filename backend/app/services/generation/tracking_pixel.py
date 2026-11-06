"""Tracking pixel generator strategy."""
from __future__ import annotations

import secrets
from typing import Any

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator


class TrackingPixelGenerator(BaseGenerator):
    """Generates realistic invisible tracking pixel image paths."""

    def generate(self, project_domain: str, params: dict[str, Any]) -> GeneratedTokenData:
        # High-entropy random hex token identifying the pixel
        token_value = secrets.token_hex(16)
        pixel_path = f"/px/{token_value}.gif"
        pixel_url = f"https://{project_domain}{pixel_path}" if project_domain else pixel_path

        return GeneratedTokenData(
            token_value=token_value,
            label="Tracking Pixel",
            metadata={
                "pixel_path": pixel_path,
                "pixel_url": pixel_url,
                "html_tag": f'<img src="{pixel_path}" width="1" height="1" alt="" style="display:none;" />',
                "domain_context": project_domain,
            },
        )
