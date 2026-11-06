"""Decoy HTML link generator strategy."""
from __future__ import annotations

import secrets
from typing import Any

from app.schemas.generation import GeneratedTokenData
from app.services.generation.base import BaseGenerator


class LinkGenerator(BaseGenerator):
    """Generates realistic decoy hyperlinks to be embedded in HTML comments or hidden elements."""

    def generate(self, project_domain: str, params: dict[str, Any]) -> GeneratedTokenData:
        link_types = [
            ("employee-portal", "Employee Portal"),
            ("staging-env", "Staging Environment"),
            ("internal-docs", "Internal Documentation"),
            ("vpn-gateway", "Corporate VPN Gateway"),
            ("legacy-access", "Legacy Admin Access"),
        ]
        prefix, desc = secrets.choice(link_types)
        random_suffix = secrets.token_hex(8)
        token_value = f"link-{prefix}-{random_suffix}"
        path = f"/t/{token_value}"
        url = f"https://{project_domain}{path}" if project_domain else path

        return GeneratedTokenData(
            token_value=token_value,
            label=f"Decoy Link: {desc}",
            metadata={
                "path": path,
                "url": url,
                "html_tag": f'<a href="{path}" style="display:none;" aria-hidden="true" rel="nofollow">{desc}</a>',
                "domain_context": project_domain,
            },
        )
