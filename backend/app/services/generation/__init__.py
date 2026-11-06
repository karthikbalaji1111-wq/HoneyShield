"""Honey token generation framework."""
from __future__ import annotations

from app.services.generation.api_key import ApiKeyGenerator
from app.services.generation.base import BaseGenerator
from app.services.generation.form_field import FormFieldGenerator
from app.services.generation.hidden_url import HiddenUrlGenerator
from app.services.generation.link import LinkGenerator
from app.services.generation.registry import GENERATOR_REGISTRY
from app.services.generation.tracking_pixel import TrackingPixelGenerator

__all__ = [
    "BaseGenerator",
    "GENERATOR_REGISTRY",
    "ApiKeyGenerator",
    "FormFieldGenerator",
    "HiddenUrlGenerator",
    "LinkGenerator",
    "TrackingPixelGenerator",
]
