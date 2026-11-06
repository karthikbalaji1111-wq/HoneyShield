"""Abstract base generator for honey token strategies."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.schemas.generation import GeneratedTokenData


class BaseGenerator(ABC):
    """Abstract base class for all token generation strategies.

    Generators must remain completely pure. They should not access
    repositories, database sessions, or framework specifics.
    """

    @abstractmethod
    def generate(self, project_domain: str, params: dict[str, Any]) -> GeneratedTokenData:
        """Generate a realistic deception asset.

        Args:
            project_domain: Domain of the owning project to contextualize the token.
            params: Strategy-specific parameters guiding generation.

        Returns:
            A pure data transfer object containing the token and metadata.
        """
        pass
