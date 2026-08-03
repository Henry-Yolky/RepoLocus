"""Provider-neutral model contract and safe error types."""

from __future__ import annotations

from abc import ABC, abstractmethod


class ProviderError(RuntimeError):
    """Base class for provider failures safe to show to end users."""


class ProviderConfigurationError(ProviderError):
    """Raised before a request when model configuration is incomplete."""


class ProviderRequestError(ProviderError):
    """Raised for a transport or HTTP failure.

    Provider calls intentionally do not retry.  A retry could duplicate billed
    work if the remote service completed a request before a connection failed.
    """


class ProviderResponseError(ProviderError):
    """Raised when a provider response does not match its documented shape."""


class ModelProvider(ABC):
    """Minimal interface implemented by local and remote language models."""

    name: str
    model: str
    is_local: bool

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate one complete response for a system/user prompt pair."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}(model={self.model!r}, is_local={self.is_local!r})"
