"""Model-provider interfaces and bundled adapters."""

from repolocus.security.privacy import is_local_provider, provider_family

from .base import (
    ModelProvider,
    ProviderConfigurationError,
    ProviderError,
    ProviderRequestError,
    ProviderResponseError,
)
from .factory import ProviderFactory, create_provider
from .http import AnthropicProvider, OllamaProvider, OpenAICompatibleProvider
from .local import ExtractiveProvider

__all__ = [
    "AnthropicProvider",
    "ExtractiveProvider",
    "ModelProvider",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "ProviderConfigurationError",
    "ProviderError",
    "ProviderFactory",
    "ProviderRequestError",
    "ProviderResponseError",
    "create_provider",
    "is_local_provider",
    "provider_family",
]
