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
from .http import (
    AnthropicProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    ProviderRequestPlan,
    build_provider_request_plan,
)
from .local import ExtractiveProvider
from .transport import (
    ProviderTransport,
    build_provider_transport,
    direct_transport,
    proxy_transport,
)

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
    "ProviderRequestPlan",
    "ProviderResponseError",
    "ProviderTransport",
    "build_provider_request_plan",
    "build_provider_transport",
    "create_provider",
    "direct_transport",
    "is_local_provider",
    "provider_family",
    "proxy_transport",
]
