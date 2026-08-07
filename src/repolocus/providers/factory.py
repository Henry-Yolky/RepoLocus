"""Model-string parsing and provider construction."""

from __future__ import annotations

from collections.abc import Mapping

import httpx

from repolocus.config import Settings
from repolocus.security.privacy import provider_family

from .base import ModelProvider, ProviderConfigurationError
from .http import AnthropicProvider, OllamaProvider, OpenAICompatibleProvider
from .local import ExtractiveProvider
from .transport import ProviderTransport, build_provider_transport


class ProviderFactory:
    """Namespace for creating adapters from explicit provider/model strings."""

    @staticmethod
    def create(
        model: str,
        settings: Settings | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        transport_route: ProviderTransport | None = None,
    ) -> ModelProvider:
        return create_provider(
            model,
            settings,
            environ=environ,
            transport=transport,
            transport_route=transport_route,
        )


def create_provider(
    model: str,
    settings: Settings | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    transport_route: ProviderTransport | None = None,
) -> ModelProvider:
    """Create a provider from ``provider/model`` or ``provider:model``.

    Supported examples are ``local/extractive``, ``ollama/qwen3-coder``,
    ``openai/gpt-4.1-mini``, and ``anthropic/claude-sonnet-4``.
    """

    if not isinstance(model, str) or not model.strip():
        raise ProviderConfigurationError("model must be a non-empty provider/model string")
    configuration = settings or Settings.load(environ=environ)
    family, model_name = _split_model(model)
    if family == "local":
        if model_name not in {"", "extractive"}:
            raise ProviderConfigurationError(
                f"unsupported built-in local model {model_name!r}; use local/extractive"
            )
        return ExtractiveProvider()
    if not model_name:
        raise ProviderConfigurationError(f"{family} model name must not be empty")
    if family == "ollama":
        route = transport_route or build_provider_transport(
            configuration, configuration.ollama_base_url, environ=environ
        )
        return OllamaProvider(
            model_name,
            base_url=configuration.ollama_base_url,
            timeout=configuration.request_timeout,
            transport=transport,
            transport_route=route,
        )
    if family == "openai":
        route = transport_route or build_provider_transport(
            configuration, configuration.openai_base_url, environ=environ
        )
        return OpenAICompatibleProvider(
            model_name,
            base_url=configuration.openai_base_url,
            timeout=configuration.request_timeout,
            max_output_tokens=configuration.max_output_tokens,
            environ=environ,
            transport=transport,
            transport_route=route,
        )
    if family == "anthropic":
        route = transport_route or build_provider_transport(
            configuration, configuration.anthropic_base_url, environ=environ
        )
        return AnthropicProvider(
            model_name,
            base_url=configuration.anthropic_base_url,
            timeout=configuration.request_timeout,
            max_output_tokens=configuration.max_output_tokens,
            environ=environ,
            transport=transport,
            transport_route=route,
        )
    raise ProviderConfigurationError(
        f"unsupported provider {family!r}; expected local, ollama, openai, or anthropic"
    )


def _split_model(value: str) -> tuple[str, str]:
    stripped = value.strip()
    lowered = stripped.lower()
    if lowered in {"local", "extractive", "local/extractive", "local:extractive"}:
        return "local", "extractive"
    slash = stripped.find("/")
    colon = stripped.find(":")
    positions = [position for position in (slash, colon) if position >= 0]
    if not positions:
        # Preserve the unknown value in the provider slot for a useful error.
        return provider_family(stripped), ""
    position = min(positions)
    family = provider_family(stripped[:position])
    return family, stripped[position + 1 :].strip()
