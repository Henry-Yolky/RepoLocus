"""HTTP provider adapters with explicit timeouts and no automatic retries."""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

from devpilot.security.network import is_loopback_url
from devpilot.security.redaction import redact_text

from .base import (
    ModelProvider,
    ProviderConfigurationError,
    ProviderRequestError,
    ProviderResponseError,
)


class _HTTPProvider(ModelProvider):
    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        timeout: float,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(model, str) or not model.strip():
            raise ProviderConfigurationError("model name must not be empty")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ProviderConfigurationError("provider timeout must be greater than zero")
        self.model = model.strip()
        self.base_url = _normalise_base_url(base_url)
        self.timeout = float(timeout)
        self._transport = transport

    def _post_json(
        self,
        endpoint: str,
        *,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        try:
            with httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                transport=self._transport,
                trust_env=not is_loopback_url(self.base_url),
            ) as client:
                response = client.post(endpoint, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderRequestError(
                f"{self.name} request timed out after {self.timeout:g} seconds; it was not retried"
            ) from exc
        except httpx.RequestError as exc:
            raise ProviderRequestError(
                f"could not reach {self.name} provider; check its URL and network access"
            ) from exc

        if response.status_code >= 400:
            if response.status_code in {401, 403}:
                detail = "authentication was rejected"
            elif response.status_code == 429:
                detail = "rate limit or quota was exceeded"
            else:
                detail = f"HTTP {response.status_code}"
            raise ProviderRequestError(
                f"{self.name} request failed: {detail}; the request was not retried"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ProviderResponseError(f"{self.name} returned invalid JSON") from exc
        if not isinstance(data, Mapping):
            raise ProviderResponseError(f"{self.name} returned a non-object JSON response")
        return data


class OllamaProvider(_HTTPProvider):
    """Adapter for Ollama's local chat endpoint."""

    name = "ollama"
    is_local = True

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://127.0.0.1:11434",
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        super().__init__(model=model, base_url=base_url, timeout=timeout, transport=transport)
        self.is_local = is_loopback_url(self.base_url)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        _validate_prompts(system_prompt, user_prompt)
        data = self._post_json(
            _append_endpoint(self.base_url, "/api/chat", accepted_suffix="/api/chat"),
            headers={"Content-Type": "application/json"},
            payload={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
            },
        )
        message = data.get("message")
        if not isinstance(message, Mapping):
            raise ProviderResponseError("ollama response is missing message")
        return _required_content(message.get("content"), "ollama")


class OpenAICompatibleProvider(_HTTPProvider):
    """Adapter for OpenAI's and compatible chat-completions endpoints."""

    name = "openai"
    is_local = False

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 30.0,
        max_output_tokens: int = 2048,
        environ: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        super().__init__(model=model, base_url=base_url, timeout=timeout, transport=transport)
        env = os.environ if environ is None else environ
        api_key = env.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise ProviderConfigurationError(
                "OPENAI_API_KEY is required in the environment for an OpenAI-compatible model"
            )
        if (
            isinstance(max_output_tokens, bool)
            or not isinstance(max_output_tokens, int)
            or max_output_tokens <= 0
        ):
            raise ProviderConfigurationError("max_output_tokens must be greater than zero")
        self._api_key = api_key
        self.max_output_tokens = int(max_output_tokens)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        _validate_prompts(system_prompt, user_prompt)
        data = self._post_json(
            _append_endpoint(
                self.base_url,
                "/chat/completions",
                accepted_suffix="/chat/completions",
            ),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            payload={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": redact_text(system_prompt)},
                    {"role": "user", "content": redact_text(user_prompt)},
                ],
                "max_tokens": self.max_output_tokens,
                "temperature": 0,
            },
        )
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderResponseError("openai response is missing choices")
        first = choices[0]
        if not isinstance(first, Mapping) or not isinstance(first.get("message"), Mapping):
            raise ProviderResponseError("openai response is missing choices[0].message")
        return _required_content(first["message"].get("content"), "openai")


class AnthropicProvider(_HTTPProvider):
    """Adapter for Anthropic's Messages API."""

    name = "anthropic"
    is_local = False

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "https://api.anthropic.com",
        timeout: float = 30.0,
        max_output_tokens: int = 2048,
        environ: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        super().__init__(model=model, base_url=base_url, timeout=timeout, transport=transport)
        env = os.environ if environ is None else environ
        api_key = env.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            raise ProviderConfigurationError(
                "ANTHROPIC_API_KEY is required in the environment for an Anthropic model"
            )
        if (
            isinstance(max_output_tokens, bool)
            or not isinstance(max_output_tokens, int)
            or max_output_tokens <= 0
        ):
            raise ProviderConfigurationError("max_output_tokens must be greater than zero")
        self._api_key = api_key
        self.max_output_tokens = int(max_output_tokens)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        _validate_prompts(system_prompt, user_prompt)
        data = self._post_json(
            _append_endpoint(self.base_url, "/v1/messages", accepted_suffix="/v1/messages"),
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            payload={
                "model": self.model,
                "system": redact_text(system_prompt),
                "messages": [{"role": "user", "content": redact_text(user_prompt)}],
                "max_tokens": self.max_output_tokens,
                "temperature": 0,
            },
        )
        blocks = data.get("content")
        if not isinstance(blocks, list) or not blocks:
            raise ProviderResponseError("anthropic response is missing content blocks")
        text_parts = [
            block.get("text")
            for block in blocks
            if isinstance(block, Mapping)
            and block.get("type") == "text"
            and isinstance(block.get("text"), str)
        ]
        response = "".join(text_parts).strip()
        if not response:
            raise ProviderResponseError("anthropic response has no text content")
        return response


def _normalise_base_url(value: str) -> str:
    if not isinstance(value, str):
        raise ProviderConfigurationError("provider base URL must be a string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ProviderConfigurationError("provider base URL must not contain control characters")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProviderConfigurationError("provider base URL must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ProviderConfigurationError("provider base URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ProviderConfigurationError("provider base URL must not contain a query or fragment")
    return value.rstrip("/")


def _append_endpoint(base_url: str, endpoint: str, *, accepted_suffix: str) -> str:
    if base_url.endswith(accepted_suffix):
        return base_url
    return f"{base_url}{endpoint}"


def _validate_prompts(system_prompt: str, user_prompt: str) -> None:
    if not isinstance(system_prompt, str) or not isinstance(user_prompt, str):
        raise TypeError("system_prompt and user_prompt must be strings")


def _required_content(value: object, provider: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProviderResponseError(f"{provider} response has no text content")
    return value.strip()
