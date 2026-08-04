"""HTTP provider adapters with explicit timeouts and no automatic retries."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from repolocus.security.network import is_loopback_url
from repolocus.security.redaction import redact_text

from .base import (
    ModelProvider,
    ProviderConfigurationError,
    ProviderRequestError,
    ProviderResponseError,
)


@dataclass(frozen=True, slots=True)
class ProviderRequestPlan:
    """Credential-free, immutable HTTP body prepared before cloud approval."""

    provider: str
    model: str
    endpoint: str
    body: bytes


def build_provider_request_plan(
    provider: str,
    model: str,
    *,
    base_url: str,
    system_prompt: str,
    user_prompt: str,
    max_output_tokens: int = 2048,
) -> ProviderRequestPlan:
    """Build the exact redacted JSON body later sent by an HTTP provider."""

    _validate_prompts(system_prompt, user_prompt)
    family = provider.strip().casefold()
    clean_model = model.strip()
    if not clean_model:
        raise ProviderConfigurationError("model name must not be empty")
    normalised_base = _normalise_base_url(base_url)
    redacted_system = redact_text(system_prompt)
    redacted_user = redact_text(user_prompt)
    if family == "ollama":
        endpoint = _append_endpoint(normalised_base, "/api/chat", accepted_suffix="/api/chat")
        payload: Mapping[str, Any] = {
            "model": clean_model,
            "messages": [
                {"role": "system", "content": redacted_system},
                {"role": "user", "content": redacted_user},
            ],
            "stream": False,
        }
    elif family == "openai":
        _validate_max_output_tokens(max_output_tokens)
        endpoint = _append_endpoint(
            normalised_base,
            "/chat/completions",
            accepted_suffix="/chat/completions",
        )
        payload = {
            "model": clean_model,
            "messages": [
                {"role": "system", "content": redacted_system},
                {"role": "user", "content": redacted_user},
            ],
            "max_tokens": int(max_output_tokens),
            "temperature": 0,
        }
    elif family == "anthropic":
        _validate_max_output_tokens(max_output_tokens)
        endpoint = _append_endpoint(normalised_base, "/v1/messages", accepted_suffix="/v1/messages")
        payload = {
            "model": clean_model,
            "system": redacted_system,
            "messages": [{"role": "user", "content": redacted_user}],
            "max_tokens": int(max_output_tokens),
            "temperature": 0,
        }
    else:
        raise ProviderConfigurationError(f"unsupported HTTP provider {provider!r}")
    body = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return ProviderRequestPlan(family, clean_model, endpoint, body)


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
        body: bytes,
    ) -> Mapping[str, Any]:
        try:
            with httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                transport=self._transport,
                trust_env=not is_loopback_url(self.base_url),
            ) as client:
                response = client.post(endpoint, headers=headers, content=body)
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
        plan = build_provider_request_plan(
            "ollama",
            self.model,
            base_url=self.base_url,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        return self.generate_prepared(plan)

    def generate_prepared(self, plan: ProviderRequestPlan) -> str:
        self._validate_plan(plan, "ollama", "/api/chat")
        data = self._post_json(
            plan.endpoint,
            headers={"Content-Type": "application/json"},
            body=plan.body,
        )
        message = data.get("message")
        if not isinstance(message, Mapping):
            raise ProviderResponseError("ollama response is missing message")
        return _required_content(message.get("content"), "ollama")

    def _validate_plan(self, plan: ProviderRequestPlan, family: str, suffix: str) -> None:
        expected = _append_endpoint(self.base_url, suffix, accepted_suffix=suffix)
        if plan.provider != family or plan.model != self.model or plan.endpoint != expected:
            raise ProviderConfigurationError(
                "prepared provider request does not match this provider"
            )


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
        plan = build_provider_request_plan(
            "openai",
            self.model,
            base_url=self.base_url,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_output_tokens=self.max_output_tokens,
        )
        return self.generate_prepared(plan)

    def generate_prepared(self, plan: ProviderRequestPlan) -> str:
        expected = _append_endpoint(
            self.base_url,
            "/chat/completions",
            accepted_suffix="/chat/completions",
        )
        if plan.provider != "openai" or plan.model != self.model or plan.endpoint != expected:
            raise ProviderConfigurationError(
                "prepared provider request does not match this provider"
            )
        data = self._post_json(
            plan.endpoint,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            body=plan.body,
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
        plan = build_provider_request_plan(
            "anthropic",
            self.model,
            base_url=self.base_url,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_output_tokens=self.max_output_tokens,
        )
        return self.generate_prepared(plan)

    def generate_prepared(self, plan: ProviderRequestPlan) -> str:
        expected = _append_endpoint(self.base_url, "/v1/messages", accepted_suffix="/v1/messages")
        if plan.provider != "anthropic" or plan.model != self.model or plan.endpoint != expected:
            raise ProviderConfigurationError(
                "prepared provider request does not match this provider"
            )
        data = self._post_json(
            plan.endpoint,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            body=plan.body,
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
    normalised = value.rstrip("/")
    if parsed.scheme == "http" and not is_loopback_url(normalised):
        raise ProviderConfigurationError(
            "provider base URL must use HTTPS unless it targets a loopback address"
        )
    return normalised


def _append_endpoint(base_url: str, endpoint: str, *, accepted_suffix: str) -> str:
    if base_url.endswith(accepted_suffix):
        return base_url
    return f"{base_url}{endpoint}"


def _validate_prompts(system_prompt: str, user_prompt: str) -> None:
    if not isinstance(system_prompt, str) or not isinstance(user_prompt, str):
        raise TypeError("system_prompt and user_prompt must be strings")


def _validate_max_output_tokens(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProviderConfigurationError("max_output_tokens must be greater than zero")


def _required_content(value: object, provider: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProviderResponseError(f"{provider} response has no text content")
    return value.strip()
