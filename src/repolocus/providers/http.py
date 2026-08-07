"""HTTP provider adapters with explicit timeouts and no automatic retries."""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

import httpx

from repolocus.security.network import is_loopback_url
from repolocus.security.redaction import contains_likely_secret, redact_secrets_with_count

from .base import (
    ModelProvider,
    ProviderConfigurationError,
    ProviderRequestError,
    ProviderResponseError,
)
from .transport import ProviderTransport, direct_transport

_MAX_REQUEST_BYTES = 8 * 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 100_000


@dataclass(frozen=True, slots=True)
class ProviderRequestPlan:
    """Credential-free, immutable HTTP body prepared before cloud approval."""

    provider: str
    model: str
    endpoint: str
    body: bytes
    redaction_count: int = 0

    def __post_init__(self) -> None:
        if (
            isinstance(self.redaction_count, bool)
            or not isinstance(self.redaction_count, int)
            or self.redaction_count < 0
        ):
            raise ValueError("redaction_count must be a non-negative integer")


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
    redacted_system, system_redactions = redact_secrets_with_count(system_prompt)
    redacted_user, user_redactions = redact_secrets_with_count(user_prompt)
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
    return ProviderRequestPlan(
        family,
        clean_model,
        endpoint,
        body,
        system_redactions + user_redactions,
    )


def _walk_json(value: object) -> list[str]:
    strings: list[str] = []
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON structure exceeds the configured complexity limit")
        if isinstance(current, str):
            strings.append(current)
        elif isinstance(current, Mapping):
            stack.extend((key, depth + 1) for key in current)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return strings


def _validate_outbound_body(body: bytes) -> None:
    """Reject a malformed or secret-bearing body immediately before transport."""

    if not isinstance(body, bytes) or len(body) > _MAX_REQUEST_BYTES:
        raise ProviderConfigurationError("prepared provider request body is invalid or too large")
    try:
        raw_text = body.decode("utf-8")
        data = json.loads(raw_text)
        strings = _walk_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProviderConfigurationError("prepared provider request body is not safe JSON") from exc
    if not isinstance(data, Mapping):
        raise ProviderConfigurationError("prepared provider request body must be a JSON object")
    if contains_likely_secret(raw_text) or any(contains_likely_secret(value) for value in strings):
        raise ProviderConfigurationError(
            "prepared provider request was blocked because credential-like content remained"
        )


def _validate_response_headers(response: httpx.Response) -> None:
    media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if media_type != "application/json" and not media_type.endswith("+json"):
        raise ProviderResponseError("provider returned a non-JSON content type")
    content_length = response.headers.get("content-length")
    if content_length is None:
        return
    try:
        declared = int(content_length, 10)
    except ValueError as exc:
        raise ProviderResponseError("provider returned an invalid Content-Length") from exc
    if declared < 0:
        raise ProviderResponseError("provider returned an invalid Content-Length")
    if declared > _MAX_RESPONSE_BYTES:
        raise ProviderResponseError(
            f"provider response exceeds the {_MAX_RESPONSE_BYTES}-byte limit"
        )


def _validate_json_shape(data: Mapping[str, Any], *, provider: str) -> None:
    try:
        _walk_json(data)
    except ValueError as exc:
        raise ProviderResponseError(f"{provider} returned overly complex JSON") from exc


class _HTTPProvider(ModelProvider):
    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        timeout: float,
        transport: httpx.BaseTransport | None = None,
        transport_route: ProviderTransport | None = None,
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
        self.transport_route = transport_route or direct_transport()
        if is_loopback_url(self.base_url) and self.transport_route.mode != "direct":
            raise ProviderConfigurationError("loopback providers must use a direct transport")

    def _post_json(
        self,
        endpoint: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
    ) -> Mapping[str, Any]:
        _validate_outbound_body(body)
        deadline = monotonic() + self.timeout
        try:
            client_options: dict[str, object] = {
                "timeout": httpx.Timeout(self.timeout),
                "transport": self._transport,
                "trust_env": False,
            }
            # An injected transport is already the complete test/embedding route;
            # combining it with HTTPX's proxy mounts would silently replace it.
            if self.transport_route.proxy_url is not None and self._transport is None:
                client_options["proxy"] = self.transport_route.proxy_url
            with (
                httpx.Client(**client_options) as client,
                client.stream("POST", endpoint, headers=headers, content=body) as response,
            ):
                if monotonic() > deadline:
                    raise ProviderRequestError(
                        f"{self.name} request exceeded the {self.timeout:g}-second "
                        "elapsed-time deadline; it was not retried"
                    )
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
                _validate_response_headers(response)
                blocks: list[bytes] = []
                received = 0
                for block in response.iter_bytes():
                    if monotonic() > deadline:
                        raise ProviderRequestError(
                            f"{self.name} request exceeded the {self.timeout:g}-second "
                            "elapsed-time deadline; it was not retried"
                        )
                    received += len(block)
                    if received > _MAX_RESPONSE_BYTES:
                        raise ProviderResponseError(
                            f"{self.name} response exceeded the {_MAX_RESPONSE_BYTES}-byte limit"
                        )
                    blocks.append(block)
                if monotonic() > deadline:
                    raise ProviderRequestError(
                        f"{self.name} request exceeded the {self.timeout:g}-second "
                        "elapsed-time deadline; it was not retried"
                    )
                response_body = b"".join(blocks)
        except httpx.TimeoutException as exc:
            raise ProviderRequestError(
                f"{self.name} request timed out after {self.timeout:g} seconds; it was not retried"
            ) from exc
        except httpx.RequestError as exc:
            raise ProviderRequestError(
                f"could not reach {self.name} provider; check its URL and network access"
            ) from exc
        try:
            data = json.loads(response_body)
        except (ValueError, RecursionError) as exc:
            raise ProviderResponseError(f"{self.name} returned invalid JSON") from exc
        if not isinstance(data, Mapping):
            raise ProviderResponseError(f"{self.name} returned a non-object JSON response")
        _validate_json_shape(data, provider=self.name)
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
        transport_route: ProviderTransport | None = None,
    ) -> None:
        super().__init__(
            model=model,
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            transport_route=transport_route,
        )
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
        transport_route: ProviderTransport | None = None,
    ) -> None:
        super().__init__(
            model=model,
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            transport_route=transport_route,
        )
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
        transport_route: ProviderTransport | None = None,
    ) -> None:
        super().__init__(
            model=model,
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            transport_route=transport_route,
        )
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
