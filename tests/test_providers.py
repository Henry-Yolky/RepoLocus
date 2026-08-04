from __future__ import annotations

import json

import httpx
import pytest

from repolocus.config import Settings
from repolocus.providers import (
    AnthropicProvider,
    ExtractiveProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    ProviderConfigurationError,
    ProviderRequestError,
    ProviderResponseError,
    build_provider_request_plan,
    create_provider,
)


def test_factory_defaults_and_model_string_families() -> None:
    local = create_provider("local/extractive", Settings())
    ollama = create_provider("ollama/qwen3-coder", Settings())

    assert isinstance(local, ExtractiveProvider)
    assert local.is_local is True
    assert local.generate("system", "question") == local.generate("system", "question")
    assert isinstance(ollama, OllamaProvider)
    assert ollama.model == "qwen3-coder"
    assert ollama.is_local is True


def test_factory_rejects_unknown_or_incomplete_model_strings() -> None:
    with pytest.raises(ProviderConfigurationError, match="unsupported provider"):
        create_provider("mystery/model", Settings())
    with pytest.raises(ProviderConfigurationError, match="model name must not be empty"):
        create_provider("anthropic", Settings())


@pytest.mark.parametrize(
    ("model", "message"),
    [
        ("openai/gpt-test", "OPENAI_API_KEY"),
        ("anthropic/claude-test", "ANTHROPIC_API_KEY"),
    ],
)
def test_cloud_factory_requires_environment_credentials(model: str, message: str) -> None:
    with pytest.raises(ProviderConfigurationError, match=message):
        create_provider(model, Settings(), environ={})


def test_openai_compatible_contract_and_cloud_redaction() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Source-backed answer."}}]},
        )

    provider = create_provider(
        "openai/gpt-test",
        Settings(request_timeout=9, max_output_tokens=321),
        environ={"OPENAI_API_KEY": "environment-only-key"},
        transport=httpx.MockTransport(handler),
    )

    result = provider.generate("System", 'api_key = "secret-value"')

    assert result == "Source-backed answer."
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.is_local is False
    assert len(captured) == 1
    request = captured[0]
    plan = build_provider_request_plan(
        "openai",
        "gpt-test",
        base_url="https://api.openai.com/v1",
        system_prompt="System",
        user_prompt='api_key = "secret-value"',
        max_output_tokens=321,
    )
    payload = json.loads(request.content)
    assert request.content == plan.body
    assert request.url == "https://api.openai.com/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer environment-only-key"
    assert payload["model"] == "gpt-test"
    assert payload["max_tokens"] == 321
    assert payload["temperature"] == 0
    assert payload["messages"][1]["content"] == 'api_key = "[REDACTED]"'
    assert request.extensions["timeout"]["read"] == 9
    assert "environment-only-key" not in repr(provider)


def test_anthropic_contract() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "Part one. "},
                    {"type": "tool_use", "id": "ignored"},
                    {"type": "text", "text": "Part two."},
                ]
            },
        )

    provider = create_provider(
        "anthropic/claude-test",
        Settings(anthropic_base_url="https://anthropic.example"),
        environ={"ANTHROPIC_API_KEY": "anthropic-environment-key"},
        transport=httpx.MockTransport(handler),
    )

    assert provider.generate("System", "Question") == "Part one. Part two."
    assert isinstance(provider, AnthropicProvider)
    request = captured[0]
    payload = json.loads(request.content)
    assert request.url == "https://anthropic.example/v1/messages"
    assert request.headers["x-api-key"] == "anthropic-environment-key"
    assert request.headers["anthropic-version"] == "2023-06-01"
    assert payload["system"] == "System"
    assert payload["messages"] == [{"role": "user", "content": "Question"}]


def test_ollama_contract_is_local_and_needs_no_secret() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"message": {"content": "Local answer."}})

    provider = create_provider(
        "ollama/qwen3-coder",
        Settings(ollama_base_url="http://localhost:11434"),
        environ={},
        transport=httpx.MockTransport(handler),
    )

    assert provider.generate("System", "Question") == "Local answer."
    request = captured[0]
    payload = json.loads(request.content)
    assert request.url == "http://localhost:11434/api/chat"
    assert "authorization" not in request.headers
    assert payload == {
        "model": "qwen3-coder",
        "messages": [
            {"role": "system", "content": "System"},
            {"role": "user", "content": "Question"},
        ],
        "stream": False,
    }


def test_remote_ollama_endpoint_is_not_classified_as_local() -> None:
    provider = create_provider(
        "ollama/model",
        Settings(ollama_base_url="https://ollama.example.invalid"),
        environ={},
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    )

    assert provider.is_local is False


@pytest.mark.parametrize("family", ["ollama", "openai", "anthropic"])
def test_remote_plain_http_provider_urls_are_rejected(family: str) -> None:
    with pytest.raises(
        ProviderConfigurationError,
        match="must use HTTPS unless it targets a loopback address",
    ):
        _provider_for_url(family, "http://provider.example.invalid")


@pytest.mark.parametrize("family", ["ollama", "openai", "anthropic"])
@pytest.mark.parametrize(
    "base_url",
    ["http://127.0.0.1:11434", "https://provider.example.invalid"],
    ids=["loopback-http", "https"],
)
def test_loopback_http_and_https_provider_urls_are_allowed(
    family: str,
    base_url: str,
) -> None:
    provider = _provider_for_url(family, base_url)

    assert provider.base_url == base_url


@pytest.mark.parametrize(
    "base_url",
    ["http://localhost:11434", "https://ollama.example.invalid"],
    ids=["loopback", "remote"],
)
def test_ollama_redacts_prompts_before_sending(base_url: str) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"message": {"content": "Safe answer."}})

    provider = OllamaProvider(
        "model",
        base_url=base_url,
        transport=httpx.MockTransport(handler),
    )

    assert (
        provider.generate('password = "system-secret"', 'api_key = "user-secret"') == "Safe answer."
    )
    payload = json.loads(captured[0].content)
    assert payload["messages"] == [
        {"role": "system", "content": 'password = "[REDACTED]"'},
        {"role": "user", "content": 'api_key = "[REDACTED]"'},
    ]
    assert "system-secret" not in captured[0].content.decode()
    assert "user-secret" not in captured[0].content.decode()


def test_http_failure_is_clear_and_never_retried() -> None:
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(429, json={"error": {"message": "sensitive remote detail"}})

    provider = OllamaProvider("model", transport=httpx.MockTransport(handler))

    with pytest.raises(ProviderRequestError, match="not retried") as caught:
        provider.generate("System", "Question")
    assert "sensitive remote detail" not in str(caught.value)
    assert requests == 1


def test_malformed_provider_response_has_clear_error() -> None:
    provider = OllamaProvider(
        "model",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    )

    with pytest.raises(ProviderResponseError, match="missing message"):
        provider.generate("System", "Question")


def _provider_for_url(
    family: str,
    base_url: str,
) -> OllamaProvider | OpenAICompatibleProvider | AnthropicProvider:
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, json={}))
    if family == "ollama":
        return OllamaProvider("model", base_url=base_url, transport=transport)
    if family == "openai":
        return OpenAICompatibleProvider(
            "model",
            base_url=base_url,
            environ={"OPENAI_API_KEY": "test-key"},
            transport=transport,
        )
    if family == "anthropic":
        return AnthropicProvider(
            "model",
            base_url=base_url,
            environ={"ANTHROPIC_API_KEY": "test-key"},
            transport=transport,
        )
    raise AssertionError(f"unexpected provider family: {family}")
