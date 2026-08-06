from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from repolocus.config import ConfigError, Settings
from repolocus.core import PrivacyRequiredError, RepoLocusService
from repolocus.providers import (
    OpenAICompatibleProvider,
    ProviderTransport,
    build_provider_transport,
    create_provider,
    proxy_transport,
)
from repolocus.security import PrivacyStore


def test_default_transport_ignores_malicious_proxy_environment() -> None:
    route = build_provider_transport(
        Settings(),
        "https://api.openai.com/v1/chat/completions",
        environ={
            "HTTPS_PROXY": "https://attacker.invalid:8443",
            "ALL_PROXY": "https://other-attacker.invalid:9443",
        },
    )

    assert Settings().trust_env is False
    assert route.mode == "direct"
    assert route.policy == "disabled"
    assert route.proxy_url is None


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("invalid", "direct", "0" * 64), "policy"),
        (("disabled", "invalid", "0" * 64), "mode"),
        (("disabled", "direct", "short"), "SHA-256"),
        (("disabled", "direct", "g" * 64), "SHA-256"),
        (
            (
                "disabled",
                "direct",
                "0" * 64,
                "https://proxy.example.com:443",
                "https://proxy.example.com:443",
            ),
            "direct transport",
        ),
        (("explicit", "proxy", "0" * 64), "proxy transport"),
    ],
)
def test_transport_model_rejects_inconsistent_routes(
    arguments: tuple[object, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ProviderTransport(*arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("proxy_url", "message"),
    [
        ("", "non-empty"),
        ("https://proxy.example.com\n", "control"),
        ("https://proxy.example.com:99999", "invalid port"),
        ("socks5://proxy.example.com", "absolute http"),
        ("https://proxy.example.com/path", "path"),
        ("https://./", "hostname"),
    ],
)
def test_proxy_url_validation_fails_closed(proxy_url: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        proxy_transport("explicit", proxy_url)


def test_proxy_url_canonicalizes_ipv6_and_username_without_leaking_to_preview() -> None:
    ipv6 = proxy_transport("explicit", "https://[2001:0db8::1]")
    username = proxy_transport("explicit", "http://alice@Proxy.Example./")

    assert ipv6.proxy_url == "https://[2001:db8::1]:443"
    assert ipv6.preview()["proxy"] == "https://[2001:db8::1]:443"
    assert username.proxy_url == "http://alice@proxy.example:80"
    assert username.preview()["proxy"] == "http://proxy.example:80"


@pytest.mark.parametrize(
    ("endpoint", "no_proxy", "expected_mode"),
    [
        ("https://api.openai.com/v1", "*", "direct"),
        ("https://api.openai.com/v1", "https://api.openai.com:443", "direct"),
        ("https://api.openai.com/v1", "api.openai.com:444", "proxy"),
        ("https://api.openai.com/v1", ", api.openai.com:notaport", "proxy"),
        ("https://192.0.2.5/v1", "192.0.2.0/24", "direct"),
        ("https://[2001:db8::1]/v1", "2001:db8::/32", "direct"),
    ],
)
def test_environment_no_proxy_matching_is_explicit_and_bounded(
    endpoint: str,
    no_proxy: str,
    expected_mode: str,
) -> None:
    route = build_provider_transport(
        Settings(proxy_mode="environment"),
        endpoint,
        environ={
            "NO_PROXY": no_proxy,
            "ALL_PROXY": "https://proxy.example.com:8443",
        },
    )

    assert route.mode == expected_mode


def test_environment_policy_without_proxy_is_direct_and_invalid_policy_fails() -> None:
    direct = build_provider_transport(
        Settings(proxy_mode="environment"),
        "https://api.openai.com/v1",
        environ={},
    )
    assert direct.mode == "direct"
    assert direct.policy == "environment"

    invalid = SimpleNamespace(proxy_mode="invalid", proxy_url="")
    with pytest.raises(ValueError, match="proxy_mode"):
        build_provider_transport(  # type: ignore[arg-type]
            invalid,
            "https://api.openai.com/v1",
            environ={},
        )


def test_provider_client_disables_ambient_proxy_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus.providers import http as provider_http

    original_client = httpx.Client
    client_options: list[dict[str, object]] = []

    def client(**options: object) -> httpx.Client:
        client_options.append(dict(options))
        options["transport"] = httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={"choices": [{"message": {"content": "safe"}}]},
            )
        )
        return original_client(**options)  # type: ignore[arg-type]

    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid:8443")
    monkeypatch.setattr(provider_http.httpx, "Client", client)
    provider = OpenAICompatibleProvider(
        "test-model",
        environ={"OPENAI_API_KEY": "test-key"},
    )

    assert provider.generate("system", "question") == "safe"
    assert client_options == [
        {
            "timeout": httpx.Timeout(30.0),
            "transport": None,
            "trust_env": False,
        }
    ]


def test_provider_client_uses_only_the_frozen_environment_proxy_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus.providers import http as provider_http

    endpoint = "https://api.openai.com/v1/chat/completions"
    route = build_provider_transport(
        Settings(proxy_mode="environment"),
        endpoint,
        environ={"HTTPS_PROXY": "https://proxy.example.com:8443"},
    )
    original_client = httpx.Client
    client_options: list[dict[str, object]] = []

    def client(**options: object) -> httpx.Client:
        client_options.append(dict(options))
        options.pop("proxy", None)
        options["transport"] = httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={"choices": [{"message": {"content": "safe"}}]},
            )
        )
        return original_client(**options)  # type: ignore[arg-type]

    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid:9443")
    monkeypatch.setattr(provider_http.httpx, "Client", client)
    provider = OpenAICompatibleProvider(
        "test-model",
        environ={"OPENAI_API_KEY": "test-key"},
        transport_route=route,
    )

    assert provider.generate("system", "question") == "safe"
    assert client_options[0]["trust_env"] is False
    assert client_options[0]["proxy"] == "https://proxy.example.com:8443"


def test_environment_proxy_route_is_explicitly_enabled_and_credential_free_in_preview() -> None:
    secret = "proxy-password-do-not-display"
    route = build_provider_transport(
        Settings(proxy_mode="environment"),
        "https://api.openai.com/v1/chat/completions",
        environ={"https_proxy": f"https://alice:{secret}@proxy.example.com:8443"},
    )

    assert route.mode == "proxy"
    assert route.policy == "environment"
    assert route.preview() == {
        "mode": "proxy",
        "policy": "environment",
        "proxy": "https://proxy.example.com:8443",
    }
    assert secret not in repr(route)
    assert secret not in str(route.preview())
    assert secret in (route.proxy_url or "")


def test_proxy_mode_and_endpoint_change_transport_identity_without_binding_credentials() -> None:
    endpoint = "https://api.openai.com/v1/chat/completions"
    explicit = build_provider_transport(
        Settings(
            proxy_mode="explicit",
            proxy_url="https://alice:first@proxy.example.com:8443",
        ),
        endpoint,
    )
    changed_credential = build_provider_transport(
        Settings(
            proxy_mode="explicit",
            proxy_url="https://alice:second@proxy.example.com:8443",
        ),
        endpoint,
    )
    environment = build_provider_transport(
        Settings(proxy_mode="environment"),
        endpoint,
        environ={"HTTPS_PROXY": "https://alice:first@proxy.example.com:8443"},
    )
    changed_endpoint = build_provider_transport(
        Settings(
            proxy_mode="explicit",
            proxy_url="https://alice:first@other-proxy.example.com:8443",
        ),
        endpoint,
    )

    assert explicit.identity == changed_credential.identity
    assert len({explicit.identity, environment.identity, changed_endpoint.identity}) == 3
    assert explicit.preview()["proxy"] == changed_credential.preview()["proxy"]


def test_no_proxy_and_loopback_ollama_force_direct_routes() -> None:
    environment = Settings(proxy_mode="environment")
    bypassed = build_provider_transport(
        environment,
        "https://api.openai.com/v1/chat/completions",
        environ={
            "HTTPS_PROXY": "https://proxy.example.com:8443",
            "NO_PROXY": ".openai.com",
        },
    )
    loopback = build_provider_transport(
        Settings(
            proxy_mode="explicit",
            proxy_url="https://proxy.example.com:8443",
        ),
        "http://127.0.0.1:11434/api/chat",
    )

    assert bypassed.mode == "direct"
    assert bypassed.policy == "environment"
    assert loopback.mode == "direct"
    assert loopback.policy == "explicit"


def test_injected_transport_remains_usable_with_an_explicit_proxy_policy() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "safe"}}]},
        )

    provider = create_provider(
        "openai/test-model",
        Settings(
            proxy_mode="explicit",
            proxy_url="https://user:secret@proxy.example.com:8443",
        ),
        environ={"OPENAI_API_KEY": "test-key"},
        transport=httpx.MockTransport(handler),
    )

    assert provider.generate("system", "question") == "safe"
    assert len(captured) == 1
    assert provider.transport_route.mode == "proxy"  # type: ignore[attr-defined]


def test_proxy_route_is_bound_to_preview_and_remembered_consent(
    sample_repo: Path,
    isolated_user_dirs: Path,
) -> None:
    state_path = isolated_user_dirs / "privacy.json"
    first_settings = Settings(
        model="openai/test-model",
        proxy_mode="explicit",
        proxy_url="https://alice:first@proxy.example.com:8443",
    )
    first_service = RepoLocusService(
        first_settings,
        privacy=PrivacyStore(state_path),
    )
    prepared, _operation = first_service.prepare_ask(
        "Where is load_config defined?",
        sample_repo,
    )
    assert prepared.transport is not None
    assert prepared.preview.to_dict()["transport"] == {
        "mode": "proxy",
        "policy": "explicit",
        "proxy": "https://proxy.example.com:8443",
    }
    first_service.privacy.grant(
        sample_repo,
        prepared.consent_scope,
        prepared.endpoint,
        transport_identity=prepared.transport.identity,
        transport=prepared.transport.preview(),
    )

    changed_credentials = RepoLocusService(
        Settings(
            model="openai/test-model",
            proxy_mode="explicit",
            proxy_url="https://alice:second@proxy.example.com:8443",
        ),
        privacy=PrivacyStore(state_path),
    )
    changed_credentials_route = changed_credentials.consent_transport("openai/test-model")
    assert changed_credentials_route is not None
    assert changed_credentials.privacy.is_allowed(
        sample_repo,
        prepared.consent_scope,
        prepared.endpoint,
        transport_identity=changed_credentials_route.identity,
    )

    changed = RepoLocusService(
        Settings(
            model="openai/test-model",
            proxy_mode="explicit",
            proxy_url="https://alice:first@other-proxy.example.com:8443",
        ),
        privacy=PrivacyStore(state_path),
    )
    with pytest.raises(PrivacyRequiredError):
        changed.ask("Where is load_config defined?", sample_repo)

    raw_state = state_path.read_text(encoding="utf-8")
    assert "first" not in raw_state
    assert "alice" not in raw_state
    assert "proxy.example.com:8443" in raw_state


def test_user_proxy_config_is_allowed_but_repository_proxy_config_is_rejected(
    tmp_path: Path,
) -> None:
    user_config = tmp_path / "user.toml"
    user_config.write_text(
        'proxy_mode = "explicit"\nproxy_url = "https://proxy.example.com:8443"\n',
        encoding="utf-8",
    )
    repository = tmp_path / "repository"
    repository.mkdir()
    repository_config = repository / ".repolocus.toml"
    repository_config.write_text('proxy_mode = "environment"\n', encoding="utf-8")

    configured = Settings.load(user_config_path=user_config, environ={})
    assert configured.proxy_mode == "explicit"
    assert configured.proxy_url == "https://proxy.example.com:8443"

    with pytest.raises(ConfigError, match="repository config cannot set 'proxy_mode'"):
        Settings.load(
            repository,
            user_config_path=user_config,
            environ={},
        )
