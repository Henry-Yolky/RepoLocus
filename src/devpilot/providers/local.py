"""Deterministic no-network provider for the default local mode."""

from __future__ import annotations

from collections.abc import Callable

from .base import ModelProvider


class ExtractiveProvider(ModelProvider):
    """A deterministic hook for provider-independent/extractive responses.

    The orchestration layer can supply a responder that formats retrieved
    evidence without a language model.  The default response is intentionally
    explicit rather than pretending to have generated a semantic answer.
    """

    name = "local"
    model = "extractive"
    is_local = True

    def __init__(self, responder: Callable[[str, str], str] | None = None) -> None:
        self._responder = responder or _default_response

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if not isinstance(system_prompt, str) or not isinstance(user_prompt, str):
            raise TypeError("system_prompt and user_prompt must be strings")
        response = self._responder(system_prompt, user_prompt)
        if not isinstance(response, str):
            raise TypeError("extractive responder must return a string")
        return response


def _default_response(_system_prompt: str, _user_prompt: str) -> str:
    return (
        "Local extractive mode does not generate free-form text. "
        "DevPilot will return its retrieved, source-cited evidence directly."
    )
