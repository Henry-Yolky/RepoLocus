from __future__ import annotations

import multiprocessing
import os
from pathlib import Path

from repolocus.security import PrivacyStore, canonical_endpoint


def _grant_worker(
    state_path: str,
    root: str,
    provider: str,
    endpoint: str,
    start: multiprocessing.synchronize.Event,
) -> None:
    start.wait(10)
    PrivacyStore(state_path).grant(root, provider, endpoint)


def _revoke_worker(
    state_path: str,
    root: str,
    start: multiprocessing.synchronize.Event,
) -> None:
    start.wait(10)
    PrivacyStore(state_path).revoke(root)


def _crash_with_lock(
    state_path: str,
    ready: multiprocessing.synchronize.Event,
) -> None:
    store = PrivacyStore(state_path)
    with store._locked_state():
        ready.set()
        os._exit(0)


def _join(process: multiprocessing.Process) -> None:
    process.join(15)
    if process.is_alive():
        process.terminate()
        process.join(5)
        raise AssertionError("privacy lock worker deadlocked")
    assert process.exitcode == 0


def test_cross_process_grants_preserve_both_providers(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    root = tmp_path / "repository"
    root.mkdir()
    state_path = tmp_path / "state" / "privacy.json"
    start = context.Event()
    workers = [
        context.Process(
            target=_grant_worker,
            args=(
                str(state_path),
                str(root),
                "openai",
                "https://api.openai.com/v1/chat/completions",
                start,
            ),
        ),
        context.Process(
            target=_grant_worker,
            args=(
                str(state_path),
                str(root),
                "anthropic",
                "https://api.anthropic.com/v1/messages",
                start,
            ),
        ),
    ]
    for worker in workers:
        worker.start()
    start.set()
    for worker in workers:
        _join(worker)

    assert PrivacyStore(state_path).grant_details(root) == {
        "anthropic": (canonical_endpoint("https://api.anthropic.com/v1/messages"),),
        "openai": (canonical_endpoint("https://api.openai.com/v1/chat/completions"),),
    }


def test_cross_process_grant_and_revoke_are_serializable(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    root = tmp_path / "repository"
    root.mkdir()
    state_path = tmp_path / "state" / "privacy.json"
    store = PrivacyStore(state_path)
    store.grant(root, "openai", "https://api.openai.com/v1/chat/completions")
    start = context.Event()
    grant = context.Process(
        target=_grant_worker,
        args=(
            str(state_path),
            str(root),
            "anthropic",
            "https://api.anthropic.com/v1/messages",
            start,
        ),
    )
    revoke = context.Process(
        target=_revoke_worker,
        args=(str(state_path), str(root), start),
    )
    grant.start()
    revoke.start()
    start.set()
    _join(grant)
    _join(revoke)

    details = store.grant_details(root)
    assert details in (
        {},
        {"anthropic": (canonical_endpoint("https://api.anthropic.com/v1/messages"),)},
    )


def test_process_exit_releases_privacy_lock(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    state_path = tmp_path / "state" / "privacy.json"
    ready = context.Event()
    worker = context.Process(target=_crash_with_lock, args=(str(state_path), ready))
    worker.start()
    assert ready.wait(10)
    _join(worker)

    root = tmp_path / "repository"
    root.mkdir()
    store = PrivacyStore(state_path)
    store.grant(root, "openai", "https://api.openai.com/v1/chat/completions")
    assert store.status(root) == {"openai": True}
