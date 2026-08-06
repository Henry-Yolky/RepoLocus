from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

import pytest

from repolocus.security import AtomicWriteError, atomic_write_within_root

_GENERATED = b"<!-- Generator: RepoLocus 0.1.5; deterministic source map. -->\nnew\n"


def test_atomic_write_creates_nested_output_and_replaces_only_generated(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    relative = PurePosixPath("docs/generated/PROJECT_MAP.md")

    atomic_write_within_root(
        root,
        relative,
        _GENERATED,
        replace_generated_only=True,
    )
    output = root / "docs" / "generated" / "PROJECT_MAP.md"
    assert output.read_bytes() == _GENERATED

    replacement = _GENERATED.replace(b"new", b"replacement")
    atomic_write_within_root(
        root,
        relative,
        replacement,
        replace_generated_only=True,
    )
    assert output.read_bytes() == replacement
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))


@pytest.mark.parametrize(
    "existing",
    [
        b"user-authored notes\n",
        b"User text mentioning Generator: RepoLocus is not a marker.\n",
    ],
)
def test_atomic_write_refuses_user_or_forged_generated_files(
    tmp_path: Path, existing: bytes
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    output.write_bytes(existing)

    with pytest.raises(AtomicWriteError, match="not recognized as generated"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=True,
        )

    assert output.read_bytes() == existing


def test_atomic_write_force_still_rejects_symlink_targets(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"outside\n")
    target = root / "PROJECT_MAP.md"
    try:
        target.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - Windows policy dependent
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(AtomicWriteError, match=r"non-regular|safe regular"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=False,
        )

    assert outside.read_bytes() == b"outside\n"


def test_fallback_generated_marker_read_is_bounded(tmp_path: Path) -> None:
    from repolocus.security import atomic_write as writer

    output = tmp_path / "PROJECT_MAP.md"
    output.write_bytes(_GENERATED + (b"x" * 1_000_000))
    expected = output.lstat()

    payload = writer._read_fallback_marker(output, expected)

    assert payload == (_GENERATED + (b"x" * writer._MARKER_READ_LIMIT))[: writer._MARKER_READ_LIMIT]
    assert len(payload) == writer._MARKER_READ_LIMIT


def test_parent_symlink_swap_fails_without_writing_outside(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    if os.name == "nt":
        pytest.skip("Windows reparse-point race is covered by the Windows-specific path")
    root = tmp_path / "repository"
    parent = root / "docs"
    parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    moved = root / "original-docs"
    swapped = False

    def swap(stage: str, _root: Path, _relative: PurePosixPath) -> None:
        nonlocal swapped
        if stage == "temporary-synced" and not swapped:
            parent.rename(moved)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(writer, "_checkpoint", swap)

    with pytest.raises(AtomicWriteError, match=r"directory tree|output parent"):
        atomic_write_within_root(
            root,
            PurePosixPath("docs/PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=True,
        )

    assert swapped
    assert not (outside / "PROJECT_MAP.md").exists()
    assert not list(moved.glob(".*.tmp"))


def test_target_file_to_symlink_race_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    output.write_bytes(_GENERATED)
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"outside\n")
    swapped = False

    def swap(stage: str, _root: Path, _relative: PurePosixPath) -> None:
        nonlocal swapped
        if stage == "target-validated" and not swapped:
            output.unlink()
            try:
                output.symlink_to(outside)
            except OSError as exc:  # pragma: no cover - Windows policy dependent
                pytest.skip(f"symlinks unavailable: {exc}")
            swapped = True

    monkeypatch.setattr(writer, "_checkpoint", swap)

    with pytest.raises(AtomicWriteError, match=r"non-regular|safe regular"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=True,
        )

    assert swapped
    assert outside.read_bytes() == b"outside\n"
    assert not list(root.glob(".*.tmp"))


def test_temporary_file_swap_at_commit_cannot_publish_a_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"outside\n")
    swapped = False

    def swap(stage: str, _root: Path, _relative: PurePosixPath) -> None:
        nonlocal swapped
        if stage == "commit-ready" and not swapped:
            temporary = next(root.glob(".PROJECT_MAP.md.*.tmp"))
            temporary.unlink()
            try:
                temporary.symlink_to(outside)
            except OSError as exc:  # pragma: no cover - Windows policy dependent
                pytest.skip(f"symlinks unavailable: {exc}")
            swapped = True

    monkeypatch.setattr(writer, "_checkpoint", swap)

    with pytest.raises(
        AtomicWriteError,
        match=r"appeared before it could be created|temporary changed|atomic replacement",
    ):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=True,
        )

    assert swapped
    assert (root / "PROJECT_MAP.md").is_symlink()
    assert outside.read_bytes() == b"outside\n"
    assert list(root.glob(".*.tmp"))


def test_generated_only_commit_preserves_a_last_moment_target_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    output.write_bytes(_GENERATED)
    raced_content = b"user-authored during final commit race\n"
    swapped = False

    def swap(stage: str, _root: Path, _relative: PurePosixPath) -> None:
        nonlocal swapped
        if stage == "commit-ready" and not swapped:
            output.unlink()
            output.write_bytes(raced_content)
            swapped = True

    monkeypatch.setattr(writer, "_checkpoint", swap)

    with pytest.raises(AtomicWriteError, match="changed during atomic replacement"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED.replace(b"new", b"replacement"),
            replace_generated_only=True,
        )

    assert swapped
    assert output.read_bytes() == _GENERATED.replace(b"new", b"replacement")
    recovery = list(root.glob(".*.tmp"))
    assert len(recovery) == 1
    assert recovery[0].read_bytes() == raced_content


@pytest.mark.skipif(os.name != "posix", reason="requires atomic POSIX name exchange")
def test_exchange_verification_error_preserves_both_recoverable_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    output.write_bytes(_GENERATED)
    original_state_at = writer._raw_state_at
    failed = False

    def fail_once(parent_fd: int, name: str) -> os.stat_result | None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("simulated post-exchange inspection failure")
        return original_state_at(parent_fd, name)

    monkeypatch.setattr(writer, "_raw_state_at", fail_once)

    replacement = _GENERATED.replace(b"new", b"replacement")
    with pytest.raises(AtomicWriteError, match="could not be verified; preserved"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            replacement,
            replace_generated_only=True,
        )

    assert failed
    contents = {path.read_bytes() for path in root.iterdir() if path.is_file()}
    assert contents == {_GENERATED, replacement}


@pytest.mark.skipif(os.name != "posix", reason="requires atomic POSIX name exchange")
def test_post_exchange_target_race_preserves_the_competing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    output.write_bytes(_GENERATED)
    replacement = _GENERATED.replace(b"new", b"replacement")
    raced_content = b"user-authored after exchange\n"
    original_state_at = writer._raw_state_at
    raced = False

    def race_after_exchange(parent_fd: int, name: str) -> os.stat_result | None:
        nonlocal raced
        if not raced:
            raced = True
            output.unlink()
            output.write_bytes(raced_content)
        return original_state_at(parent_fd, name)

    monkeypatch.setattr(writer, "_raw_state_at", race_after_exchange)

    with pytest.raises(AtomicWriteError, match="preserved recoverable names"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            replacement,
            replace_generated_only=True,
        )

    assert raced
    assert output.read_bytes() == raced_content
    assert _GENERATED in {path.read_bytes() for path in root.glob(".*.tmp") if path.is_file()}


def test_post_link_target_race_preserves_the_competing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    raced_content = b"user-authored after link\n"
    original_state_at = writer._raw_state_at
    raced = False

    def race_after_link(parent_fd: int, name: str) -> os.stat_result | None:
        nonlocal raced
        if not raced:
            raced = True
            output.unlink()
            output.write_bytes(raced_content)
        return original_state_at(parent_fd, name)

    monkeypatch.setattr(writer, "_raw_state_at", race_after_link)

    with pytest.raises(AtomicWriteError, match="preserved target"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=True,
        )

    assert raced
    assert output.read_bytes() == raced_content
    assert not list(root.glob(".*.tmp"))


def test_windows_new_commit_mismatch_preserves_the_competing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    temporary = tmp_path / ".PROJECT_MAP.md.tmp"
    destination = tmp_path / "PROJECT_MAP.md"
    temporary.write_bytes(_GENERATED)
    expected = temporary.lstat()
    raced_content = b"windows competitor after move\n"

    def move_then_race(source: Path, target: Path) -> None:
        source.rename(target)
        target.unlink()
        target.write_bytes(raced_content)

    monkeypatch.setattr(writer, "_move_file_windows", move_then_race)

    with pytest.raises(AtomicWriteError, match="preserved"):
        writer._windows_commit_new(temporary, destination, expected)

    assert destination.read_bytes() == raced_content


def test_windows_exchange_mismatch_preserves_destination_and_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    destination = tmp_path / "PROJECT_MAP.md"
    temporary = tmp_path / ".PROJECT_MAP.md.tmp"
    destination.write_bytes(_GENERATED)
    temporary.write_bytes(_GENERATED.replace(b"new", b"replacement"))
    expected_target = destination.lstat()
    expected_temporary = temporary.lstat()
    raced_content = b"windows competitor after replace\n"

    def replace_then_race(target: Path, replacement: Path, backup: Path) -> None:
        target.rename(backup)
        replacement.rename(target)
        target.unlink()
        target.write_bytes(raced_content)

    monkeypatch.setattr(writer, "_replace_file_windows", replace_then_race)

    with pytest.raises(AtomicWriteError, match="preserved recoverable names"):
        writer._windows_commit_exchange(
            destination,
            temporary,
            expected_temporary,
            expected_target,
        )

    assert destination.read_bytes() == raced_content
    backups = list(tmp_path.glob(".PROJECT_MAP.md.*.rollback"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == _GENERATED


@pytest.mark.skipif(os.name != "posix", reason="requires descriptor-relative POSIX path")
def test_unsupported_atomic_exchange_fails_without_replacing_the_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    output.write_bytes(_GENERATED)

    def unsupported(_parent_fd: int, _first: str, _second: str) -> None:
        raise AtomicWriteError("atomic exchange unsupported")

    monkeypatch.setattr(writer, "_rename_exchange_at", unsupported)

    with pytest.raises(AtomicWriteError, match="atomic exchange unsupported"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED.replace(b"new", b"replacement"),
            replace_generated_only=True,
        )

    assert output.read_bytes() == _GENERATED
    assert not list(root.glob(".*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO semantics")
def test_target_file_to_fifo_race_fails_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repolocus.security import atomic_write as writer

    root = tmp_path / "repository"
    root.mkdir()
    output = root / "PROJECT_MAP.md"
    output.write_bytes(_GENERATED)

    def swap(stage: str, _root: Path, _relative: PurePosixPath) -> None:
        if stage == "target-validated":
            output.unlink()
            os.mkfifo(output)

    monkeypatch.setattr(writer, "_checkpoint", swap)

    with pytest.raises(AtomicWriteError, match="non-regular"):
        atomic_write_within_root(
            root,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=True,
        )

    assert stat_is_fifo(output)
    assert not list(root.glob(".*.tmp"))


def stat_is_fifo(path: Path) -> bool:
    import stat

    return stat.S_ISFIFO(path.lstat().st_mode)


@pytest.mark.parametrize(
    "relative",
    [
        PurePosixPath("../outside.md"),
        PurePosixPath("/absolute.md"),
        PurePosixPath("."),
        PurePosixPath("bad\\name.md"),
        PurePosixPath("bad\0name.md"),
    ],
)
def test_atomic_write_rejects_non_relative_paths(tmp_path: Path, relative: PurePosixPath) -> None:
    with pytest.raises(AtomicWriteError, match="repository-relative"):
        atomic_write_within_root(
            tmp_path,
            relative,
            _GENERATED,
            replace_generated_only=True,
        )


def test_atomic_write_rejects_invalid_public_argument_types(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="root must be a Path"):
        atomic_write_within_root(  # type: ignore[arg-type]
            str(tmp_path),
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=True,
        )
    with pytest.raises(TypeError, match="relative_path must be a PurePosixPath"):
        atomic_write_within_root(  # type: ignore[arg-type]
            tmp_path,
            "PROJECT_MAP.md",
            _GENERATED,
            replace_generated_only=True,
        )
    with pytest.raises(TypeError, match="content must be bytes"):
        atomic_write_within_root(  # type: ignore[arg-type]
            tmp_path,
            PurePosixPath("PROJECT_MAP.md"),
            "content",
            replace_generated_only=True,
        )
    with pytest.raises(TypeError, match="replace_generated_only must be true or false"):
        atomic_write_within_root(  # type: ignore[arg-type]
            tmp_path,
            PurePosixPath("PROJECT_MAP.md"),
            _GENERATED,
            replace_generated_only=1,
        )


def test_atomic_write_rejects_a_zero_length_low_level_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from repolocus.security import atomic_write as writer

    monkeypatch.setattr(writer.os, "write", lambda _descriptor, _content: 0)

    with pytest.raises(OSError, match="short write"):
        writer._write_all(1, b"content")
