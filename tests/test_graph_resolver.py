from __future__ import annotations

import pytest

from repolocus.graph import (
    build_alias_index,
    go_module_roots,
    path_aliases,
    resolve_dependencies,
)
from repolocus.graph import resolver as resolver_module
from repolocus.models import Dependency


def _resolve(source: str, target: str, *paths: str):
    dependency = Dependency(source, target, "import", 1)
    return resolve_dependencies((source, *paths), (dependency,))[0]


def test_relative_import_cannot_escape_repository_root() -> None:
    javascript = _resolve("src/a.js", "../../worker", "worker.js")
    python = _resolve("src/pkg/a.py", "...worker", "worker.py")

    assert javascript.confidence == "unresolved"
    assert javascript.target_path is None
    assert python.confidence == "unresolved"
    assert python.target_path is None


def test_single_dot_import_can_resolve_in_repository_root_package() -> None:
    resolved = _resolve("module.py", ".worker", "worker.py")

    assert resolved.confidence == "exact"
    assert resolved.target_path == "worker.py"


def test_rust_crate_scope_uses_nearest_workspace_source_root() -> None:
    resolved = _resolve(
        "crates/app/src/main.rs",
        "crate::worker::run",
        "crates/app/src/worker.rs",
    )

    assert resolved.confidence == "probable"
    assert resolved.target_path == "crates/app/src/worker.rs"
    assert resolved.target_symbol == "run"


def test_rust_self_scope_uses_file_module_directory() -> None:
    resolved = _resolve("src/foo.rs", "self::bar::run", "src/foo/bar.rs")

    assert resolved.confidence == "probable"
    assert resolved.target_path == "src/foo/bar.rs"
    assert resolved.target_symbol == "run"


def test_rust_super_scope_stays_inside_crate_root() -> None:
    valid = _resolve("src/foo.rs", "super::worker::run", "src/worker.rs")
    invalid = _resolve(
        "src/foo.rs",
        "super::super::worker",
        "worker.rs",
        "src/super.rs",
    )

    assert valid.target_path == "src/worker.rs"
    assert valid.target_symbol == "run"
    assert invalid.confidence == "unresolved"
    assert invalid.target_path is None


def test_invalid_relative_target_cannot_be_reinterpreted_as_module_plus_symbol() -> None:
    resolved = _resolve(
        "src/a.js",
        "./foo/../../../worker/Thing",
        "src/foo.js",
        "worker.js",
    )

    assert resolved.confidence == "unresolved"
    assert resolved.target_path is None


def test_missing_crate_module_cannot_fall_back_to_bare_scope_keyword() -> None:
    resolved = _resolve("src/main.rs", "crate::missing::Thing", "crate.rs")

    assert resolved.confidence == "unresolved"
    assert resolved.target_path is None


def test_missing_javascript_child_does_not_fall_back_to_parent_module() -> None:
    resolved = _resolve("src/app.ts", "./utils/missing", "src/utils.ts")

    assert resolved.confidence == "unresolved"
    assert resolved.target_path is None
    assert resolved.target_symbol is None


def test_java_standard_source_roots_expose_package_qualified_aliases() -> None:
    main = _resolve(
        "src/main/java/com/acme/App.java",
        "com.acme.Worker",
        "src/main/java/com/acme/Worker.java",
    )
    test = _resolve(
        "src/test/java/com/acme/AppTest.java",
        "com.acme.WorkerTest",
        "src/test/java/com/acme/WorkerTest.java",
    )

    assert main.confidence == "exact"
    assert main.target_path == "src/main/java/com/acme/Worker.java"
    assert test.confidence == "exact"
    assert test.target_path == "src/test/java/com/acme/WorkerTest.java"


def test_go_import_uses_explicit_nearest_module_declaration() -> None:
    files = (
        ("go.mod", "module fixture.local/service\n\ngo 1.22\n"),
        ("nested/go.mod", "module fixture.local/nested\n"),
    )
    modules = go_module_roots(files)
    paths = (
        "go.mod",
        "cmd/server/main.go",
        "internal/health/handler.go",
        "nested/go.mod",
        "nested/internal/health/handler.go",
    )
    root_dependency = Dependency(
        "cmd/server/main.go",
        "fixture.local/service/internal/health",
        "import",
        3,
    )
    nested_dependency = Dependency(
        "nested/cmd/server/main.go",
        "fixture.local/nested/internal/health",
        "import",
        3,
    )

    resolved = resolve_dependencies(
        (*paths, "nested/cmd/server/main.go"),
        (root_dependency, nested_dependency),
        go_modules=modules,
    )

    assert modules == {"": "fixture.local/service", "nested": "fixture.local/nested"}
    assert resolved[0].target_path == "internal/health/handler.go"
    assert resolved[0].confidence == "exact"
    assert resolved[1].target_path == "nested/internal/health/handler.go"
    assert resolved[1].confidence == "exact"


def test_cargo_standalone_targets_use_their_own_crate_root() -> None:
    binary = _resolve(
        "src/bin/tool.rs",
        "crate::worker::run",
        "src/worker.rs",
        "src/bin/worker.rs",
    )
    example = _resolve(
        "examples/tool.rs",
        "crate::worker::run",
        "src/worker.rs",
        "examples/worker.rs",
    )

    assert binary.target_path == "src/bin/worker.rs"
    assert binary.target_symbol == "run"
    assert example.target_path == "examples/worker.rs"
    assert example.target_symbol == "run"


def test_cargo_directory_binary_uses_its_directory_as_crate_root() -> None:
    resolved = _resolve(
        "src/bin/tool/main.rs",
        "crate::worker::run",
        "src/worker.rs",
        "src/bin/tool/worker.rs",
    )

    assert resolved.target_path == "src/bin/tool/worker.rs"
    assert resolved.target_symbol == "run"


def test_cargo_directory_target_modules_inherit_the_crate_root() -> None:
    binary_module = _resolve(
        "src/bin/tool/worker.rs",
        "crate::config",
        "src/config.rs",
        "src/bin/tool/config.rs",
    )
    example_module = _resolve(
        "examples/tool/worker.rs",
        "crate::config",
        "examples/config.rs",
        "examples/tool/config.rs",
    )

    assert binary_module.target_path == "src/bin/tool/config.rs"
    assert example_module.target_path == "examples/tool/config.rs"


@pytest.mark.parametrize(
    "target_path",
    [
        "src/worker.mjs",
        "src/worker.cjs",
        "src/worker.mts",
        "src/worker.cts",
        "src/worker.d.ts",
        "src/worker.d.mts",
        "src/worker.d.cts",
    ],
)
def test_extensionless_import_resolves_every_supported_javascript_suffix(
    target_path: str,
) -> None:
    resolved = _resolve("src/app.ts", "./worker", target_path)

    assert resolved.confidence == "exact"
    assert resolved.target_path == target_path


def test_python_relative_import_cannot_cross_the_package_source_root() -> None:
    resolved = _resolve(
        "src/pkg/sub/a.py",
        "...worker",
        "src/worker.py",
        "src/pkg/__init__.py",
        "src/pkg/sub/__init__.py",
    )

    assert resolved.confidence == "unresolved"
    assert resolved.target_path is None


def test_rust_module_declaration_prefers_its_lexical_module_directory() -> None:
    dependency = Dependency("src/nested/mod.rs", "foo", "module", 1)
    resolved = resolve_dependencies(
        ("src/nested/mod.rs", "src/nested/foo.rs", "src/other/foo.rs"),
        (dependency,),
    )[0]

    assert resolved.confidence == "exact"
    assert resolved.target_path == "src/nested/foo.rs"


def test_casefold_only_resolution_is_probable_not_exact() -> None:
    probable = _resolve("src/app.js", "./Worker", "src/worker.js")
    exact = _resolve("src/app.js", "./Worker", "src/Worker.js", "src/worker.js")

    assert probable.confidence == "probable"
    assert probable.target_path == "src/worker.js"
    assert exact.confidence == "exact"
    assert exact.target_path == "src/Worker.js"


def test_path_aliases_have_a_constant_per_path_bound() -> None:
    path = "/".join([*(f"segment_{index}" for index in range(63)), "worker.py"])

    aliases = path_aliases(path)

    assert len(aliases) <= 12
    assert "worker" in aliases


def test_alias_index_fails_closed_at_its_global_record_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(resolver_module, "_MAX_ALIAS_RECORDS", 2)

    with pytest.raises(ValueError, match="alias record budget"):
        build_alias_index(("src/one.py", "src/two.py"))
