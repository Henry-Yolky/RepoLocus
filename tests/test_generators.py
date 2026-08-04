import re
from pathlib import Path
from urllib.parse import unquote

from repolocus.generators import MermaidGenerator, ProjectMapGenerator, validate_mermaid
from repolocus.models import Chunk, Dependency, ScannedFile, ScanResult, ScanStats, Symbol


def _result() -> ScanResult:
    readme = ScannedFile(
        path="README.md",
        language="Markdown",
        size_bytes=80,
        sha256="a" * 64,
        line_count=4,
        text="# Example\n\nExample accepts jobs and runs them locally.\n",
        chunks=(
            Chunk(
                "README.md",
                1,
                3,
                "# Example\n\nExample accepts jobs and runs them locally.",
                "Markdown",
            ),
        ),
    )
    main = ScannedFile(
        path="src/app/main.py",
        language="Python",
        size_bytes=120,
        sha256="b" * 64,
        line_count=8,
        text=(
            "from app.worker import run\n\ndef main():\n    run()\n\n"
            "if __name__ == '__main__':\n    main()\n"
        ),
        symbols=(Symbol("main", "function", "src/app/main.py", 3, 4, "def main()"),),
        dependencies=(Dependency("src/app/main.py", "app.worker", "import", 1),),
        chunks=(
            Chunk("src/app/main.py", 1, 7, "from app.worker import run\n...", "Python", "main"),
        ),
        is_entry_point=True,
    )
    worker = ScannedFile(
        path="src/app/worker.py",
        language="Python",
        size_bytes=40,
        sha256="c" * 64,
        line_count=2,
        text="def run():\n    return 1\n",
        symbols=(Symbol("run", "function", "src/app/worker.py", 1, 2, "def run()"),),
        chunks=(Chunk("src/app/worker.py", 1, 2, "def run():\n    return 1", "Python", "run"),),
    )
    test = ScannedFile(
        path="tests/test_worker.py",
        language="Python",
        size_bytes=30,
        sha256="d" * 64,
        line_count=2,
        text="def test_run():\n    assert True\n",
        symbols=(Symbol("test_run", "function", "tests/test_worker.py", 1, 2, "def test_run()"),),
    )
    stats = ScanStats(
        discovered_files=4,
        indexed_files=4,
        indexed_bytes=270,
        languages={"Markdown": 1, "Python": 3},
    )
    return ScanResult(Path("/tmp/example"), [readme, main, worker, test], stats)


def test_project_map_is_stable_and_source_backed() -> None:
    generator = ProjectMapGenerator()
    first = generator.generate(_result())
    second = generator.generate(_result())

    assert first == second
    assert "## Main entry points" in first
    assert "[src/app/main.py:3](src/app/main.py#L3)" in first
    assert "**Confirmed:**" in first
    assert "**Inferred:**" in first
    assert "**Needs review:**" in first
    assert "Generated metadata" in first


def test_mermaid_source_is_valid_and_reproducible() -> None:
    generator = MermaidGenerator()
    first = generator.generate_source(_result())
    second = generator.generate_source(_result())

    assert first == second
    assert validate_mermaid(first) == (True, "ok")


def test_mermaid_document_keeps_source_evidence() -> None:
    document = MermaidGenerator().generate(_result())

    assert "```mermaid" in document
    assert "## Source evidence" in document
    assert "[src/app/main.py:1](src/app/main.py#L1)" in document


def test_nested_generated_documents_use_destination_relative_source_links(tmp_path: Path) -> None:
    result = _result()
    result.root = tmp_path
    for file in result.files:
        source = tmp_path / file.path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(file.text or "fixture\n", encoding="utf-8")
    destination = tmp_path / "docs/generated/output.md"
    destination.parent.mkdir(parents=True)

    project_map = ProjectMapGenerator().generate(result, destination=destination)
    diagram = MermaidGenerator().generate(result, destination=destination)

    assert "[src/app/main.py:3](../../src/app/main.py#L3)" in project_map
    assert "Source link base: generated-document-relative" in project_map
    assert "[src/app/main.py:1](../../src/app/main.py#L1)" in diagram
    assert "Source links are relative to this generated document." in diagram
    for document, line in ((project_map, 3), (diagram, 1)):
        match = re.search(rf"\[src/app/main\.py:{line}\]\(([^)#]+)#L{line}\)", document)
        assert match is not None
        assert (destination.parent / unquote(match.group(1))).resolve(strict=True).is_file()


def test_every_mermaid_edge_has_import_evidence() -> None:
    caller = ScannedFile(
        path="src/api/routes.py",
        language="Python",
        size_bytes=34,
        sha256="1" * 64,
        line_count=2,
        text="from worker.jobs import run\nrun()\n",
        dependencies=(Dependency("src/api/routes.py", "worker.jobs", "import", 1),),
    )
    target = ScannedFile(
        path="src/worker/jobs.py",
        language="Python",
        size_bytes=22,
        sha256="2" * 64,
        line_count=2,
        text="def run():\n    pass\n",
    )
    result = ScanResult(Path("/tmp/edges"), [caller, target], ScanStats(indexed_files=2))

    document = MermaidGenerator().generate(result)
    source = MermaidGenerator().generate_source(result)

    assert " --> " in source
    assert "### Edge evidence" in document
    assert "`api -&gt; worker`" in document
    assert "`worker.jobs`" in document
    assert "[src/api/routes.py:1](src/api/routes.py#L1)" in document


def test_mermaid_validator_rejects_model_like_free_text() -> None:
    valid, reason = validate_mermaid("flowchart LR\n    A[hello]\n    click A evil\n")

    assert not valid
    assert "unsupported" in reason


def test_empty_repository_has_valid_fallback_diagram() -> None:
    empty = ScanResult(Path("/tmp/empty"), [], ScanStats())
    source = MermaidGenerator().generate_source(empty)
    valid, _ = validate_mermaid(source)

    assert not valid
    document = MermaidGenerator().generate(empty)
    assert 'n_0000000000["empty repository"]' in document


def test_hostile_filename_cannot_inject_markdown_link() -> None:
    path = "x](javascript:alert)\x1b]8;;https://attacker.invalid\x1b\\.py"
    source = ScannedFile(
        path=path,
        language="python",
        size_bytes=10,
        sha256="e" * 64,
        line_count=1,
        text="value = 1\n",
    )
    result = ScanResult(Path("/tmp/hostile"), [source], ScanStats(indexed_files=1))

    project_map = ProjectMapGenerator().generate(result)
    diagram = MermaidGenerator().generate(result)

    assert "[x](javascript:" not in project_map
    assert "javascript%3Aalert" in project_map
    assert "[x](javascript:" not in diagram
    assert "\x1b" not in project_map
    assert "\x1b" not in diagram
    assert "\\u001b" in project_map
