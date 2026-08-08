"""Optional Tree-sitter symbol adapters with deterministic heuristic fallback."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Iterable, Iterator
from importlib import metadata
from pathlib import PurePosixPath
from typing import Any

from repolocus.models import Dependency, Symbol
from repolocus.parsers.base import (
    DEFAULT_MAX_CHUNKS_PER_FILE,
    DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    DEFAULT_MAX_SYMBOLS_PER_FILE,
    ParseResult,
)
from repolocus.parsers.chunking import Region, semantic_chunks
from repolocus.parsers.heuristic import HeuristicParser, _source_entry_point
from repolocus.parsers.source_layout import SourceLayout

_LANGUAGE_MODULES = {
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "rust": ("tree_sitter_rust", "language"),
}

_OPTIONAL_ADAPTER_ERRORS = (
    AttributeError,
    ImportError,
    OSError,
    RuntimeError,
    SystemError,
    TypeError,
    ValueError,
)

_SYMBOL_KINDS = {
    "class_declaration": "class",
    "class_specifier": "class",
    "enum_declaration": "enum",
    "enum_item": "enum",
    "enum_specifier": "enum",
    "function_declaration": "function",
    "function_definition": "function",
    "function_item": "function",
    "generator_function_declaration": "function",
    "impl_item": "impl",
    "interface_declaration": "interface",
    "method_definition": "method",
    "namespace_definition": "namespace",
    "struct_item": "struct",
    "struct_specifier": "struct",
    "trait_item": "trait",
    "type_alias_declaration": "type",
    "union_specifier": "union",
}

_FUNCTION_VALUE_NODES = frozenset({"arrow_function", "function_expression", "generator_function"})

_NAME_NODE_TYPES = frozenset(
    {
        "destructor_name",
        "field_identifier",
        "identifier",
        "namespace_identifier",
        "operator_name",
        "property_identifier",
        "type_identifier",
    }
)

_QUALIFIED_NAME_NODE_TYPES = frozenset(
    {
        "generic_type",
        "qualified_identifier",
        "scoped_identifier",
        "scoped_type_identifier",
    }
)


class _FactLimitError(ValueError):
    """A parser budget failure that must not trigger heuristic fallback."""


def _package_version(distribution: str) -> str:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return "unknown"


def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _literal_target(source: bytes, node: Any | None) -> str | None:
    if node is None:
        return None
    value = _node_text(source, node).strip()
    if len(value) < 2:
        return None
    delimiters = {'"': '"', "'": "'", "`": "`", "<": ">"}
    closing = delimiters.get(value[0])
    if closing is None or value[-1] != closing:
        return None
    target = value[1:-1]
    return target if target else None


def _join_rust_path(prefix: str, target: str) -> str:
    if target == "self" and prefix:
        return prefix
    if not prefix:
        return target
    if not target:
        return prefix
    return f"{prefix}::{target}"


def _rust_use_targets(source: bytes, node: Any | None, prefix: str = "") -> Iterator[str]:
    if node is None:
        return
    if node.type == "use_as_clause":
        yield from _rust_use_targets(source, node.child_by_field_name("path"), prefix)
        return
    if node.type == "scoped_use_list":
        path = node.child_by_field_name("path")
        use_list = node.child_by_field_name("list")
        path_text = "".join(_node_text(source, path).split()) if path is not None else ""
        scoped_prefix = _join_rust_path(prefix, path_text)
        root_scope = scoped_prefix.split("::", 1)[0]
        if not prefix and root_scope not in {"crate", "self", "super"}:
            if scoped_prefix:
                yield scoped_prefix
            return
        yield from _rust_use_targets(source, use_list, scoped_prefix)
        return
    if node.type == "use_list":
        for child in node.named_children:
            yield from _rust_use_targets(source, child, prefix)
        return
    target = "".join(_node_text(source, node).split())
    if target:
        yield _join_rust_path(prefix, target)


class TreeSitterParser:
    """Extract native syntax facts with a deterministic heuristic fallback."""

    priority = 20

    def __init__(self, parser_type: type[Any], language_objects: dict[str, Any]) -> None:
        self._parser_type = parser_type
        self._language_objects = dict(language_objects)
        self.languages = frozenset(language for language in language_objects if language != "tsx")
        self._fallback = HeuristicParser()
        versions = [f"tree-sitter-{_package_version('tree-sitter')}"]
        versions.extend(
            f"{variant}:{factory}-{_package_version(module.replace('_', '-'))}"
            for variant, (module, factory) in sorted(_LANGUAGE_MODULES.items())
            if variant in self._language_objects
        )
        cache_material = "\0".join([*versions, self._fallback.cache_key])
        cache_digest = hashlib.sha256(cache_material.encode("utf-8")).hexdigest()[:24]
        self.cache_key = f"tree-sitter-native:v4+{cache_digest}"

    @classmethod
    def discover(cls) -> TreeSitterParser | None:
        """Return adapters for installed language wheels, or no adapter."""

        try:
            tree_sitter = importlib.import_module("tree_sitter")
            parser_type = tree_sitter.Parser
        except _OPTIONAL_ADAPTER_ERRORS:
            return None
        language_objects: dict[str, Any] = {}
        for language, (module_name, factory_name) in _LANGUAGE_MODULES.items():
            try:
                module = importlib.import_module(module_name)
                capsule = getattr(module, factory_name)()
                language_objects[language] = tree_sitter.Language(capsule)
            except _OPTIONAL_ADAPTER_ERRORS:
                continue
        if not any(language != "tsx" for language in language_objects):
            return None
        try:
            return cls(parser_type, language_objects)
        except _OPTIONAL_ADAPTER_ERRORS:
            return None

    def _parser(self, language: str, *, path: str = "") -> Any:
        parser = self._parser_type()
        variant = (
            "tsx"
            if language == "typescript"
            and PurePosixPath(path).suffix.casefold() == ".tsx"
            and "tsx" in self._language_objects
            else language
        )
        language_object = self._language_objects[variant]
        try:
            parser.language = language_object
        except (AttributeError, TypeError):
            parser.set_language(language_object)
        return parser

    @staticmethod
    def _declarator_name(node: Any) -> Any | None:
        if node.type in _NAME_NODE_TYPES | _QUALIFIED_NAME_NODE_TYPES:
            return node
        for field in ("name", "declarator"):
            candidate = node.child_by_field_name(field)
            if candidate is not None:
                resolved = TreeSitterParser._declarator_name(candidate)
                if resolved is not None:
                    return resolved
        return None

    @staticmethod
    def _name_node(node: Any) -> Any | None:
        if node.type == "impl_item":
            return node.child_by_field_name("type")

        candidate = node.child_by_field_name("name")
        if candidate is not None:
            return candidate

        declarator = node.child_by_field_name("declarator")
        if declarator is not None:
            return TreeSitterParser._declarator_name(declarator)

        return next(
            (child for child in node.named_children if child.type in _NAME_NODE_TYPES),
            None,
        )

    @staticmethod
    def _symbol_kind(node: Any) -> str | None:
        if node.type != "variable_declarator":
            return _SYMBOL_KINDS.get(node.type)
        value = node.child_by_field_name("value")
        if value is None or value.type not in _FUNCTION_VALUE_NODES:
            return None
        return "function"

    @staticmethod
    def _symbols(
        path: str,
        source: bytes,
        root: Any,
        layout: SourceLayout,
        *,
        max_symbols: int = DEFAULT_MAX_SYMBOLS_PER_FILE,
    ) -> tuple[Symbol, ...]:
        output: set[Symbol] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            stack.extend(reversed(node.named_children))
            kind = TreeSitterParser._symbol_kind(node)
            if kind is None:
                continue
            name_node = TreeSitterParser._name_node(node)
            if name_node is None:
                continue
            name = source[name_node.start_byte : name_node.end_byte].decode(
                "utf-8", errors="replace"
            )
            if not name.strip():
                continue
            signature_bytes = source[node.start_byte : min(node.end_byte, node.start_byte + 1000)]
            signature = " ".join(
                signature_bytes.decode("utf-8", errors="replace").split("{", 1)[0].split()
            )[:500]
            start_line = layout.line_at_byte_offset(node.start_byte)
            final_byte = node.end_byte - 1 if node.end_byte > node.start_byte else node.start_byte
            symbol = Symbol(
                name=name.strip()[:500],
                kind=kind,
                path=path,
                start_line=start_line,
                end_line=max(start_line, layout.line_at_byte_offset(final_byte)),
                signature=signature,
            )
            if symbol in output:
                continue
            if len(output) >= max_symbols:
                raise _FactLimitError("parser exceeded the configured symbol limit")
            output.add(symbol)
        return tuple(
            sorted(
                output,
                key=lambda item: (item.start_line, item.end_line, item.kind, item.name),
            )
        )

    @staticmethod
    def _dependencies(
        path: str,
        source: bytes,
        root: Any,
        language: str,
        layout: SourceLayout,
        *,
        max_dependencies: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE,
    ) -> tuple[Dependency, ...]:
        output: set[Dependency] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            stack.extend(reversed(node.named_children))
            targets: Iterable[tuple[str, str]] = ()

            if language in {"javascript", "typescript"}:
                if node.type in {"import_statement", "export_statement"}:
                    target = _literal_target(source, node.child_by_field_name("source"))
                    if target is not None:
                        targets = ((target, "import"),)
                elif node.type == "call_expression":
                    function = node.child_by_field_name("function")
                    function_name = _node_text(source, function).strip() if function else ""
                    if function is not None and (
                        function.type == "import"
                        or (function.type == "identifier" and function_name == "require")
                    ):
                        arguments = node.child_by_field_name("arguments")
                        argument = (
                            arguments.named_children[0]
                            if arguments is not None and arguments.named_children
                            else None
                        )
                        target = _literal_target(source, argument)
                        if target is not None:
                            kind = "dynamic_import" if function.type == "import" else "require"
                            targets = ((target, kind),)
            elif language in {"c", "cpp"} and node.type == "preproc_include":
                target = _literal_target(source, node.child_by_field_name("path"))
                if target is not None:
                    targets = ((target, "include"),)
            elif language == "rust":
                if node.type == "use_declaration":
                    targets = (
                        (target, "import")
                        for target in _rust_use_targets(
                            source, node.child_by_field_name("argument")
                        )
                    )
                elif node.type == "mod_item":
                    name = node.child_by_field_name("name")
                    if name is not None and _node_text(source, node).rstrip().endswith(";"):
                        targets = ((_node_text(source, name).strip(), "module"),)
                elif node.type == "extern_crate_declaration":
                    name = node.child_by_field_name("name")
                    if name is not None:
                        targets = ((_node_text(source, name).strip(), "import"),)

            line = layout.line_at_byte_offset(node.start_byte)
            for target, kind in targets:
                if not target:
                    continue
                dependency = Dependency(path, target, kind, line)
                if dependency in output:
                    continue
                if len(output) >= max_dependencies:
                    raise _FactLimitError("parser exceeded the configured dependency limit")
                output.add(dependency)
        return tuple(sorted(output, key=lambda item: (item.line, item.target, item.kind)))

    def parse(
        self,
        path: str,
        text: str,
        language: str,
        *,
        max_chunk_lines: int,
        max_chunk_chars: int,
        max_dependencies_per_file: int = DEFAULT_MAX_DEPENDENCIES_PER_FILE,
        max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE,
        max_chunks_per_file: int = DEFAULT_MAX_CHUNKS_PER_FILE,
    ) -> ParseResult:
        layout = SourceLayout.build(text, language=language)

        def fallback() -> ParseResult:
            return self._fallback._parse_layout(
                path,
                text,
                language,
                layout,
                max_chunk_lines=max_chunk_lines,
                max_chunk_chars=max_chunk_chars,
                max_dependencies_per_file=max_dependencies_per_file,
                max_symbols_per_file=max_symbols_per_file,
                max_chunks_per_file=max_chunks_per_file,
            )

        try:
            source = text.encode("utf-8")
            tree = self._parser(language, path=path).parse(source)
            root = tree.root_node
            has_error = bool(root.has_error)
        except (
            AttributeError,
            KeyError,
            OSError,
            RuntimeError,
            SystemError,
            TypeError,
            ValueError,
        ):
            return fallback()
        if has_error:
            return fallback()
        try:
            symbols = self._symbols(
                path,
                source,
                root,
                layout,
                max_symbols=max_symbols_per_file,
            )
            dependencies = self._dependencies(
                path,
                source,
                root,
                language,
                layout,
                max_dependencies=max_dependencies_per_file,
            )
        except _FactLimitError:
            raise
        except (
            AttributeError,
            KeyError,
            OSError,
            RuntimeError,
            SystemError,
            TypeError,
            ValueError,
        ):
            return fallback()
        chunks = semantic_chunks(
            path=path,
            text=text,
            language=language,
            regions=[Region(item.start_line, item.end_line, item.name) for item in symbols],
            max_lines=max_chunk_lines,
            max_chars=max_chunk_chars,
            max_chunks=max_chunks_per_file,
            source_lines=layout.source_lines,
        )
        return ParseResult(
            symbols=symbols,
            dependencies=dependencies,
            chunks=chunks,
            is_entry_point=_source_entry_point(path, layout, language),
        )
