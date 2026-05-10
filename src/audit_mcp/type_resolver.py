"""Cross-file call resolver via include graph + type declarations.

Resolves method calls across files WITHOUT compiling by:
1. Parsing #include directives → per-file visibility graph
2. Extracting class/struct declarations from headers → global type table
3. Extracting variable declarations with types → receiver type inference
4. Matching call expressions to definitions by qualified name

This bridges the gap between tree-sitter (per-file, no cross-file edges)
and the full compiler (resolves everything but requires building the project).
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "TypeResolver",
    "IncludeGraph",
    "TypeTable",
    "ResolvedEdge",
]

_log = logging.getLogger(__name__)

# Regex patterns for C/C++ source analysis
_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
_CLASS_DECL_RE = re.compile(
    r'(?:class|struct)\s+(\w+)\s*(?:final\s*)?(?::\s*(?:public|protected|private)\s+(\w[\w:]*))?\s*\{',
)
_METHOD_DECL_RE = re.compile(
    r'(?:virtual\s+)?(?:static\s+)?'
    r'(?:[\w:*&<>, ]+?)\s+'  # return type
    r'(\w+)\s*\('           # method name
    r'[^)]*\)'              # params
    r'\s*(?:const\s*)?(?:override\s*)?(?:final\s*)?'
    r'\s*[;{=]',            # ends with ; (decl) or { (def) or = (pure virtual)
)
_VAR_DECL_RE = re.compile(
    r'(?:const\s+)?'
    r'([\w:]+)'              # type name
    r'(?:\s*[*&]+\s*|\s+)'   # pointer/ref or space
    r'(\w+)'                 # variable name
    r'\s*[;=({]',            # end
)
_CALL_EXPR_RE = re.compile(
    r'(\w+)'                 # receiver or function name
    r'(?:\s*->\s*|\s*\.\s*)' # -> or .
    r'(\w+)'                 # method name
    r'\s*\(',                # opening paren
)
_FUNC_CALL_RE = re.compile(
    r'(?<![.\->])\b(\w+)\s*\(',  # free function call (not method)
)
_FUNC_DEF_RE = re.compile(
    r'^(?:[\w:*&<>, ]+?)\s+'   # return type
    r'([\w:]+::)?(\w+)'       # optional Class:: + function name
    r'\s*\([^)]*\)'           # params
    r'\s*(?:const\s*)?'
    r'\s*\{',                 # opening brace = definition
    re.MULTILINE,
)
_OVERRIDE_RE = re.compile(r'\boverride\b')
_VIRTUAL_RE = re.compile(r'\bvirtual\b')
_ADDR_OF_RE = re.compile(r'&(\w+)::(\w+)')  # &Class::Method — address-taken


@dataclass(slots=True)
class ResolvedEdge:
    """A resolved cross-file call edge."""
    caller_file: str
    caller_func: str
    callee_file: str
    callee_func: str
    callee_qualified: str
    kind: str  # "direct" | "virtual" | "address_taken"
    confidence: float  # 0.0-1.0


@dataclass
class ClassInfo:
    """Parsed class/struct declaration."""
    name: str
    qualified_name: str
    file_path: str
    line: int
    parents: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    virtual_methods: list[str] = field(default_factory=list)
    is_override: dict[str, bool] = field(default_factory=dict)


@dataclass
class FuncDef:
    """A function/method definition."""
    name: str
    qualified_name: str  # "Class::method" or just "function"
    file_path: str
    line: int
    class_name: str = ""


class IncludeGraph:
    """Directed graph of #include relationships."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._edges: dict[str, list[str]] = {}  # file → [included files]

    def build(self, source_files: list[str]) -> None:
        """Parse #include directives from all source files."""
        for fpath in source_files:
            self._parse_includes(fpath)
        _log.info("include graph: %d files, %d edges",
                  len(self._edges),
                  sum(len(v) for v in self._edges.values()))

    def includes_of(self, file_path: str) -> list[str]:
        """Return files directly included by file_path."""
        return self._edges.get(self._normalize(file_path), [])

    def transitive_includes(self, file_path: str, max_depth: int = 10) -> set[str]:
        """Return all files transitively included."""
        result: set[str] = set()
        stack = [(self._normalize(file_path), 0)]
        while stack:
            current, depth = stack.pop()
            if depth > max_depth or current in result:
                continue
            result.add(current)
            for inc in self._edges.get(current, []):
                if inc not in result:
                    stack.append((inc, depth + 1))
        result.discard(self._normalize(file_path))
        return result

    def includers_of(self, file_path: str, max_depth: int = 10) -> set[str]:
        """Return all files that transitively include ``file_path``."""
        target = self._normalize(file_path)
        # Build reverse edges (who includes whom)
        reverse: dict[str, list[str]] = {}
        for src, dests in self._edges.items():
            for dest in dests:
                reverse.setdefault(dest, []).append(src)
        result: set[str] = set()
        stack = [(target, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > max_depth or current in result:
                continue
            result.add(current)
            for inc in reverse.get(current, []):
                if inc not in result:
                    stack.append((inc, depth + 1))
        result.discard(target)
        return result

    def _parse_includes(self, file_path: str) -> None:
        """Extract #include "..." directives from a file."""
        norm = self._normalize(file_path)
        if norm in self._edges:
            return
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            self._edges[norm] = []
            return
        includes: list[str] = []
        for match in _INCLUDE_RE.finditer(content):
            inc_path = match.group(1).replace("\\", "/")
            resolved = self._resolve_include(file_path, inc_path)
            if resolved:
                includes.append(self._normalize(resolved))
        self._edges[norm] = includes

    def _resolve_include(self, from_file: str, inc_path: str) -> str | None:
        """Resolve an include path relative to the file or project root."""
        # Try relative to the including file
        from_dir = Path(from_file).parent
        candidate = from_dir / inc_path
        if candidate.exists():
            return str(candidate)
        # Try relative to project root
        candidate = self._root / inc_path
        if candidate.exists():
            return str(candidate)
        return None

    def _normalize(self, path: str) -> str:
        return str(Path(path).resolve()).replace("\\", "/").lower()


class TypeTable:
    """Global type table extracted from headers."""

    def __init__(self) -> None:
        self.classes: dict[str, ClassInfo] = {}  # class_name → ClassInfo
        self.functions: dict[str, list[FuncDef]] = {}  # func_name → [definitions]
        self.qualified: dict[str, FuncDef] = {}  # "Class::method" → FuncDef
        self.inheritance: dict[str, list[str]] = {}  # class → [parent_classes]
        self.children: dict[str, list[str]] = {}  # class → [child_classes]

    def add_class(self, info: ClassInfo) -> None:
        self.classes[info.name] = info
        for parent in info.parents:
            self.inheritance.setdefault(info.name, []).append(parent)
            self.children.setdefault(parent, []).append(info.name)

    def add_function(self, fdef: FuncDef) -> None:
        self.functions.setdefault(fdef.name, []).append(fdef)
        if fdef.qualified_name:
            self.qualified[fdef.qualified_name] = fdef

    def resolve_method(self, class_name: str, method_name: str) -> list[FuncDef]:
        """Resolve Class::method, including inherited and overridden methods."""
        results: list[FuncDef] = []
        qname = f"{class_name}::{method_name}"
        if qname in self.qualified:
            results.append(self.qualified[qname])
        # Check parent classes
        for parent in self.inheritance.get(class_name, []):
            pqname = f"{parent}::{method_name}"
            if pqname in self.qualified:
                results.append(self.qualified[pqname])
        return results

    def all_overrides(self, class_name: str, method_name: str) -> list[FuncDef]:
        """Find all overrides of a virtual method in the class hierarchy."""
        results: list[FuncDef] = []
        # Check this class and all children recursively
        stack = [class_name]
        visited: set[str] = set()
        while stack:
            cls = stack.pop()
            if cls in visited:
                continue
            visited.add(cls)
            qname = f"{cls}::{method_name}"
            if qname in self.qualified:
                results.append(self.qualified[qname])
            for child in self.children.get(cls, []):
                stack.append(child)
        return results

    def lookup_function(self, name: str) -> list[FuncDef]:
        """Look up all definitions of a function by unqualified name."""
        return self.functions.get(name, [])

    def children_of(self, class_name: str) -> list[str]:
        """Return all classes that directly or transitively inherit from class_name."""
        result: list[str] = []
        stack = list(self.children.get(class_name, []))
        visited: set[str] = set()
        while stack:
            cls = stack.pop()
            if cls in visited:
                continue
            visited.add(cls)
            result.append(cls)
            stack.extend(self.children.get(cls, []))
        return result


class TypeResolver:
    """Cross-file call resolver using include graph + type analysis."""

    def __init__(self, root: str) -> None:
        self._root = Path(root).resolve()
        self.include_graph = IncludeGraph(self._root)
        self.type_table = TypeTable()
        self._var_types: dict[str, dict[str, str]] = {}  # file → {var_name → type_name}
        self._file_funcs: dict[str, list[str]] = {}  # file → [func_names defined]

    def index(self, source_files: list[str] | None = None) -> dict[str, Any]:
        """Build the include graph, type table, and resolve cross-file edges.

        Returns summary stats.
        """
        if source_files is None:
            source_files = self._discover_files()

        h_files = [f for f in source_files if f.endswith(".h")]
        cc_files = [f for f in source_files if f.endswith((".cc", ".cpp", ".c"))]

        # Step 1: Include graph
        self.include_graph.build(source_files)

        # Step 2: Parse headers → type table
        for h in h_files:
            self._parse_header(h)

        # Step 3: Parse source files → function defs + variable types + calls
        for cc in cc_files:
            self._parse_source(cc)

        _log.info(
            "type_resolver: %d classes, %d functions, %d qualified names",
            len(self.type_table.classes),
            sum(len(v) for v in self.type_table.functions.values()),
            len(self.type_table.qualified),
        )

        return {
            "classes": len(self.type_table.classes),
            "functions": sum(len(v) for v in self.type_table.functions.values()),
            "qualified_names": len(self.type_table.qualified),
            "include_edges": sum(len(v) for v in self.include_graph._edges.values()),
            "files_parsed": len(h_files) + len(cc_files),
        }

    def resolve_calls(self, file_path: str) -> list[ResolvedEdge]:
        """Resolve all cross-file call edges from a single source file."""
        edges: list[ResolvedEdge] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return edges

        # Current function context (simplified: track the last function definition)
        current_func = ""
        for match in _FUNC_DEF_RE.finditer(content):
            class_prefix = (match.group(1) or "").rstrip(":")
            func_name = match.group(2)
            current_func = f"{class_prefix}::{func_name}" if class_prefix else func_name

        # Method calls: receiver->method() or receiver.method()
        var_types = self._var_types.get(file_path, {})
        for match in _CALL_EXPR_RE.finditer(content):
            receiver = match.group(1)
            method = match.group(2)
            receiver_type = var_types.get(receiver)
            if receiver_type:
                targets = self.type_table.resolve_method(receiver_type, method)
                for t in targets:
                    edges.append(ResolvedEdge(
                        caller_file=file_path,
                        caller_func=current_func or "(unknown)",
                        callee_file=t.file_path,
                        callee_func=t.name,
                        callee_qualified=t.qualified_name,
                        kind="direct",
                        confidence=0.9,
                    ))
                # Check for virtual dispatch
                cls = self.type_table.classes.get(receiver_type)
                if cls and method in cls.virtual_methods:
                    overrides = self.type_table.all_overrides(receiver_type, method)
                    for ovr in overrides:
                        if ovr.qualified_name not in {e.callee_qualified for e in edges}:
                            edges.append(ResolvedEdge(
                                caller_file=file_path,
                                caller_func=current_func or "(unknown)",
                                callee_file=ovr.file_path,
                                callee_func=ovr.name,
                                callee_qualified=ovr.qualified_name,
                                kind="virtual",
                                confidence=0.7,
                            ))

        # Free function calls: name-matched globally
        for match in _FUNC_CALL_RE.finditer(content):
            func_name = match.group(1)
            if func_name in ("if", "for", "while", "switch", "return", "sizeof",
                             "static_cast", "dynamic_cast", "reinterpret_cast",
                             "const_cast", "decltype", "typeof"):
                continue
            targets = self.type_table.lookup_function(func_name)
            for t in targets:
                if t.file_path != file_path:  # only cross-file edges
                    edges.append(ResolvedEdge(
                        caller_file=file_path,
                        caller_func=current_func or "(unknown)",
                        callee_file=t.file_path,
                        callee_func=t.name,
                        callee_qualified=t.qualified_name,
                        kind="direct",
                        confidence=0.6,
                    ))

        # Address-taken: &Class::Method
        for match in _ADDR_OF_RE.finditer(content):
            class_name = match.group(1)
            method_name = match.group(2)
            targets = self.type_table.resolve_method(class_name, method_name)
            for t in targets:
                edges.append(ResolvedEdge(
                    caller_file=file_path,
                    caller_func=current_func or "(unknown)",
                    callee_file=t.file_path,
                    callee_func=t.name,
                    callee_qualified=t.qualified_name,
                    kind="address_taken",
                    confidence=0.8,
                ))

        return edges

    def resolve_all(self) -> list[ResolvedEdge]:
        """Resolve all cross-file edges across all parsed source files."""
        all_edges: list[ResolvedEdge] = []
        for file_path in self._file_funcs:
            all_edges.extend(self.resolve_calls(file_path))
        return all_edges

    def callers_of(self, func_name: str) -> list[ResolvedEdge]:
        """Find all callers of a function by name."""
        all_edges = self.resolve_all()
        return [e for e in all_edges
                if e.callee_func == func_name or e.callee_qualified.endswith(f"::{func_name}")]

    def callees_of(self, func_name: str) -> list[ResolvedEdge]:
        """Find all callees from a function by name."""
        all_edges = self.resolve_all()
        return [e for e in all_edges
                if e.caller_func == func_name or e.caller_func.endswith(f"::{func_name}")]

    def trace_to(self, sink_name: str, max_depth: int = 10) -> list[list[ResolvedEdge]]:
        """Trace all paths from any entrypoint to a named sink."""
        all_edges = self.resolve_all()
        # Build reverse adjacency list
        callers_map: dict[str, list[ResolvedEdge]] = {}
        for e in all_edges:
            callers_map.setdefault(e.callee_func, []).append(e)
            if "::" in e.callee_qualified:
                short = e.callee_qualified.split("::")[-1]
                callers_map.setdefault(short, []).append(e)

        # BFS backward from sink
        paths: list[list[ResolvedEdge]] = []
        queue: list[tuple[str, list[ResolvedEdge]]] = [(sink_name, [])]
        visited: set[str] = set()
        while queue and len(paths) < 50:
            current, path = queue.pop(0)
            if current in visited or len(path) > max_depth:
                continue
            visited.add(current)
            for edge in callers_map.get(current, []):
                new_path = [edge] + path
                paths.append(new_path)
                queue.append((edge.caller_func, new_path))

        return paths

    def _parse_header(self, file_path: str) -> None:
        """Extract class declarations, methods, and inheritance from a header."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        for match in _CLASS_DECL_RE.finditer(content):
            class_name = match.group(1)
            parent = match.group(2)
            info = ClassInfo(
                name=class_name,
                qualified_name=class_name,
                file_path=file_path,
                line=content[:match.start()].count("\n") + 1,
                parents=[parent] if parent else [],
            )

            # Find methods within this class (simplified: scan forward for method-like patterns)
            brace_depth = 0
            class_start = match.end()
            class_end = class_start
            for i in range(class_start, min(class_start + 50000, len(content))):
                if content[i] == "{":
                    brace_depth += 1
                elif content[i] == "}":
                    if brace_depth == 0:
                        class_end = i
                        break
                    brace_depth -= 1

            class_body = content[class_start:class_end]
            for m_match in _METHOD_DECL_RE.finditer(class_body):
                method_name = m_match.group(1)
                if method_name in ("if", "for", "while", "return", "class", "struct"):
                    continue
                info.methods.append(method_name)
                qname = f"{class_name}::{method_name}"
                self.type_table.add_function(FuncDef(
                    name=method_name,
                    qualified_name=qname,
                    file_path=file_path,
                    line=content[:class_start + m_match.start()].count("\n") + 1,
                    class_name=class_name,
                ))
                # Check virtual/override
                line_text = class_body[max(0, m_match.start() - 50):m_match.end() + 50]
                if _VIRTUAL_RE.search(line_text):
                    info.virtual_methods.append(method_name)
                if _OVERRIDE_RE.search(line_text):
                    info.is_override[method_name] = True

            self.type_table.add_class(info)

    def _parse_source(self, file_path: str) -> None:
        """Extract function definitions and variable types from a source file."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        # Function definitions
        func_names: list[str] = []
        for match in _FUNC_DEF_RE.finditer(content):
            class_prefix = (match.group(1) or "").rstrip(":")
            func_name = match.group(2)
            qname = f"{class_prefix}::{func_name}" if class_prefix else func_name
            fdef = FuncDef(
                name=func_name,
                qualified_name=qname,
                file_path=file_path,
                line=content[:match.start()].count("\n") + 1,
                class_name=class_prefix,
            )
            self.type_table.add_function(fdef)
            func_names.append(func_name)
        self._file_funcs[file_path] = func_names

        # Variable declarations with types
        var_types: dict[str, str] = {}
        for match in _VAR_DECL_RE.finditer(content):
            type_name = match.group(1)
            var_name = match.group(2)
            # Strip common prefixes
            type_name = type_name.split("::")[-1] if "::" in type_name else type_name
            if type_name and type_name[0].isupper():  # likely a class name, not a keyword
                var_types[var_name] = type_name
        self._var_types[file_path] = var_types

    def _discover_files(self) -> list[str]:
        """Find all C/C++ source and header files under root."""
        exts = {".c", ".cc", ".cpp", ".h", ".hpp"}
        skip = {".git", "test", "tests", "testing", "testdata", "third_party",
                "node_modules", "build", "out"}
        files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self._root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in exts:
                    files.append(os.path.join(dirpath, fn))
        return files
