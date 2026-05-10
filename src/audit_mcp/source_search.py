"""Source-level search tools — find constants, types, assertions, and raw patterns.

These complement the function-level ``search_functions`` tool by searching
constructs that live OUTSIDE the call graph: ``constexpr`` constants,
``using``/``typedef`` type aliases, ``static_assert`` capacity checks,
``#define`` macros, bitfield declarations, and raw regex over source text.

These are critical for vulnerability research — the call graph tells you
WHO calls a dangerous function, but constants and type declarations tell
you WHETHER the call is dangerous (e.g., a 20-bit bitfield storing a value
that can reach 1,048,576).
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "SourceSearcher",
    "SourceMatch",
]

_log = logging.getLogger(__name__)

_C_EXTS = frozenset({".c", ".cc", ".cpp", ".h", ".hpp", ".cxx", ".mm"})


@dataclass(slots=True)
class SourceMatch:
    """A match from source-level search."""
    file: str
    line: int
    text: str
    kind: str  # "constant" | "type" | "assertion" | "bitfield" | "macro" | "raw"
    name: str = ""
    value: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "file": os.path.basename(self.file),
            "file_path": self.file,
            "line": self.line,
            "text": self.text,
            "kind": self.kind,
        }
        if self.name:
            d["name"] = self.name
        if self.value:
            d["value"] = self.value
        return d


class SourceSearcher:
    """Search source files for non-function constructs."""

    def __init__(self, root: str) -> None:
        self._root = Path(root).resolve()
        self._files: list[str] | None = None

    def _source_files(self) -> list[str]:
        if self._files is not None:
            return self._files
        skip = {".git", "test", "tests", "testing", "testdata",
                "node_modules", "build", "out", "third_party"}
        files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(self._root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in _C_EXTS:
                    files.append(os.path.join(dirpath, fn))
        self._files = files
        return files

    def search_constants(
        self, pattern: str, limit: int = 100,
    ) -> list[SourceMatch]:
        """Search constexpr, static const, and enum constants."""
        try:
            pat = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []

        const_re = re.compile(
            r'(?:constexpr|static\s+const(?:expr)?|enum)\s+'
            r'(?:[\w:<>, ]+\s+)?'
            r'(\w+)\s*=\s*([^;{]+)',
        )

        results: list[SourceMatch] = []
        for fp in self._source_files():
            try:
                lines = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if not pat.search(line):
                    continue
                m = const_re.search(line)
                if m:
                    results.append(SourceMatch(
                        file=fp, line=i + 1, text=line.strip(),
                        kind="constant", name=m.group(1), value=m.group(2).strip(),
                    ))
                    if len(results) >= limit:
                        return results
        return results

    def search_types(
        self, pattern: str, limit: int = 100,
    ) -> list[SourceMatch]:
        """Search using/typedef type aliases, class/struct declarations."""
        try:
            pat = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []

        type_re = re.compile(
            r'(?:using|typedef|class|struct|enum\s+class)\s+(\w+)',
        )

        results: list[SourceMatch] = []
        for fp in self._source_files():
            try:
                lines = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if not pat.search(line):
                    continue
                m = type_re.search(line)
                if m:
                    results.append(SourceMatch(
                        file=fp, line=i + 1, text=line.strip(),
                        kind="type", name=m.group(1),
                    ))
                    if len(results) >= limit:
                        return results
        return results

    def search_assertions(
        self, pattern: str, limit: int = 100,
    ) -> list[SourceMatch]:
        """Search static_assert, DCHECK, CHECK, DCHECK_LT/LE/GT/GE/EQ/NE."""
        try:
            pat = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []

        assert_re = re.compile(
            r'(static_assert|DCHECK\w*|CHECK\w*)\s*\((.+)',
        )

        results: list[SourceMatch] = []
        for fp in self._source_files():
            try:
                lines = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if not pat.search(line):
                    continue
                m = assert_re.search(line)
                if m:
                    results.append(SourceMatch(
                        file=fp, line=i + 1, text=line.strip(),
                        kind="assertion", name=m.group(1), value=m.group(2).strip(),
                    ))
                    if len(results) >= limit:
                        return results
        return results

    def search_bitfields(
        self, pattern: str = "", limit: int = 100,
    ) -> list[SourceMatch]:
        """Search BitField declarations — the core of type truncation bugs."""
        bf_re = re.compile(r'BitField<(\w+),\s*(\d+),\s*(\d+)')

        try:
            pat = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error:
            pat = None

        results: list[SourceMatch] = []
        for fp in self._source_files():
            try:
                lines = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                m = bf_re.search(line)
                if not m:
                    continue
                if pat and not pat.search(line):
                    continue
                bits = int(m.group(3))
                max_val = 1 << bits
                results.append(SourceMatch(
                    file=fp, line=i + 1, text=line.strip(),
                    kind="bitfield", name=m.group(0),
                    value=f"{bits} bits (max {max_val:,})",
                ))
                if len(results) >= limit:
                    return results
        return results

    def search_macros(
        self, pattern: str, limit: int = 100,
    ) -> list[SourceMatch]:
        """Search #define macros."""
        try:
            pat = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []

        define_re = re.compile(r'#\s*define\s+(\w+)(?:\([^)]*\))?\s*(.*)')

        results: list[SourceMatch] = []
        for fp in self._source_files():
            try:
                lines = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if not pat.search(line):
                    continue
                m = define_re.search(line)
                if m:
                    results.append(SourceMatch(
                        file=fp, line=i + 1, text=line.strip(),
                        kind="macro", name=m.group(1), value=m.group(2).strip(),
                    ))
                    if len(results) >= limit:
                        return results
        return results

    def search_source(
        self, pattern: str, limit: int = 100,
    ) -> list[SourceMatch]:
        """Raw regex search over source text — the escape hatch."""
        try:
            pat = re.compile(pattern)
        except re.error:
            return []

        results: list[SourceMatch] = []
        for fp in self._source_files():
            try:
                lines = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if pat.search(line):
                    results.append(SourceMatch(
                        file=fp, line=i + 1, text=line.strip(),
                        kind="raw",
                    ))
                    if len(results) >= limit:
                        return results
        return results

    def search_narrowing_casts(
        self, pattern: str = "", limit: int = 100,
    ) -> list[SourceMatch]:
        """Find static_cast to narrower types on size/index values."""
        cast_re = re.compile(
            r'static_cast<(u?int(?:8|16|32)_t)>\s*\(([^)]+)\)',
        )
        try:
            pat = re.compile(pattern, re.IGNORECASE) if pattern else None
        except re.error:
            pat = None

        results: list[SourceMatch] = []
        for fp in self._source_files():
            try:
                lines = Path(fp).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                m = cast_re.search(line)
                if not m:
                    continue
                if pat and not pat.search(line):
                    continue
                expr = m.group(2).strip()
                if any(kw in expr for kw in ('size', 'count', 'index', 'length', 'offset', 'num_')):
                    results.append(SourceMatch(
                        file=fp, line=i + 1, text=line.strip(),
                        kind="narrowing_cast", name=m.group(1), value=expr,
                    ))
                    if len(results) >= limit:
                        return results
        return results
