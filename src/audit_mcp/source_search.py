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
    numeric_value: int | float | None = None  # evaluated constant value
    context_before: list[str] | None = None
    context_after: list[str] | None = None

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
        if self.numeric_value is not None:
            d["numeric_value"] = self.numeric_value
        if self.context_before:
            d["context_before"] = self.context_before
        if self.context_after:
            d["context_after"] = self.context_after
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

    def _read_file_lines(self, file_path: str) -> list[str] | None:
        try:
            return Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None

    @staticmethod
    def _get_context(
        lines: list[str], match_line: int, context_lines: int,
    ) -> tuple[list[str], list[str]]:
        start = max(0, match_line - context_lines)
        end = min(len(lines), match_line + 1 + context_lines)
        before = [lines[i].rstrip() for i in range(start, match_line)]
        after = [lines[i].rstrip() for i in range(match_line + 1, end)]
        return before, after

    @staticmethod
    def _eval_constant(expr: str) -> int | float | None:
        cleaned = expr.replace("'", "").strip()
        cleaned = re.sub(r'[uUlLfF]+$', '', cleaned)
        try:
            return int(eval(cleaned, {"__builtins__": {}}, {}))  # noqa: S307
        except (ValueError, TypeError, SyntaxError, NameError, ZeroDivisionError):
            return None

    def _attach_context(
        self, match: SourceMatch, lines: list[str], context_lines: int,
    ) -> None:
        if context_lines > 0:
            before, after = self._get_context(lines, match.line - 1, context_lines)
            match.context_before = before
            match.context_after = after

    def search_constants(
        self, pattern: str, limit: int = 100, context_lines: int = 0,
    ) -> list[SourceMatch]:
        """Search constexpr/static const/enum constants. Evaluates simple arithmetic."""
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
            lines = self._read_file_lines(fp)
            if lines is None:
                continue
            for i, line in enumerate(lines):
                if not pat.search(line):
                    continue
                m = const_re.search(line)
                if m:
                    val_str = m.group(2).strip()
                    sm = SourceMatch(
                        file=fp, line=i + 1, text=line.strip(),
                        kind="constant", name=m.group(1), value=val_str,
                        numeric_value=self._eval_constant(val_str),
                    )
                    self._attach_context(sm, lines, context_lines)
                    results.append(sm)
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

    def extract_class(
        self, file_path: str, class_name: str,
    ) -> dict[str, Any] | None:
        """Extract the full body of a class/struct from a source file.

        Returns the class declaration, members, methods, and inheritance.
        """
        full_path = None
        for fp in self._source_files():
            if file_path in fp or os.path.basename(fp) == file_path:
                full_path = fp
                break
        if full_path is None:
            return None
        lines = self._read_file_lines(full_path)
        if lines is None:
            return None
        class_re = re.compile(
            rf'(?:class|struct)\s+(?:__attribute__\s*\(\([^)]*\)\)\s*)?{re.escape(class_name)}\b'
        )
        for i, line in enumerate(lines):
            if not class_re.search(line):
                continue
            # Found the class declaration — extract body by brace matching
            start_line = i
            brace_count = 0
            started = False
            body_lines: list[str] = []
            for j in range(i, min(len(lines), i + 2000)):
                body_lines.append(lines[j].rstrip())
                brace_count += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started = True
                if started and brace_count <= 0:
                    break
            return {
                "file": os.path.basename(full_path),
                "file_path": full_path,
                "class_name": class_name,
                "start_line": start_line + 1,
                "end_line": start_line + len(body_lines),
                "line_count": len(body_lines),
                "body": body_lines,
            }
        return None

    def read_function(
        self, file_path: str, function_name: str,
    ) -> dict[str, Any] | None:
        """Extract the full body of a function/method from a source file."""
        full_path = None
        for fp in self._source_files():
            if file_path in fp or os.path.basename(fp) == file_path:
                full_path = fp
                break
        if full_path is None:
            return None
        lines = self._read_file_lines(full_path)
        if lines is None:
            return None
        func_re = re.compile(
            rf'\b{re.escape(function_name)}\s*\([^;]*\)\s*(?:const\s*)?(?:override\s*)?(?:final\s*)?\{{'
        )
        for i, line in enumerate(lines):
            if not func_re.search(line):
                continue
            start_line = i
            brace_count = 0
            started = False
            body_lines: list[str] = []
            for j in range(i, min(len(lines), i + 5000)):
                body_lines.append(lines[j].rstrip())
                brace_count += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started = True
                if started and brace_count <= 0:
                    break
            return {
                "file": os.path.basename(full_path),
                "file_path": full_path,
                "function_name": function_name,
                "start_line": start_line + 1,
                "end_line": start_line + len(body_lines),
                "line_count": len(body_lines),
                "body": body_lines,
            }
        return None

    def cross_reference_bitfields(self) -> list[dict[str, Any]]:
        """Cross-reference BitField declarations against static_assert capacity checks.

        For each BitField with >= 10 bits, find related kMax constants and
        check if a static_assert connects them. Returns findings sorted by risk.
        """
        bitfields = self.search_bitfields(limit=500)
        assertions = self.search_assertions("static_assert", limit=500)
        constants = self.search_constants("kMax|kV8Max", limit=500)
        assert_texts = [a.text for a in assertions]

        findings: list[dict[str, Any]] = []
        for bf in bitfields:
            bits_match = re.search(r'(\d+) bits', bf.value)
            if not bits_match:
                continue
            bits = int(bits_match.group(1))
            if bits < 10:
                continue
            max_val = 1 << bits

            # Extract field name
            field_name = bf.text.split("using ")[-1].split("=")[0].strip() if "using" in bf.text else ""

            # Check if any static_assert references this field
            protected = any(
                field_name in at and "<<" in at
                for at in assert_texts
                if field_name and len(field_name) > 3
            )

            # Find related kMax constant by name heuristic
            field_lower = field_name.lower().replace("field", "").replace("bits", "").strip()
            related_const = None
            related_val = None
            for c in constants:
                const_lower = c.name.lower()
                if field_lower and len(field_lower) > 3 and field_lower in const_lower:
                    related_const = c.name
                    related_val = c.numeric_value
                    break

            # Compute margin
            margin = None
            margin_pct = None
            if related_val is not None:
                margin = max_val - related_val
                margin_pct = round(margin / max_val * 100, 1)

            risk = "safe"
            if margin is not None and margin <= 0:
                risk = "overflow"
            elif margin is not None and margin_pct is not None and margin_pct < 5:
                risk = "tight"
            elif not protected and bits >= 14:
                risk = "unprotected"

            findings.append({
                "field": field_name,
                "file": os.path.basename(bf.file),
                "line": bf.line,
                "bits": bits,
                "max_capacity": max_val,
                "related_constant": related_const,
                "related_value": related_val,
                "margin": margin,
                "margin_pct": margin_pct,
                "has_static_assert": protected,
                "risk": risk,
                "text": bf.text,
            })

        # Sort: overflow first, then tight, then unprotected, then safe
        risk_order = {"overflow": 0, "tight": 1, "unprotected": 2, "safe": 3}
        findings.sort(key=lambda f: (risk_order.get(f["risk"], 99), -f["bits"]))
        return findings
