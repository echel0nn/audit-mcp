"""Trailmark MCP server — code graph tools via FastMCP.

Wraps trailmark's :class:`QueryEngine` as MCP tools. Every analytical tool
requires an ``index_id`` returned by :func:`index_codebase`; until that index
reports ``status == "ready"`` the tool returns ``{"status": "pending", ...}``
so callers can poll without blocking.

The same ``mcp`` and ``index_manager`` singletons are shared with the HTTP
transport so callers see one cache across both.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from fastmcp import FastMCP

from trailmark_mcp.indexer import IndexManager

__all__ = ["mcp", "run_mcp", "index_manager"]

_log = logging.getLogger(__name__)

mcp = FastMCP("trailmark-mcp")
index_manager = IndexManager()


# Errors that map to a JSON envelope rather than crashing the tool transport.
_TOOL_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    RuntimeError,
    KeyError,
    TypeError,
    OSError,
    LookupError,
)


def _require_engine(index_id: str) -> tuple[Any, dict[str, Any] | None]:
    """Return ``(engine, None)`` when ready, else ``(None, error_envelope)``.

    Pending and unknown ids return a structured envelope rather than raising
    so MCP callers can branch on ``status`` without try/except.
    """
    snapshot = index_manager.poll(index_id)
    status = snapshot.get("status")
    if status == "ready":
        engine = index_manager.get_engine(index_id)
        if engine is None:
            return None, {
                "status": "error",
                "error": f"Index {index_id} reported ready but engine missing",
            }
        return engine, None
    if status == "error":
        return None, {"status": "error", "error": snapshot.get("error", "unknown error")}
    return None, snapshot  # status == "pending" / "indexing" / unknown id


def _annotation_kind(kind: str) -> Any:
    """Resolve a string into the trailmark ``AnnotationKind`` enum."""
    from trailmark.models.annotations import AnnotationKind

    try:
        return AnnotationKind(kind)
    except ValueError as exc:
        valid = ", ".join(k.value for k in AnnotationKind)
        raise ValueError(f"Unknown annotation kind {kind!r}; valid: {valid}") from exc


# ---------------------------------------------------------------------------
# Index lifecycle
# ---------------------------------------------------------------------------


@mcp.tool()
def index_codebase(path: str, language: str = "auto") -> dict[str, Any]:
    """Begin indexing a codebase. Returns immediately with an index_id.

    ``language`` accepts ``"auto"``, a single language (e.g. ``"python"``),
    or a comma-separated list (e.g. ``"python,rust"``). Poll progress with
    :func:`poll_index`.
    """
    index_id = index_manager.start_index(path, language=language)
    snapshot = index_manager.poll(index_id)
    return snapshot


@mcp.tool()
def poll_index(index_id: str) -> dict[str, Any]:
    """Return the current status and (when ready) summary for an index."""
    return index_manager.poll(index_id)


@mcp.tool()
def list_indexes() -> dict[str, Any]:
    """Return all known indexes with their current status."""
    return {"indexes": index_manager.list_indexes()}


# ---------------------------------------------------------------------------
# Graph queries
# ---------------------------------------------------------------------------


@mcp.tool()
def summary(index_id: str) -> dict[str, Any]:
    """Return graph counters: nodes, functions, classes, call edges, entrypoints."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return engine.summary()


@mcp.tool()
def preanalysis(index_id: str) -> dict[str, Any]:
    """Return blast radius, entrypoints, privilege boundaries, and taint passes."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return engine.preanalysis()


@mcp.tool()
def callers_of(index_id: str, name: str) -> dict[str, Any]:
    """Return direct callers of ``name``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"callers": engine.callers_of(name)}


@mcp.tool()
def callees_of(index_id: str, name: str) -> dict[str, Any]:
    """Return direct callees of ``name``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"callees": engine.callees_of(name)}


@mcp.tool()
def ancestors_of(index_id: str, name: str) -> dict[str, Any]:
    """Return every function/method that can transitively reach ``name``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"ancestors": engine.ancestors_of(name)}


@mcp.tool()
def reachable_from(index_id: str, name: str) -> dict[str, Any]:
    """Return every function/method transitively reachable from ``name``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"reachable": engine.reachable_from(name)}


@mcp.tool()
def paths_between(index_id: str, source: str, target: str) -> dict[str, Any]:
    """Return all call paths from ``source`` to ``target``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"paths": engine.paths_between(source, target)}


@mcp.tool()
def entrypoint_paths_to(
    index_id: str,
    name: str,
    max_depth: int = 20,
) -> dict[str, Any]:
    """Return call paths from any entrypoint to ``name``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {
        "paths": engine.entrypoint_paths_to(name, max_depth=max_depth),
    }


@mcp.tool()
def attack_surface(index_id: str) -> dict[str, Any]:
    """Return entrypoints with their trust levels and asset values."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"entrypoints": engine.attack_surface()}


@mcp.tool()
def complexity_hotspots(index_id: str, threshold: int = 10) -> dict[str, Any]:
    """Return functions with cyclomatic complexity >= ``threshold``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"hotspots": engine.complexity_hotspots(threshold=threshold)}


@mcp.tool()
def search_functions(index_id: str, pattern: str) -> dict[str, Any]:
    """Regex-search function/method names in the graph (case-insensitive)."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return {"status": "error", "error": f"Invalid regex: {exc}"}
    graph = engine._store._graph  # noqa: SLF001 — trailmark public-by-convention
    matches: list[dict[str, Any]] = []
    for unit in graph.nodes.values():
        kind_value = getattr(unit.kind, "value", str(unit.kind))
        if kind_value not in {"function", "method"}:
            continue
        name = getattr(unit, "name", "") or ""
        qualified = getattr(unit, "qualified_name", "") or ""
        if regex.search(name) or regex.search(qualified):
            matches.append(
                {
                    "id": getattr(unit, "id", None),
                    "name": name,
                    "qualified_name": qualified,
                    "file_path": getattr(unit, "file_path", ""),
                    "line_start": getattr(unit, "line_start", 0),
                    "line_end": getattr(unit, "line_end", 0),
                    "kind": kind_value,
                }
            )
    return {"matches": matches, "count": len(matches)}


@mcp.tool()
def diff_codebases(index_id_a: str, index_id_b: str) -> dict[str, Any]:
    """Diff index ``a`` ("before") against index ``b`` ("after")."""
    engine_b, err = _require_engine(index_id_b)
    if err is not None:
        return err
    engine_a, err = _require_engine(index_id_a)
    if err is not None:
        return err
    return engine_b.diff_against(engine_a)


# ---------------------------------------------------------------------------
# Annotations & findings
# ---------------------------------------------------------------------------


@mcp.tool()
def annotate_function(
    index_id: str,
    name: str,
    kind: str,
    description: str,
) -> dict[str, Any]:
    """Attach an annotation to a function by name. ``kind`` matches AnnotationKind."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    try:
        ann_kind = _annotation_kind(kind)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}
    ok = engine.annotate(name, ann_kind, description)
    return {"applied": bool(ok), "name": name, "kind": kind}


@mcp.tool()
def annotations_of(index_id: str, name: str) -> dict[str, Any]:
    """Return annotations on a function by name."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"annotations": engine.annotations_of(name)}


@mcp.tool()
def findings(index_id: str) -> dict[str, Any]:
    """Return nodes with FINDING or AUDIT_NOTE annotations."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"findings": engine.findings()}


# ---------------------------------------------------------------------------
# Language utilities (no index required)
# ---------------------------------------------------------------------------


@mcp.tool()
def supported_languages() -> dict[str, Any]:
    """Return languages trailmark can parse."""
    import trailmark

    return {"languages": list(trailmark.supported_languages())}


@mcp.tool()
def detect_languages(path: str) -> dict[str, Any]:
    """Detect languages present under ``path``."""
    import trailmark

    return {"path": path, "languages": list(trailmark.detect_languages(path))}


def run_mcp() -> None:
    """Run the MCP server over stdio."""
    mcp.run()
