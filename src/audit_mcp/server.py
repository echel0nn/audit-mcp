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

from audit_mcp.indexer import IndexManager

__all__ = ["mcp", "run_mcp", "index_manager"]

_log = logging.getLogger(__name__)

mcp = FastMCP("audit-mcp")
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
# SARIF augmentation + scanner orchestration
# ---------------------------------------------------------------------------


@mcp.tool()
def augment_sarif(index_id: str, sarif_path: str) -> dict[str, Any]:
    """Import SARIF static analysis results and overlay findings on the code graph."""
    engine, err = _require_engine(index_id)
    if err:
        return err
    return engine.augment_sarif(sarif_path)


@mcp.tool()
def list_scanners() -> dict[str, Any]:
    """List available source code scanners and whether they are installed.

    Supported: semgrep, bandit, trivy, bearer, gosec, phpstan.
    A scanner is 'installed' when its binary is on PATH.
    """
    from audit_mcp.scanners import ScannerRunner

    return {"scanners": ScannerRunner.list_installed()}


@mcp.tool()
def run_scanner(index_id: str, scanner: str, timeout_seconds: int = 600) -> dict[str, Any]:
    """Execute a SAST scanner on an indexed codebase and import results.

    Runs the scanner, produces SARIF, imports findings into the code graph.
    Returns a summary of findings found.

    Supported scanners: semgrep, bandit, trivy, bearer, gosec, phpstan.
    """
    from audit_mcp.scanners import ScannerRunner

    engine, err = _require_engine(index_id)
    if err:
        return err
    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return {"status": "error", "error": f"Index {index_id!r} not found"}

    try:
        sarif_path = ScannerRunner.run(scanner, entry.root_path, timeout_seconds)
    except (ValueError, RuntimeError, OSError) as exc:
        return {"status": "error", "error": str(exc)}

    # Import SARIF results into the graph
    import_result = engine.augment_sarif(str(sarif_path))

    # Clean up temp file
    try:
        sarif_path.unlink(missing_ok=True)
    except OSError:
        pass

    return {
        "status": "ready",
        "scanner": scanner,
        "target": entry.root_path,
        "import_result": import_result,
    }


@mcp.tool()
def scan_and_correlate(index_id: str, scanner: str, timeout_seconds: int = 600) -> dict[str, Any]:
    """Run a scanner, import results, and correlate with graph properties.

    The killer query: 'semgrep found 47 SQLi. Of those, 12 are tainted
    from entrypoints. Of those, 3 have blast radius > 50. Start there.'

    Returns findings sorted by risk_score (tainted + entrypoint-reachable
    + high blast radius = highest priority).
    """
    from audit_mcp.scanners import ScannerRunner

    engine, err = _require_engine(index_id)
    if err:
        return err
    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return {"status": "error", "error": f"Index {index_id!r} not found"}

    # Step 1: Run the scanner
    try:
        sarif_path = ScannerRunner.run(scanner, entry.root_path, timeout_seconds)
    except (ValueError, RuntimeError, OSError) as exc:
        return {"status": "error", "error": str(exc)}

    # Step 2: Import SARIF into graph
    engine.augment_sarif(str(sarif_path))
    try:
        sarif_path.unlink(missing_ok=True)
    except OSError:
        pass

    # Step 3: Correlate findings with graph properties
    correlation = ScannerRunner.correlate_findings(engine, entry.preanalysis)
    return {
        "status": "ready",
        "scanner": scanner,
        "target": entry.root_path,
        **correlation,
    }


# ---------------------------------------------------------------------------
# Exception + annotation queries
# ---------------------------------------------------------------------------


@mcp.tool()
def functions_that_raise(index_id: str, exception_name: str) -> dict[str, Any]:
    """Find all functions that raise/throw a specific exception type."""
    engine, err = _require_engine(index_id)
    if err:
        return err
    results = engine.functions_that_raise(exception_name)
    return {"exception": exception_name, "functions": results, "count": len(results)}


@mcp.tool()
def nodes_with_annotation(index_id: str, kind: str) -> dict[str, Any]:
    """Find all nodes tagged with a specific annotation kind.

    Valid kinds: finding, audit_note, blast_radius, privilege_boundary,
    taint, entrypoint, sarif_finding, weaudit_finding.
    """
    from trailmark.models.annotations import AnnotationKind

    engine, err = _require_engine(index_id)
    if err:
        return err
    kind_map = {k.value: k for k in AnnotationKind}
    ak = kind_map.get(kind)
    if ak is None:
        return {"status": "error", "error": f"Unknown annotation kind: {kind!r}. Valid: {sorted(kind_map)}"}
    results = engine.nodes_with_annotation(ak)
    return {"kind": kind, "nodes": results, "count": len(results)}


@mcp.tool()
def clear_annotations(index_id: str, name: str, kind: str | None = None) -> dict[str, Any]:
    """Remove annotations from a function, optionally filtered by kind."""
    from trailmark.models.annotations import AnnotationKind

    engine, err = _require_engine(index_id)
    if err:
        return err
    ak: AnnotationKind | None = None
    if kind is not None:
        kind_map = {k.value: k for k in AnnotationKind}
        ak = kind_map.get(kind)
        if ak is None:
            return {"status": "error", "error": f"Unknown annotation kind: {kind!r}"}
    ok = engine.clear_annotations(name, ak)
    if not ok:
        return {"status": "error", "error": f"Function {name!r} not found"}
    return {"status": "ok", "cleared": name, "kind": kind}


@mcp.tool()
def export_graph(index_id: str) -> dict[str, Any]:
    """Export the full code graph as JSON. Use for offline analysis or caching."""
    engine, err = _require_engine(index_id)
    if err:
        return err
    return engine.to_json()


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


# ---------------------------------------------------------------------------
# Deep audit tools (graph-aware, our differentiator)
# ---------------------------------------------------------------------------


@mcp.tool()
def dead_code(index_id: str) -> dict[str, Any]:
    """Find functions with zero callers that are not entrypoints.

    Dead code = never called. Removing it reduces attack surface.
    Sorted by complexity (most complex dead code first)."""
    from audit_mcp.deep_audit import find_dead_code

    engine, err = _require_engine(index_id)
    if err:
        return err
    return find_dead_code(engine)


@mcp.tool()
def unreachable_from_entrypoints(index_id: str) -> dict[str, Any]:
    """Find functions no external entrypoint can transitively reach.

    Any SAST finding in these functions is lower priority — not exploitable
    by external attackers (unless dynamic dispatch bypasses static analysis)."""
    from audit_mcp.deep_audit import find_unreachable_from_entrypoints

    engine, err = _require_engine(index_id)
    if err:
        return err
    return find_unreachable_from_entrypoints(engine)


@mcp.tool()
def taint_paths_to(index_id: str, sink_name: str, max_depth: int = 20) -> dict[str, Any]:
    """Find all entrypoint-to-sink call paths for a dangerous function.

    Answers: 'Is this eval/exec/SQL query reachable from the network?'
    Returns every concrete path from every entrypoint to the named sink."""
    from audit_mcp.deep_audit import taint_paths_to_sink

    engine, err = _require_engine(index_id)
    if err:
        return err
    return taint_paths_to_sink(engine, sink_name, max_depth)


@mcp.tool()
def fuzzing_targets(index_id: str, min_complexity: int = 10, limit: int = 20) -> dict[str, Any]:
    """Identify the highest-value fuzzing targets.

    Ranks functions by: tainted from untrusted input + high complexity +
    high blast radius + is entrypoint. Returns: 'fuzz these first.'"""
    from audit_mcp.deep_audit import suggest_fuzzing_targets

    engine, err = _require_engine(index_id)
    if err:
        return err
    return suggest_fuzzing_targets(engine, min_complexity, limit)


@mcp.tool()
def attack_surface_diff(index_id_a: str, index_id_b: str) -> dict[str, Any]:
    """Compare attack surfaces between two indexed codebase versions.

    Answers: 'Did this PR / release change our attack surface?'
    Reports new/removed entrypoints, blast radius changes, structural diff."""
    from audit_mcp.deep_audit import diff_attack_surface

    engine_a, err_a = _require_engine(index_id_a)
    if err_a:
        return err_a
    engine_b, err_b = _require_engine(index_id_b)
    if err_b:
        return err_b
    return diff_attack_surface(engine_a, engine_b)


# ---------------------------------------------------------------------------
# Scale: partitioned indexing for large codebases (Chromium, Linux kernel)
# ---------------------------------------------------------------------------


@mcp.tool()
def plan_partitions(path: str) -> dict[str, Any]:
    """Analyze a codebase and produce a partition plan for large-scale indexing.

    For codebases > 10K files (Chromium, Linux kernel, Android), single-graph
    indexing fails (OOM, timeout). This tool splits the codebase into indexable
    partitions by top-level directory. Each partition can be indexed separately.

    Returns:
      - Whether partitioning is needed
      - List of partitions with file counts
      - Which partitions are third-party (lower audit priority)
      - Which directories were excluded (test, docs, build artifacts)
    """
    from audit_mcp.partitioner import Partitioner

    planner = Partitioner()
    plan = planner.plan(path)
    return {
        "status": "ready",
        "root_path": plan.root_path,
        "needs_partitioning": plan.needs_partitioning,
        "reason": plan.reason,
        "total_files": plan.total_files,
        "total_partitions": plan.total_partitions,
        "excluded_dirs": plan.excluded_dirs,
        "partitions": [
            {
                "name": p.name,
                "path": p.path,
                "is_third_party": p.is_third_party,
                "estimated_files": p.estimated_files,
            }
            for p in plan.partitions
        ],
    }


@mcp.tool()
def cache_stats() -> dict[str, Any]:
    """Return parse cache size and entry count.

    The cache stores SHA256-indexed parse results so unchanged files
    are never re-parsed. Second index of the same codebase: <1 second."""
    from audit_mcp.fast_indexer import FastIndexer

    return FastIndexer().cache_stats()


@mcp.tool()
def clear_cache() -> dict[str, Any]:
    """Remove all cached parse results. Forces full re-parse on next index."""
    from audit_mcp.fast_indexer import FastIndexer

    count = FastIndexer().clear_cache()
    return {"status": "ok", "cleared_entries": count}


def run_mcp() -> None:
    """Run the MCP server over stdio."""
    mcp.run()
