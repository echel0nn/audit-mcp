"""Trailmark MCP server — code graph tools via FastMCP.

Wraps trailmark's :class:`QueryEngine` as MCP tools. Every analytical tool
requires an ``index_id`` returned by :func:`index_codebase`; until that index
reports ``status == "ready"`` the tool returns ``{"status": "pending", ...}``
so callers can poll without blocking.

Performance-optimised for large codebases (Chromium, Linux kernel, Android):
- All graph queries are bounded (depth, limit, offset, hub exclusion)
- Preanalysis is lazy (blast radius computed on demand, not eagerly)
- Heavy tools (dead_code, scanners) run async with poll-for-result
- export_graph is capped for large graphs

The same ``mcp`` and ``index_manager`` singletons are shared with the HTTP
transport so callers see one cache across both.
"""
from __future__ import annotations

import logging
import os
import re
from functools import partial
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from audit_mcp.indexer import IndexManager
from audit_mcp.query_bounds import (
    BoundedResult,
    QueryBounds,
    bounded_ancestors,
    bounded_callees,
    bounded_callers,
    bounded_paths,
    bounded_reachable,
    bounded_search,
)
from audit_mcp.tasks import TaskRunner

__all__ = ["mcp", "run_mcp", "index_manager", "task_runner"]

_log = logging.getLogger(__name__)

mcp = FastMCP("audit-mcp")
index_manager = IndexManager()
task_runner = TaskRunner()


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


def _gpu(index_id: str) -> Any:
    """Return the GpuGraphEngine for *index_id*, or None."""
    return index_manager.get_gpu_engine(index_id)


def _annotation_kind(kind: str) -> Any:
    """Resolve a string into the trailmark ``AnnotationKind`` enum."""
    from trailmark.models.annotations import AnnotationKind

    try:
        return AnnotationKind(kind)
    except ValueError as exc:
        valid = ", ".join(k.value for k in AnnotationKind)
        raise ValueError(f"Unknown annotation kind {kind!r}; valid: {valid}") from exc


def _bounded_envelope(result: BoundedResult, key: str) -> dict[str, Any]:
    """Turn a BoundedResult into a standard tool response envelope."""
    return {
        key: result.results,
        "total": result.total,
        "returned": result.returned,
        "truncated": result.truncated,
        "truncation_hint": result.truncation_hint,
    }


# ---------------------------------------------------------------------------
# Index lifecycle
# ---------------------------------------------------------------------------


_CLONE_DIR_DEFAULT = Path.home() / ".cache" / "audit-mcp" / "clones"
_CLONE_TIMEOUT_SECONDS = 600
_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _clone_dir() -> Path:
    root = Path(os.environ.get("AUDIT_MCP_CLONE_DIR") or _CLONE_DIR_DEFAULT)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _repo_slug(repo_url: str, ref: str | None) -> str:
    base = repo_url
    for prefix in ("https://", "http://", "git@", "ssh://"):
        if base.startswith(prefix):
            base = base[len(prefix):]
            break
    base = base.replace(":", "/").rstrip("/")
    if base.endswith(".git"):
        base = base[:-4]
    slug = _SAFE_NAME_RE.sub("_", base.replace("/", "_"))
    suffix = _SAFE_NAME_RE.sub("_", ref) if ref else "HEAD"
    return f"{slug}@{suffix}"


@mcp.tool()
def clone_repo(repo_url: str, ref: str = "") -> dict[str, Any]:
    """Shallow-clone ``repo_url`` into the MCP server's clone cache.

    The server owns the working tree — callers pass the returned ``path``
    straight into :func:`index_codebase`. Re-cloning the same (repo, ref)
    pair is idempotent: it does ``git fetch + checkout`` on the existing
    checkout instead of a fresh clone.

    Returns ``{"status": "ready", "path": "...", "repo_url": "...",
    "ref": "..."}`` on success, or ``{"status": "error", "error": "..."}``.
    Clone root defaults to ``~/.cache/audit-mcp/clones`` and is overridable
    via the ``AUDIT_MCP_CLONE_DIR`` env var.
    """
    import shutil
    import subprocess

    if not repo_url:
        return {"status": "error", "error": "repo_url required"}
    if not shutil.which("git"):
        return {"status": "error", "error": "git is not installed on the MCP server"}

    ref_clean = ref.strip() or None
    dest = _clone_dir() / _repo_slug(repo_url, ref_clean)

    try:
        if (dest / ".git").exists():
            subprocess.run(  # noqa: S603
                ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", ref_clean or "HEAD"],
                capture_output=True, check=True, timeout=_CLONE_TIMEOUT_SECONDS,
            )
            if ref_clean:
                subprocess.run(  # noqa: S603
                    ["git", "-C", str(dest), "checkout", "FETCH_HEAD"],
                    capture_output=True, check=True, timeout=_CLONE_TIMEOUT_SECONDS,
                )
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            cmd = ["git", "clone", "--depth", "1"]
            if ref_clean:
                cmd += ["--branch", ref_clean]
            cmd += [repo_url, str(dest)]
            subprocess.run(  # noqa: S603
                cmd, capture_output=True, check=True, timeout=_CLONE_TIMEOUT_SECONDS,
            )
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or b"").decode(errors="replace").strip()[:400]
        return {"status": "error", "error": f"git failed (exit {exc.returncode}): {err}"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"git timed out after {_CLONE_TIMEOUT_SECONDS}s"}

    return {
        "status": "ready",
        "path": str(dest),
        "repo_url": repo_url,
        "ref": ref_clean or "HEAD",
    }


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
# Graph queries — ALL bounded (depth, limit, offset, hub exclusion)
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
    """Return entrypoints, blast radius top-50, and privilege boundaries.

    Blast radius is computed lazily — first call may take a few seconds
    while the top-50 functions are analyzed.
    """
    from audit_mcp.lazy_preanalysis import LazyPreanalysis

    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    lazy = LazyPreanalysis(engine, gpu_engine=_gpu(index_id))
    return lazy.full_preanalysis()


@mcp.tool()
def callers_of(
    index_id: str,
    name: str,
    limit: int = 100,
    offset: int = 0,
    exclude_hubs: bool = True,
) -> dict[str, Any]:
    """Return direct callers of ``name``.

    High-in-degree functions (logging, utility) are excluded by default.
    Set ``exclude_hubs=False`` to include all callers."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    bounds = QueryBounds(limit=limit, offset=offset, exclude_hubs=exclude_hubs)
    result = bounded_callers(engine, name, bounds, gpu_engine=_gpu(index_id))
    return _bounded_envelope(result, "callers")


@mcp.tool()
def callees_of(
    index_id: str,
    name: str,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Return direct callees of ``name``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    bounds = QueryBounds(limit=limit, offset=offset, exclude_hubs=False)
    result = bounded_callees(engine, name, bounds, gpu_engine=_gpu(index_id))
    return _bounded_envelope(result, "callees")


@mcp.tool()
def ancestors_of(
    index_id: str,
    name: str,
    depth: int = 5,
    limit: int = 100,
    offset: int = 0,
    exclude_hubs: bool = True,
) -> dict[str, Any]:
    """Return functions that can transitively reach ``name``.

    Bounded by ``depth`` (max 20) and ``limit`` (max 5000).
    Hub functions (in-degree > 100) are excluded by default."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    bounds = QueryBounds(depth=depth, limit=limit, offset=offset, exclude_hubs=exclude_hubs)
    result = bounded_ancestors(engine, name, bounds, gpu_engine=_gpu(index_id))
    return _bounded_envelope(result, "ancestors")


@mcp.tool()
def reachable_from(
    index_id: str,
    name: str,
    depth: int = 5,
    limit: int = 100,
    offset: int = 0,
    exclude_hubs: bool = True,
) -> dict[str, Any]:
    """Return functions transitively reachable from ``name``.

    Bounded by ``depth`` (max 20) and ``limit`` (max 5000).
    Hub functions (in-degree > 100) are excluded by default."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    bounds = QueryBounds(depth=depth, limit=limit, offset=offset, exclude_hubs=exclude_hubs)
    result = bounded_reachable(engine, name, bounds, gpu_engine=_gpu(index_id))
    return _bounded_envelope(result, "reachable")


@mcp.tool()
def paths_between(
    index_id: str,
    source: str,
    target: str,
    depth: int = 10,
    limit: int = 5,
) -> dict[str, Any]:
    """Return call paths from ``source`` to ``target``.

    Returns at most ``limit`` shortest paths (default 5, max 5000).
    ``depth`` caps the max path length (default 10, max 20)."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    bounds = QueryBounds(depth=depth, limit=limit)
    result = bounded_paths(engine, source, target, bounds, max_paths=limit)
    return _bounded_envelope(result, "paths")


@mcp.tool()
def entrypoint_paths_to(
    index_id: str,
    name: str,
    max_depth: int = 20,
    limit: int = 10,
) -> dict[str, Any]:
    """Return call paths from any entrypoint to ``name``.

    Returns at most ``limit`` paths (default 10)."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    raw_paths = engine.entrypoint_paths_to(name, max_depth=max_depth)
    total = len(raw_paths) if isinstance(raw_paths, list) else 0
    capped = raw_paths[:limit] if isinstance(raw_paths, list) else raw_paths
    truncated = total > limit
    return {
        "paths": capped,
        "total": total,
        "returned": len(capped) if isinstance(capped, list) else 0,
        "truncated": truncated,
        "truncation_hint": f"Showing {limit} of {total} paths. Increase limit to see more." if truncated else "",
    }


@mcp.tool()
def attack_surface(index_id: str) -> dict[str, Any]:
    """Return entrypoints with their trust levels and asset values."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    return {"entrypoints": engine.attack_surface()}


@mcp.tool()
def complexity_hotspots(
    index_id: str,
    threshold: int = 10,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Return functions with cyclomatic complexity >= ``threshold``.

    Results are paginated. Blast radius is computed lazily per function."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    all_hotspots = engine.complexity_hotspots(threshold=threshold)
    total = len(all_hotspots) if isinstance(all_hotspots, list) else 0
    page = all_hotspots[offset:offset + limit] if isinstance(all_hotspots, list) else all_hotspots
    return {
        "hotspots": page,
        "total": total,
        "returned": len(page) if isinstance(page, list) else 0,
        "truncated": total > offset + limit,
    }


@mcp.tool()
def search_functions(
    index_id: str,
    pattern: str,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Regex-search function/method names in the graph (case-insensitive).

    Results are paginated via ``limit`` and ``offset``."""
    engine, err = _require_engine(index_id)
    if err is not None:
        return err
    bounds = QueryBounds(limit=limit, offset=offset)
    result = bounded_search(engine, pattern, bounds)
    return _bounded_envelope(result, "matches")


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


def _run_scanner_sync(
    index_id: str, scanner: str, timeout_seconds: int,
) -> dict[str, Any]:
    """Synchronous scanner execution — runs in a background thread."""
    from audit_mcp.scanners import ScannerRunner

    engine = index_manager.get_engine(index_id)
    if engine is None:
        return {"status": "error", "error": f"Engine not available for {index_id}"}
    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return {"status": "error", "error": f"Index {index_id!r} not found"}
    sarif_path = ScannerRunner.run(scanner, entry.root_path, timeout_seconds)
    import_result = engine.augment_sarif(str(sarif_path))
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


def _scan_and_correlate_sync(
    index_id: str, scanner: str, timeout_seconds: int,
) -> dict[str, Any]:
    """Synchronous scan + correlate — runs in a background thread."""
    from audit_mcp.scanners import ScannerRunner

    engine = index_manager.get_engine(index_id)
    if engine is None:
        return {"status": "error", "error": f"Engine not available for {index_id}"}
    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return {"status": "error", "error": f"Index {index_id!r} not found"}
    sarif_path = ScannerRunner.run(scanner, entry.root_path, timeout_seconds)
    engine.augment_sarif(str(sarif_path))
    try:
        sarif_path.unlink(missing_ok=True)
    except OSError:
        pass
    correlation = ScannerRunner.correlate_findings(engine, entry.preanalysis)
    return {
        "status": "ready",
        "scanner": scanner,
        "target": entry.root_path,
        **correlation,
    }


@mcp.tool()
def run_scanner(index_id: str, scanner: str, timeout_seconds: int = 600) -> dict[str, Any]:
    """Execute a SAST scanner on an indexed codebase (async).

    Returns a ``task_id`` immediately. Poll with :func:`poll_task`.
    Supported scanners: semgrep, bandit, trivy, bearer, gosec, phpstan.
    """
    engine, err = _require_engine(index_id)
    if err:
        return err
    task_id = task_runner.submit(
        kind="run_scanner",
        index_id=index_id,
        fn=partial(_run_scanner_sync, index_id, scanner, timeout_seconds),
    )
    return {"task_id": task_id, "status": "running", "kind": "run_scanner"}


@mcp.tool()
def scan_and_correlate(index_id: str, scanner: str, timeout_seconds: int = 600) -> dict[str, Any]:
    """Run a scanner, import results, and correlate with graph properties (async).

    Returns a ``task_id`` immediately. Poll with :func:`poll_task`.
    The killer query: 'semgrep found 47 SQLi. Of those, 12 are tainted
    from entrypoints. Of those, 3 have blast radius > 50. Start there.'
    """
    engine, err = _require_engine(index_id)
    if err:
        return err
    task_id = task_runner.submit(
        kind="scan_and_correlate",
        index_id=index_id,
        fn=partial(_scan_and_correlate_sync, index_id, scanner, timeout_seconds),
    )
    return {"task_id": task_id, "status": "running", "kind": "scan_and_correlate"}


# ---------------------------------------------------------------------------
# Exception + annotation queries
# ---------------------------------------------------------------------------


@mcp.tool()
def functions_that_raise(index_id: str, name: str) -> dict[str, Any]:
    exception_name = name
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
def export_graph(index_id: str, max_nodes: int = 10000) -> dict[str, Any]:
    """Export the code graph as JSON.

    Refuses graphs with more than ``max_nodes`` nodes to prevent
    multi-gigabyte responses. Use ``plan_partitions`` to split large
    codebases and export per-partition.
    """
    engine, err = _require_engine(index_id)
    if err:
        return err
    s = engine.summary()
    node_count = s.get("functions", 0) + s.get("classes", 0) + s.get("nodes", 0)
    if node_count > max_nodes:
        return {
            "status": "error",
            "error": (
                f"Graph has {node_count} nodes (cap: {max_nodes}). "
                "Use plan_partitions to split, or increase max_nodes."
            ),
            "node_count": node_count,
            "max_nodes": max_nodes,
        }
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
# Deep audit tools — async (return task_id, poll with poll_task)
# ---------------------------------------------------------------------------


def _dead_code_sync(index_id: str) -> dict[str, Any]:
    from audit_mcp.deep_audit import find_dead_code

    engine = index_manager.get_engine(index_id)
    if engine is None:
        return {"status": "error", "error": f"Engine not available for {index_id}"}
    return find_dead_code(engine, gpu_engine=index_manager.get_gpu_engine(index_id))


def _unreachable_sync(index_id: str) -> dict[str, Any]:
    from audit_mcp.deep_audit import find_unreachable_from_entrypoints

    engine = index_manager.get_engine(index_id)
    if engine is None:
        return {"status": "error", "error": f"Engine not available for {index_id}"}
    return find_unreachable_from_entrypoints(engine, gpu_engine=index_manager.get_gpu_engine(index_id))


@mcp.tool()
def dead_code(index_id: str) -> dict[str, Any]:
    """Find functions with zero callers that are not entrypoints (async).

    Returns a ``task_id`` immediately. Poll with :func:`poll_task`.
    Dead code = never called. Removing it reduces attack surface.
    """
    engine, err = _require_engine(index_id)
    if err:
        return err
    task_id = task_runner.submit(
        kind="dead_code", index_id=index_id,
        fn=partial(_dead_code_sync, index_id),
    )
    return {"task_id": task_id, "status": "running", "kind": "dead_code"}


@mcp.tool()
def unreachable_from_entrypoints(index_id: str) -> dict[str, Any]:
    """Find functions no external entrypoint can transitively reach (async).

    Returns a ``task_id`` immediately. Poll with :func:`poll_task`.
    Any SAST finding in these functions is lower priority — not exploitable
    by external attackers (unless dynamic dispatch bypasses static analysis).
    """
    engine, err = _require_engine(index_id)
    if err:
        return err
    task_id = task_runner.submit(
        kind="unreachable", index_id=index_id,
        fn=partial(_unreachable_sync, index_id),
    )
    return {"task_id": task_id, "status": "running", "kind": "unreachable"}


@mcp.tool()
def taint_paths_to(index_id: str, name: str, max_depth: int = 20) -> dict[str, Any]:
    sink_name = name
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
    return suggest_fuzzing_targets(engine, _gpu(index_id), min_complexity, limit)


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


# ---------------------------------------------------------------------------
# Task polling (for async tools: dead_code, scanners, unreachable)
# ---------------------------------------------------------------------------


@mcp.tool()
def poll_task(task_id: str) -> dict[str, Any]:
    """Poll the status of an async task. Returns result when completed."""
    return task_runner.poll(task_id)


@mcp.tool()
def list_tasks() -> dict[str, Any]:
    """Return all background tasks and their current status."""
    return {"tasks": task_runner.list_tasks()}


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------


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


@mcp.tool()
def memory_usage() -> dict[str, Any]:
    """Return engine memory stats: loaded engines, eviction count, budget.

    Use to monitor memory pressure when working with multiple large codebases.
    Engines are evicted LRU-style when the loaded count exceeds the budget
    (default 8, configurable via ``AUDIT_MCP_MAX_ENGINES`` env var).
    """
    return index_manager.memory_stats()



# ---------------------------------------------------------------------------
# Source-level search (constants, types, assertions, bitfields, macros, raw)
# ---------------------------------------------------------------------------


def _searcher(index_id: str) -> Any:
    """Return a SourceSearcher for the indexed codebase's root path."""
    from audit_mcp.source_search import SourceSearcher

    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return None
    return SourceSearcher(entry.root_path)


@mcp.tool()
def search_constants(index_id: str, pattern: str, limit: int = 50) -> dict[str, Any]:
    """Search constexpr, static const, and enum constants by regex.

    Finds the VALUES that control security boundaries — bit widths,
    max counts, buffer sizes, mask constants. These live outside the
    call graph and are invisible to search_functions."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    results = searcher.search_constants(pattern, limit=limit)
    return {"matches": [r.to_dict() for r in results], "count": len(results)}


@mcp.tool()
def search_types(index_id: str, pattern: str, limit: int = 50) -> dict[str, Any]:
    """Search using/typedef type aliases, class/struct/enum declarations.

    Finds type definitions that determine how values are stored — narrowing
    typedefs, bitfield type aliases, wrapper structs."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    results = searcher.search_types(pattern, limit=limit)
    return {"matches": [r.to_dict() for r in results], "count": len(results)}


@mcp.tool()
def search_assertions(index_id: str, pattern: str, limit: int = 50) -> dict[str, Any]:
    """Search static_assert, DCHECK, CHECK statements.

    Finds compile-time and runtime capacity checks. A missing static_assert
    on a bitfield is the CVE-2024-2887 pattern."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    results = searcher.search_assertions(pattern, limit=limit)
    return {"matches": [r.to_dict() for r in results], "count": len(results)}


@mcp.tool()
def search_bitfields(index_id: str, pattern: str = "", limit: int = 50) -> dict[str, Any]:
    """Search BitField<type, offset, size> declarations.

    Returns the bit width and max value for each field. Core tool for
    finding truncation bugs — a 20-bit field storing a value up to 1M
    is the exact CVE-2024-2887 pattern."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    results = searcher.search_bitfields(pattern, limit=limit)
    return {"matches": [r.to_dict() for r in results], "count": len(results)}


@mcp.tool()
def search_macros(index_id: str, pattern: str, limit: int = 50) -> dict[str, Any]:
    """Search #define macro definitions."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    results = searcher.search_macros(pattern, limit=limit)
    return {"matches": [r.to_dict() for r in results], "count": len(results)}


@mcp.tool()
def search_source(index_id: str, pattern: str, limit: int = 50) -> dict[str, Any]:
    """Raw regex search over source text — the escape hatch.

    Use when no structured search tool fits. Searches all C/C++ source
    and header files in the indexed codebase."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    results = searcher.search_source(pattern, limit=limit)
    return {"matches": [r.to_dict() for r in results], "count": len(results)}


@mcp.tool()
def search_narrowing_casts(index_id: str, pattern: str = "", limit: int = 50) -> dict[str, Any]:
    """Find static_cast to narrower integer types on size/index values.

    Integer overflow via narrowing cast is the CVE-2026-2649 pattern.
    Finds casts where a .size(), count, index, or length is truncated."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    results = searcher.search_narrowing_casts(pattern, limit=limit)
    return {"matches": [r.to_dict() for r in results], "count": len(results)}


@mcp.tool()
def extract_class(index_id: str, file_path: str, name: str) -> dict[str, Any]:
    class_name = name
    """Extract the full body of a class/struct from a source file.

    Returns the complete class declaration with all members and methods.
    Use when search_types finds a class and you need its full definition."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    result = searcher.extract_class(file_path, class_name)
    if result is None:
        return {"status": "error", "error": f"Class {class_name!r} not found in {file_path}"}
    return result


@mcp.tool()
def read_function(index_id: str, file_path: str, name: str) -> dict[str, Any]:
    function_name = name
    """Extract the full body of a function/method from a source file.

    Fast path (semble): query the semble chunk index for chunks
    matching ``function_name`` inside ``file_path``. Returns instantly
    (<5 ms) regardless of repo size — no per-call re-indexing.

    Slow path (TypeResolver fallback): when semble is unavailable OR
    the semble chunk doesn't contain the function (e.g. minified /
    macro-defined / wrapper-defined functions), fall back to the
    AST-only resolver. Previously this fallback was the ONLY path,
    and on firefox-scale repos it re-indexed 250k files per call
    (>15 min) — that's the bug investigation 417b469f tripped.
    """
    # ── Fast path: semble chunk lookup ────────────────────────────
    sidx = index_manager.get_semble_index(index_id)
    if sidx is not None and function_name:
        try:
            hits = sidx.search(
                function_name,
                top_k=20,
                filter_paths=[file_path] if file_path else None,
            )
        except (ValueError, RuntimeError):
            hits = []
        for r in hits:
            c = r.chunk
            content = c.content or ""
            # Confirm the chunk actually defines/declares the requested
            # function — avoids returning a chunk that just MENTIONS
            # the name in a comment or call site. We check for common
            # definition patterns rather than relying on tree-sitter
            # node kind (semble doesn't expose it).
            patterns = (
                f"{function_name}(",         # most C/C++/JS/Py
                f" {function_name} (",       # spaced
                f"::{function_name}(",        # C++ method
                f".{function_name}(",         # JS/Py method
                f"def {function_name}(",      # Python def
                f"function {function_name}(", # JS function
                f"fn {function_name}(",       # Rust
                f"func {function_name}(",     # Go
            )
            if any(p in content for p in patterns):
                return {
                    "file_path": c.file_path,
                    "name": function_name,
                    "line": c.start_line,
                    "end_line": c.end_line,
                    "language": c.language,
                    "content": content,
                    "source": "semble",
                }

    # ── Slow path: AST resolver ───────────────────────────────────
    # Only reached when semble didn't find a confirming chunk. On
    # huge functions (cyc > 500 / spans > 2000 lines) this can still
    # take minutes — the caller (AILA bridge) should set a generous
    # timeout, and we keep a single shared TypeResolver per index_id
    # to avoid the per-call re-index regression that used to hang the
    # whole server.
    from audit_mcp.type_resolver import TypeResolver

    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}

    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return {"status": "error", "error": f"Index {index_id!r} has no root path"}

    # Cache the resolver on the entry so we don't re-walk the tree
    # 250k times for firefox. The slot is intentionally added at
    # runtime (no dataclass field) so we don't break recovery paths.
    resolver = getattr(entry, "_type_resolver", None)
    if resolver is None:
        resolver = TypeResolver(entry.root_path)
        resolver.index()
        entry._type_resolver = resolver  # noqa: SLF001
    candidates = resolver.type_table.lookup_function(function_name)
    if not candidates:
        return {
            "status": "error",
            "error": f"Function {function_name!r} not indexed. Try search_functions or semantic_search.",
        }

    chosen = None
    if file_path:
        needle = file_path.replace("\\", "/")
        for c in candidates:
            if needle in c.file_path.replace("\\", "/"):
                chosen = c
                break
    if chosen is None:
        chosen = candidates[0]

    extracted = searcher.read_function_at(chosen.file_path, chosen.line, function_name)
    if extracted is None:
        return {
            "status": "error",
            "error": f"Indexed location for {function_name!r} unreadable: {chosen.file_path}:{chosen.line}",
        }
    if len(candidates) > 1:
        extracted["other_definitions"] = [
            {"file_path": c.file_path, "line": c.line, "qualified_name": c.qualified_name}
            for c in candidates if c is not chosen
        ]
    extracted["source"] = "type_resolver"
    return extracted


@mcp.tool()
def cross_reference_bitfields(index_id: str) -> dict[str, Any]:
    """Cross-reference BitField declarations against static_assert checks.

    The core variant detection tool. For each BitField >= 10 bits, finds
    the related kMax constant, checks if a static_assert connects them,
    and computes the overflow margin. Returns findings sorted by risk."""
    searcher = _searcher(index_id)
    if searcher is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    findings = searcher.cross_reference_bitfields()
    return {"findings": findings, "count": len(findings)}


@mcp.tool()
def children_of(index_id: str, name: str) -> dict[str, Any]:
    class_name = name
    """Find all classes that inherit from a given class (direct + transitive).

    Uses the type resolver's inheritance graph. Requires index built with
    type resolution enabled."""
    from audit_mcp.type_resolver import TypeResolver

    engine, err = _require_engine(index_id)
    if err:
        return err
    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    resolver = TypeResolver(entry.root_path)
    resolver.index()
    children = resolver.type_table.children_of(class_name)
    return {"class": class_name, "children": children, "count": len(children)}


@mcp.tool()
def includers_of(index_id: str, file_path: str) -> dict[str, Any]:
    """Find all files that transitively include a given header.

    Uses the include graph from the type resolver. Scopes the attack
    surface — every file that includes a vulnerable header is affected."""
    from audit_mcp.type_resolver import TypeResolver

    entry = index_manager._indexes.get(index_id)  # noqa: SLF001
    if entry is None:
        return {"status": "error", "error": f"Unknown index: {index_id}"}
    resolver = TypeResolver(entry.root_path)
    resolver.index()
    includers = resolver.include_graph.includers_of(file_path)
    return {
        "file": file_path,
        "includers": sorted(includers),
        "count": len(includers),
    }



# ---------------------------------------------------------------------------
# Browser testing (headless Chrome/Firefox for PoC validation)
# ---------------------------------------------------------------------------


@mcp.tool()
def test_in_browser(
    html: str,
    timeout_seconds: int = 30,
    browser: str = "auto",
) -> dict[str, Any]:
    """Execute HTML/JS in headless Chrome or Firefox and return results.

    Serves the HTML via a local HTTP server with COOP/COEP headers
    (for SharedArrayBuffer support). Captures console.log output,
    detects crashes (STATUS_BREAKPOINT, ACCESS_VIOLATION, SIGABRT),
    and reports timing.

    ``browser``: ``"chrome"``, ``"firefox"``, or ``"auto"`` (try Chrome first).

    Returns: console lines, errors, crash status, exit code, elapsed time.
    """
    from audit_mcp.browser_test import BrowserTestRunner

    runner = BrowserTestRunner(browser=browser)
    if not runner.available():
        return {"status": "error", "error": "No browser found", **runner.info()}
    result = runner.run(html, timeout_seconds=timeout_seconds, browser=browser)
    return result.to_dict()


@mcp.tool()
def browser_info() -> dict[str, Any]:
    """Check which browsers are available for test_in_browser."""
    from audit_mcp.browser_test import BrowserTestRunner

    chrome = BrowserTestRunner(browser="chrome")
    firefox = BrowserTestRunner(browser="firefox")
    return {
        "chrome": chrome.info(),
        "firefox": firefox.info(),
    }


@mcp.tool()
def fuzz_generators(
    iterations: int = 50,
    timeout_per_test: int = 15,
    seed: int | None = None,
    browser: str = "auto",
) -> dict[str, Any]:
    """Fuzz async/sync generator edge cases in headless browser.

    Generates randomized generator functions varying yield* count,
    iterator overrides, .done getters, try/finally, queue flooding,
    TypedArray interactions, and cross-delegation patterns.

    Returns crash count, interesting findings, and timing."""
    from audit_mcp.generator_fuzzer import GeneratorFuzzer

    fuzzer = GeneratorFuzzer(browser=browser, seed=seed)
    if not fuzzer.available():
        return {"status": "error", "error": "No browser available"}
    result = fuzzer.fuzz(iterations=iterations, timeout_per_test=timeout_per_test)
    return result.to_dict()
@mcp.tool()
def semantic_search(
    index_id: str,
    query: str,
    top_k: int = 10,
    alpha: float | None = None,
    rerank: bool = True,
    filter_languages: list[str] | None = None,
    filter_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Natural-language / hybrid code search via semble (Model2Vec + BM25 + RRF).

    Returns the top-k code chunks semantically + lexically matching the
    query. Each chunk is a code-aware tree-sitter slice — not a file:line
    snippet — so the agent gets enough context in one shot.

    Parameters:
      query: natural language ("how is HTTP/2 framed") OR identifier
        ("ngx_http_v2_parse"). Both work; the reranker auto-adapts.
      top_k: max chunks to return (default 10).
      alpha: 0.0..1.0 — bias toward BM25 (1.0) or embedding (0.0). None
        = adaptive (recommended). Use >=0.8 for exact-identifier
        queries; <=0.3 for pure semantic intent.
      rerank: enable code-aware reranking (definition boost, identifier
        stems, file coherence, noise penalty). Off = ~30% faster but
        misses canonical-definition prioritization.
      filter_languages: restrict results to e.g. ["c", "cpp"].
      filter_paths: restrict to specific file paths.

    Use this for "find code that does X" / "where is Y handled". Use
    callers_of / taint_paths_to / read_function for graph-aware drill-in.

    Cold first-call builds the semble index lazily (~250 ms nginx /
    ~13 s firefox); warm queries are ~200 ms through MCP HTTP (~5 ms
    in-process).
    """
    sidx = index_manager.get_semble_index(index_id)
    if sidx is None:
        return {
            "status": "error",
            "error": (
                f"semble index for {index_id!r} unavailable (install "
                "`semble` + `model2vec` to enable, or check index is ready)"
            ),
        }
    try:
        kwargs: dict[str, Any] = {
            "top_k": top_k,
            "rerank": rerank,
            "filter_languages": filter_languages,
            "filter_paths": filter_paths,
        }
        if alpha is not None:
            kwargs["alpha"] = alpha
        results = sidx.search(query, **kwargs)
    except (ValueError, RuntimeError) as exc:
        return {"status": "error", "error": f"semble.search failed: {exc}"}
    chunks = []
    for r in results:
        c = r.chunk
        chunks.append({
            "file_path": c.file_path,
            "start_line": c.start_line,
            "end_line": c.end_line,
            "language": c.language,
            "content": c.content,
            "score": float(r.score),
        })
    return {
        "status": "ready",
        "query": query,
        "results": chunks,
        "count": len(chunks),
        "alpha": alpha,
        "rerank": rerank,
    }


@mcp.tool()
def find_related(
    index_id: str,
    file_path: str,
    line: int,
    top_k: int = 5,
) -> dict[str, Any]:
    """Find code semantically similar to the chunk at (file_path, line).

    Pass file_path + line from a prior search/read result. Returns the
    top-k chunks whose embeddings are nearest to the source chunk —
    useful for "show me other places that look like this" / pattern
    expansion / variant hunting.
    """
    sidx = index_manager.get_semble_index(index_id)
    if sidx is None:
        return {
            "status": "error",
            "error": f"semble index for {index_id!r} unavailable",
        }
    # Locate a source chunk overlapping the requested (file, line).
    # semble's search itself doubles as a chunk lookup when we filter
    # by path; we then pick whichever chunk contains the requested line.
    try:
        candidates = sidx.search(
            file_path,  # query = filename, biases retrieval to chunks in that file
            top_k=50,
            filter_paths=[file_path],
        )
    except (ValueError, RuntimeError) as exc:
        return {"status": "error", "error": f"semble.search seed failed: {exc}"}
    seed = None
    for r in candidates:
        c = r.chunk
        if c.file_path.replace("\\", "/").endswith(file_path.replace("\\", "/")) and (
            c.start_line <= line <= c.end_line
        ):
            seed = r
            break
    if seed is None and candidates:
        seed = candidates[0]  # best file-match if no line-overlap
    if seed is None:
        return {
            "status": "error",
            "error": f"no chunk found at {file_path}:{line}",
        }
    try:
        related = sidx.find_related(seed, top_k=top_k)
    except (ValueError, RuntimeError) as exc:
        return {"status": "error", "error": f"semble.find_related failed: {exc}"}
    chunks = []
    for r in related:
        c = r.chunk
        chunks.append({
            "file_path": c.file_path,
            "start_line": c.start_line,
            "end_line": c.end_line,
            "language": c.language,
            "content": c.content,
            "score": float(r.score),
        })
    return {
        "status": "ready",
        "seed": {
            "file_path": seed.chunk.file_path,
            "start_line": seed.chunk.start_line,
            "end_line": seed.chunk.end_line,
        },
        "results": chunks,
        "count": len(chunks),
    }


@mcp.tool()
def semble_stats(index_id: str) -> dict[str, Any]:
    """Return semble index statistics for ``index_id``.

    Useful for observability — how many chunks, total bytes indexed,
    languages present, average chunk size. Triggers a lazy semble
    build if the index hasn't been queried yet.
    """
    sidx = index_manager.get_semble_index(index_id)
    if sidx is None:
        return {
            "status": "error",
            "error": f"semble index for {index_id!r} unavailable",
        }
    try:
        s = sidx.stats()
    except (AttributeError, RuntimeError) as exc:
        return {"status": "error", "error": f"semble.stats() failed: {exc}"}
    # IndexStats dataclass → dict; field set varies by semble version
    # so we pull known attrs defensively and fall through to repr.
    out: dict[str, Any] = {"status": "ready"}
    for field in (
        "chunks", "files", "bytes", "languages", "avg_chunk_size",
        "embedding_dim", "vocab_size", "build_time_ms",
    ):
        if hasattr(s, field):
            v = getattr(s, field)
            try:
                out[field] = (
                    list(v) if isinstance(v, (set, tuple)) else v
                )
            except (TypeError, ValueError):
                out[field] = repr(v)
    if len(out) == 1:  # nothing matched the known field set
        out["raw"] = repr(s)
    return out


def run_mcp() -> None:
    """Run the MCP server over stdio."""
    mcp.run()
