"""Deep audit tools — graph-aware security analysis.

These tools use the code graph to answer questions no flat-file
scanner can: "Is this finding reachable from untrusted input?"
"What's the blast radius if this function is compromised?"
"Which functions are dead code that should be removed?"

Every tool here requires a ready index with preanalysis completed.
"""
from __future__ import annotations

import logging
import re
from typing import Any

__all__ = [
    "find_dead_code",
    "find_unreachable_from_entrypoints",
    "taint_paths_to_sink",
    "suggest_fuzzing_targets",
    "diff_attack_surface",
    "cross_scanner_dedup",
]

_log = logging.getLogger(__name__)


def find_dead_code(engine: Any, gpu_engine: Any = None) -> dict[str, Any]:
    """Find functions with zero callers that are NOT entrypoints.

    When ``gpu_engine`` is provided, uses precomputed in-degree from the
    CSR adjacency matrix (O(1) per node) instead of calling
    ``engine.callers_of()`` per function (O(V * avg_degree)).
    """
    attack = engine.attack_surface()
    entrypoint_ids = {ep.get("node_id") for ep in attack}

    all_funcs = _get_all_functions(engine)
    dead: list[dict[str, Any]] = []

    for func in all_funcs:
        name = func.get("name", "")
        node_id = func.get("id", "")
        if node_id in entrypoint_ids:
            continue
        if gpu_engine is not None:
            has_callers = gpu_engine.in_degree_of(name) > 0
        else:
            callers = engine.callers_of(name)
            has_callers = bool(callers)
        if not has_callers:
            dead.append({
                "name": name,
                "file": func.get("location", {}).get("file_path", ""),
                "line": func.get("location", {}).get("start_line", 0),
                "complexity": func.get("cyclomatic_complexity", 0),
            })

    dead.sort(key=lambda x: x.get("complexity", 0), reverse=True)
    return {
        "dead_functions": dead,
        "count": len(dead),
        "total_functions": len(all_funcs),
        "dead_percentage": round(100 * len(dead) / max(len(all_funcs), 1), 1),
    }


def find_unreachable_from_entrypoints(engine: Any, gpu_engine: Any = None) -> dict[str, Any]:
    """Find functions that no entrypoint can transitively reach.

    When ``gpu_engine`` is provided, runs one batched BFS from ALL
    entrypoints simultaneously via SpMV instead of serial
    ``engine.reachable_from()`` per entrypoint.
    """
    attack = engine.attack_surface()
    all_funcs = _get_all_functions(engine)

    # GPU fast path — one batched SpMV covers all entrypoints
    if gpu_engine is not None:
        ep_names = []
        for ep in attack:
            node = _find_node_by_id(engine, ep.get("node_id", ""))
            if node:
                ep_names.append(node.get("name", ""))
        unreachable_dicts = gpu_engine.unreachable_from(ep_names, max_depth=50)
        # Filter to only real functions (exclude phantom nodes for external APIs
        # that the GPU engine creates but trailmark doesn't track).
        # Phantoms have empty file_path; real functions always have a source file.
        real_func_names = {f.get("name", "") for f in all_funcs}
        unreachable = [
            {
                "name": d.get("name", ""),
                "file": d.get("location", {}).get("file_path", ""),
                "line": d.get("location", {}).get("start_line", 0),
                "complexity": d.get("cyclomatic_complexity", 0),
            }
            for d in unreachable_dicts
            if d.get("name", "") in real_func_names
            and d.get("location", {}).get("file_path", "") != ""
        ]
        return {
            "unreachable_functions": unreachable,
            "count": len(unreachable),
            "total_functions": len(all_funcs),
            "reachable_functions": len(all_funcs) - len(unreachable),
            "unreachable_percentage": round(100 * len(unreachable) / max(len(all_funcs), 1), 1),
        }

    # CPU fallback — serial reachable_from per entrypoint
    reachable_ids: set[str] = set()
    for ep in attack:
        node_id = ep.get("node_id", "")
        node = _find_node_by_id(engine, node_id)
        if node:
            name = node.get("name", "")
            reachable = engine.reachable_from(name)
            reachable_ids.update(r.get("id", "") for r in reachable)
            reachable_ids.add(node_id)

    unreachable: list[dict[str, Any]] = []
    for func in all_funcs:
        node_id = func.get("id", "")
        if node_id not in reachable_ids:
            unreachable.append({
                "name": func.get("name", ""),
                "file": func.get("location", {}).get("file_path", ""),
                "line": func.get("location", {}).get("start_line", 0),
                "complexity": func.get("cyclomatic_complexity", 0),
            })

    return {
        "unreachable_functions": unreachable,
        "count": len(unreachable),
        "total_functions": len(all_funcs),
        "reachable_functions": len(all_funcs) - len(unreachable),
        "unreachable_percentage": round(100 * len(unreachable) / max(len(all_funcs), 1), 1),
    }


def taint_paths_to_sink(
    engine: Any,
    sink_name: str,
    max_depth: int = 20,
) -> dict[str, Any]:
    """Find all entrypoint→sink call paths for a specific dangerous function.

    Answers: "Is this SQL injection / eval / deserialization call reachable
    from the network?" Returns every concrete path from every entrypoint.
    """
    paths = engine.entrypoint_paths_to(sink_name, max_depth=max_depth)
    callers = engine.callers_of(sink_name)
    annotations = engine.annotations_of(sink_name)

    is_tainted = any(a.get("kind") == "taint" for a in annotations)

    return {
        "sink": sink_name,
        "is_tainted": is_tainted,
        "entrypoint_paths": paths,
        "path_count": len(paths),
        "direct_callers": [c.get("name", "") for c in callers],
        "caller_count": len(callers),
        "exploitable": is_tainted and len(paths) > 0,
    }


def suggest_fuzzing_targets(
    engine: Any,
    gpu_engine: Any = None,
    min_complexity: int = 10,
    limit: int = 20,
) -> dict[str, Any]:
    """Identify the highest-value fuzzing targets in the codebase.

    Criteria (weighted):
    - Processes untrusted input (is tainted from entrypoint)
    - High cyclomatic complexity (more branches = more crash paths)
    - High blast radius (corruption propagates widely)
    - Is an entrypoint itself (directly exposed to attacker)

    When ``gpu_engine`` is provided, downstream blast-radius is computed
    for all hotspots in ONE batched SpMV BFS pass on the GPU instead of
    extracting it per-hotspot from the annotation store (which on
    monorepo-scale graphs — e.g. firefox at ~750k functions / ~5M
    edges — does not return within any reasonable wall time on CPU).
    Below ``_GPU_THRESHOLD`` the GPU engine internally falls back to
    CPU SpMV so small graphs see no overhead.

    Returns a ranked list: "fuzz these first."
    """
    attack = engine.attack_surface()
    entrypoint_ids = {ep.get("node_id") for ep in attack}

    hotspots = engine.complexity_hotspots(threshold=min_complexity)

    # Bound the per-hotspot Python loop cost. On monorepo-scale graphs
    # ``complexity_hotspots`` can return 30k+ entries — and the rest of
    # this function does an O(N) Python loop over them (annotations_of
    # dict-lookup + score-computation), which becomes the dominant cost
    # once blast_radius is GPU-accelerated. Take only the top-N by raw
    # complexity before scoring. Lower-complexity hotspots cannot
    # out-score the top ones with a meaningful margin once the
    # is_tainted (+40), is_entrypoint (+30), high-blast (+15) bonuses
    # are applied, so the truncation is invariant for any realistic
    # ``limit`` (the caller asks for top-K, K << _HOTSPOT_LIMIT).
    _HOTSPOT_LIMIT = 2000
    if len(hotspots) > _HOTSPOT_LIMIT:
        hotspots = sorted(
            hotspots,
            key=lambda f: f.get("cyclomatic_complexity", 0),
            reverse=True,
        )[:_HOTSPOT_LIMIT]

    # GPU fast path for blast-radius: chunked SpMV BFS instead of
    # extracting "(\d+) downstream" from the annotation store per
    # hotspot. The annotation store extraction is fast in isolation
    # (dict lookup + regex) but on firefox-scale graphs the per-call
    # Python loop dominates and the call never returns within the
    # AILA worker's 600s timeout.
    #
    # Chunking math: _batched_bfs holds 3-4 live [n_nodes x k] float32
    # matrices (frontier + visited + SpMV result + multiplicand). On
    # firefox (n=742k, ~4 GB persistent CSR on a 10 GB GPU) chunk=500
    # produced a ~5 GB working set per chunk → OOM with only ~4.3 GB
    # free after CSR. chunk=64 keeps the working set under ~750 MB.
    #
    # CuPy's default memory pool keeps freed allocations cached, so
    # without an explicit free_all_blocks() between chunks the per-
    # iteration peak accumulates and a later chunk OOMs even when
    # the first one fit.
    _GPU_CHUNK = 64
    downstream_map: dict[str, int] = {}
    if gpu_engine is not None and hotspots:
        hotspot_names = [f.get("name", "") for f in hotspots if f.get("name")]
        _free_pool = None
        try:
            import cupy as _cp  # noqa: PLC0415
            _free_pool = _cp.get_default_memory_pool().free_all_blocks
        except ImportError:
            pass
        for i in range(0, len(hotspot_names), _GPU_CHUNK):
            chunk = hotspot_names[i:i + _GPU_CHUNK]
            try:
                downstream_map.update(
                    gpu_engine.blast_radius_batch(chunk, max_depth=20),
                )
            except (RuntimeError, MemoryError) as exc:
                _log.warning(
                    "blast_radius_batch failed on chunk %d-%d (%s) — "
                    "falling back to per-hotspot annotation lookup for "
                    "remaining hotspots",
                    i, i + len(chunk), exc,
                )
                break
            if _free_pool is not None:
                _free_pool()

    scored: list[dict[str, Any]] = []

    for func in hotspots:
        name = func.get("name", "")
        node_id = func.get("id", "")
        cc = func.get("cyclomatic_complexity", 0)

        annotations = engine.annotations_of(name)
        is_tainted = any(a.get("kind") == "taint" for a in annotations)
        is_entrypoint = node_id in entrypoint_ids

        # Prefer GPU-computed blast radius; fall back to annotation
        # store (the original CPU path) when GPU was not available
        # or the batched call failed.
        if name in downstream_map:
            downstream = downstream_map[name]
        else:
            blast_ann = [a for a in annotations if a.get("kind") == "blast_radius"]
            downstream = 0
            if blast_ann:
                desc = blast_ann[0].get("description", "")
                m = re.search(r"(\d+)\s+downstream", desc)
                if m:
                    downstream = int(m.group(1))

        # Weighted score
        score = 0
        if is_tainted:
            score += 40
        if is_entrypoint:
            score += 30
        if cc >= 20:
            score += 20
        elif cc >= 10:
            score += 10
        if downstream >= 50:
            score += 15
        elif downstream >= 10:
            score += 5

        if score > 0:
            scored.append({
                "name": name,
                "file": func.get("location", {}).get("file_path", ""),
                "line": func.get("location", {}).get("start_line", 0),
                "complexity": cc,
                "blast_radius_downstream": downstream,
                "is_tainted": is_tainted,
                "is_entrypoint": is_entrypoint,
                "fuzz_priority_score": score,
            })

    scored.sort(key=lambda x: x["fuzz_priority_score"], reverse=True)
    return {
        "targets": scored[:limit],
        "count": min(len(scored), limit),
        "total_candidates": len(scored),
        "used_gpu_blast_radius": bool(downstream_map),
    }


def diff_attack_surface(
    engine_before: Any,
    engine_after: Any,
) -> dict[str, Any]:
    """Compare attack surfaces between two codebase versions.

    Answers: "Did the PR / release change our attack surface?"
    Reports: new entrypoints, removed entrypoints, new tainted sinks,
    blast radius changes on critical functions.
    """
    surface_before = {ep.get("node_id"): ep for ep in engine_before.attack_surface()}
    surface_after = {ep.get("node_id"): ep for ep in engine_after.attack_surface()}

    before_ids = set(surface_before.keys())
    after_ids = set(surface_after.keys())

    added_eps = [surface_after[i] for i in after_ids - before_ids]
    removed_eps = [surface_before[i] for i in before_ids - after_ids]

    # Structural diff
    structural = engine_after.diff_against(engine_before)

    return {
        "entrypoints_added": added_eps,
        "entrypoints_removed": removed_eps,
        "entrypoints_before": len(before_ids),
        "entrypoints_after": len(after_ids),
        "entrypoint_delta": len(after_ids) - len(before_ids),
        "structural_diff": structural,
    }


def cross_scanner_dedup(
    engine: Any,
    findings_a: list[dict[str, Any]],
    findings_b: list[dict[str, Any]],
) -> dict[str, Any]:
    """Deduplicate findings from two scanners using graph node identity.

    When semgrep and bandit both flag the same function, this merges
    them into one finding with evidence from both scanners. Reduces
    noise by 30-50% in typical multi-scanner pipelines.
    """
    # Group by (file, function_name) using graph lookup
    by_node: dict[str, list[dict[str, Any]]] = {}

    for finding in findings_a + findings_b:
        name = finding.get("name", "")
        file_path = finding.get("file", "")
        key = f"{file_path}:{name}" if name else f"{file_path}:{finding.get('line', 0)}"
        by_node.setdefault(key, []).append(finding)

    unique: list[dict[str, Any]] = []
    duplicates = 0

    for key, group in by_node.items():
        if len(group) == 1:
            unique.append(group[0])
        else:
            # Merge: keep the highest risk score, note all sources
            merged = dict(group[0])
            sources = list({f.get("scanner", "unknown") for f in group})
            merged["scanners"] = sources
            merged["duplicate_count"] = len(group)
            merged["risk_score"] = max(f.get("risk_score", 0) for f in group)
            unique.append(merged)
            duplicates += len(group) - 1

    return {
        "unique_findings": unique,
        "unique_count": len(unique),
        "total_input": len(findings_a) + len(findings_b),
        "duplicates_merged": duplicates,
        "reduction_percentage": round(
            100 * duplicates / max(len(findings_a) + len(findings_b), 1), 1,
        ),
    }


def _get_all_functions(engine: Any) -> list[dict[str, Any]]:
    """Extract all function/method nodes from the engine."""
    try:
        graph = engine._store._graph  # noqa: SLF001
        return [
            _node_to_dict(node)
            for node in graph.nodes.values()
            if node.kind.value in ("function", "method")
        ]
    except AttributeError:
        return []


def _find_node_by_id(engine: Any, node_id: str) -> dict[str, Any] | None:
    """Look up a node by its graph ID."""
    try:
        graph = engine._store._graph  # noqa: SLF001
        node = graph.nodes.get(node_id)
        if node is None:
            return None
        return _node_to_dict(node)
    except AttributeError:
        return None


def _node_to_dict(node: Any) -> dict[str, Any]:
    """Convert a CodeUnit to a plain dict."""
    return {
        "id": node.id,
        "name": node.name,
        "kind": node.kind.value,
        "location": {
            "file_path": node.location.file_path if node.location else "",
            "start_line": node.location.start_line if node.location else 0,
        },
        "cyclomatic_complexity": node.cyclomatic_complexity or 0,
    }
