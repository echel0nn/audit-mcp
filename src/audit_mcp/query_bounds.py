"""Bounded graph query wrappers — safety layer for large codebases.

These wrappers cap traversal depth, result size, and skip "hub" nodes (very
high in-degree) to keep memory and latency bounded on graphs with millions of
edges. Every wrapper returns a :class:`BoundedResult` carrying the truncation
state, so callers can surface paging or "narrow your query" hints to the user.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

__all__ = [
    "QueryBounds",
    "BoundedResult",
    "clamp_bounds",
    "hub_set",
    "bounded_callers",
    "bounded_callees",
    "bounded_ancestors",
    "bounded_reachable",
    "bounded_paths",
    "bounded_search",
    "HARD_DEPTH_CAP",
    "HARD_LIMIT_CAP",
]


HARD_DEPTH_CAP: int = 20
HARD_LIMIT_CAP: int = 5000

_FUNCTION_KINDS: frozenset[str] = frozenset({"function", "method"})


@dataclass(frozen=True, slots=True)
class QueryBounds:
    """Caller-supplied limits applied to a single bounded query."""

    depth: int = 5
    limit: int = 100
    offset: int = 0
    exclude_hubs: bool = True
    hub_threshold: int = 100


@dataclass(slots=True)
class BoundedResult:
    """Result of a bounded query with paging and truncation metadata."""

    results: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    returned: int = 0
    truncated: bool = False
    truncation_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "results": self.results,
            "total": self.total,
            "returned": self.returned,
            "truncated": self.truncated,
            "truncation_hint": self.truncation_hint,
        }


def clamp_bounds(bounds: QueryBounds) -> QueryBounds:
    """Clamp user-supplied bounds against the hard process-wide caps."""
    depth = max(0, min(bounds.depth, HARD_DEPTH_CAP))
    limit = max(1, min(bounds.limit, HARD_LIMIT_CAP))
    offset = max(0, bounds.offset)
    hub_threshold = max(1, bounds.hub_threshold)
    return QueryBounds(
        depth=depth,
        limit=limit,
        offset=offset,
        exclude_hubs=bounds.exclude_hubs,
        hub_threshold=hub_threshold,
    )


def _iter_function_nodes(engine: Any) -> list[Any]:
    """Return all function/method CodeUnit nodes from the engine's graph.

    Accesses the internal ``_store._graph.nodes`` mapping; if the engine does
    not expose it we return an empty list rather than raise — the caller will
    simply get a degenerate hub set / empty search result.
    """
    try:
        nodes = engine._store._graph.nodes
    except AttributeError:
        return []
    out: list[Any] = []
    for node in nodes.values():
        kind = getattr(node, "kind", None)
        kind_value = getattr(kind, "value", kind)
        if kind_value in _FUNCTION_KINDS:
            out.append(node)
    return out


@lru_cache(maxsize=64)
def _hub_set_cached(engine_id: int, threshold: int, engine_ref: Any) -> frozenset[str]:
    """Internal lru_cache-backed hub computation.

    Builds an in-degree map from the graph's edge list in a single pass —
    O(E) instead of the previous O(V * callers_of) which was catastrophically
    slow on large codebases (82s on Chromium's 29K functions).
    """
    del engine_id  # purely a cache key

    # Build in-degree map from the edge list directly.
    in_degree: dict[str, int] = {}
    try:
        edges = engine_ref._store._graph.edges
    except AttributeError:
        return frozenset()

    # Collect names of function/method nodes for filtering.
    func_names: set[str] = set()
    node_id_to_name: dict[str, str] = {}
    for node in _iter_function_nodes(engine_ref):
        name = getattr(node, "name", None)
        nid = getattr(node, "id", None)
        if name:
            func_names.add(name)
        if nid and name:
            node_id_to_name[nid] = name

    # Count in-degree from call edges.
    for edge in edges:
        kind = getattr(edge, "kind", None)
        kind_value = getattr(kind, "value", kind)
        if kind_value != "call":
            continue
        target_id = getattr(edge, "target_id", None)
        if target_id is None:
            continue
        target_name = node_id_to_name.get(target_id)
        if target_name:
            in_degree[target_name] = in_degree.get(target_name, 0) + 1

    hubs = frozenset(name for name, deg in in_degree.items() if deg > threshold)
    return hubs


def hub_set(engine: Any, threshold: int) -> frozenset[str]:
    """Return the set of function/method names whose in-degree exceeds *threshold*.

    The result is cached per ``(id(engine), threshold)`` pair so repeated
    queries against the same engine reuse the scan.
    """
    return _hub_set_cached(id(engine), threshold, engine)


def _filter_and_page(
    items: list[dict[str, Any]],
    bounds: QueryBounds,
    hubs: frozenset[str],
) -> BoundedResult:
    """Apply hub exclusion + offset/limit paging to a list of result dicts."""
    if bounds.exclude_hubs and hubs:
        filtered = [item for item in items if item.get("name") not in hubs]
    else:
        filtered = list(items)

    total = len(filtered)
    start = bounds.offset
    end = start + bounds.limit
    page = filtered[start:end]
    returned = len(page)
    truncated = end < total or start > 0
    hint = ""
    if truncated:
        if end < total:
            hint = (
                f"showing {start}..{start + returned} of {total}; "
                f"raise offset to {end} for next page or narrow the query"
            )
        else:
            hint = f"offset {start} > 0; {total} total results available"
    return BoundedResult(
        results=page,
        total=total,
        returned=returned,
        truncated=truncated,
        truncation_hint=hint,
    )


def _safe_call(engine: Any, method_name: str, *args: Any) -> list[dict[str, Any]]:
    """Invoke ``engine.<method_name>(*args)`` returning [] on failure."""
    method = getattr(engine, method_name, None)
    if method is None:
        return []
    try:
        result = method(*args)
    except (AttributeError, KeyError, ValueError, TypeError, RuntimeError):
        return []
    if result is None:
        return []
    if isinstance(result, list):
        return result
    try:
        return list(result)
    except TypeError:
        return []


def bounded_callers(engine: Any, name: str, bounds: QueryBounds, gpu_engine: Any = None) -> BoundedResult:
    """Direct callers of *name*, with hub filtering and paging."""
    bounds = clamp_bounds(bounds)
    hubs = hub_set(engine, bounds.hub_threshold) if bounds.exclude_hubs else frozenset()
    if gpu_engine is not None:
        callers = gpu_engine.callers_of(name)
    else:
        callers = _safe_call(engine, "callers_of", name)
    return _filter_and_page(callers, bounds, hubs)


def bounded_callees(engine: Any, name: str, bounds: QueryBounds, gpu_engine: Any = None) -> BoundedResult:
    """Direct callees of *name*, with hub filtering and paging."""
    bounds = clamp_bounds(bounds)
    hubs = hub_set(engine, bounds.hub_threshold) if bounds.exclude_hubs else frozenset()
    if gpu_engine is not None:
        callees = gpu_engine.callees_of(name)
    else:
        callees = _safe_call(engine, "callees_of", name)
    return _filter_and_page(callees, bounds, hubs)


def _bfs(
    engine: Any,
    name: str,
    bounds: QueryBounds,
    direction: str,
    gpu_engine: Any = None,
) -> BoundedResult:
    """Generic depth-bounded BFS in the call graph.

    When *gpu_engine* is available, delegates to its SpMV-based BFS
    (``ancestors_of`` or ``reachable_from``). Otherwise falls back to
    the Python-level ``engine.callers_of``/``engine.callees_of`` loop.
    """
    bounds = clamp_bounds(bounds)
    hubs = hub_set(engine, bounds.hub_threshold) if bounds.exclude_hubs else frozenset()

    # GPU fast path — single SpMV BFS, already depth-bounded inside the engine
    if gpu_engine is not None:
        if direction == "callers_of":
            raw = gpu_engine.ancestors_of(name, max_depth=bounds.depth)
        else:
            raw = gpu_engine.reachable_from(name, max_depth=bounds.depth)
        return _filter_and_page(raw, bounds, hubs)

    # CPU fallback — manual BFS with the trailmark engine
    visited: set[str] = {name}
    found: list[dict[str, Any]] = []
    frontier: deque[tuple[str, int]] = deque([(name, 0)])
    explore_cap = HARD_LIMIT_CAP * 4
    explored = 0

    while frontier:
        current, depth = frontier.popleft()
        if depth >= bounds.depth:
            continue
        neighbors = _safe_call(engine, direction, current)
        for neighbor in neighbors:
            explored += 1
            if explored > explore_cap:
                frontier.clear()
                break
            n_name = neighbor.get("name") if isinstance(neighbor, dict) else None
            if not n_name or n_name in visited:
                continue
            visited.add(n_name)
            if bounds.exclude_hubs and n_name in hubs:
                continue
            found.append(neighbor)
            frontier.append((n_name, depth + 1))

    return _filter_and_page(found, bounds, frozenset())


def bounded_ancestors(engine: Any, name: str, bounds: QueryBounds, gpu_engine: Any = None) -> BoundedResult:
    """Transitive callers of *name* via depth-bounded BFS."""
    return _bfs(engine, name, bounds, "callers_of", gpu_engine=gpu_engine)


def bounded_reachable(engine: Any, name: str, bounds: QueryBounds, gpu_engine: Any = None) -> BoundedResult:
    """Transitive callees of *name* via depth-bounded BFS."""
    return _bfs(engine, name, bounds, "callees_of", gpu_engine=gpu_engine)


def bounded_paths(
    engine: Any,
    source: str,
    target: str,
    bounds: QueryBounds,
    max_paths: int = 5,
) -> BoundedResult:
    """All simple paths between *source* and *target*, capped at *max_paths*.

    The engine's ``paths_between`` is called with the depth bound when
    supported. Result list is capped at ``max_paths`` after offset.
    """
    bounds = clamp_bounds(bounds)
    method = getattr(engine, "paths_between", None)
    if method is None:
        return BoundedResult(
            results=[],
            total=0,
            returned=0,
            truncated=False,
            truncation_hint="engine has no paths_between method",
        )

    # Prefer max_depth kwarg if supported; fall back to positional then bare.
    raw: Any = None
    for attempt in (
        lambda: method(source, target, max_depth=bounds.depth),
        lambda: method(source, target, bounds.depth),
        lambda: method(source, target),
    ):
        try:
            raw = attempt()
            break
        except TypeError:
            continue
        except (AttributeError, KeyError, ValueError, RuntimeError):
            raw = None
            break
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        try:
            raw = list(raw)
        except TypeError:
            raw = []

    capped_max = max(1, min(max_paths, HARD_LIMIT_CAP))
    total = len(raw)
    start = bounds.offset
    end = start + capped_max
    page_paths = raw[start:end]
    returned = len(page_paths)
    truncated = end < total or start > 0

    # Wrap each path in a dict so the result conforms to list[dict[str, Any]].
    results: list[dict[str, Any]] = []
    for idx, path in enumerate(page_paths):
        if isinstance(path, dict):
            results.append(path)
        else:
            results.append({"index": start + idx, "path": path})

    hint = ""
    if truncated:
        if end < total:
            hint = (
                f"showing paths {start}..{start + returned} of {total}; "
                f"raise offset to {end} or narrow source/target"
            )
        else:
            hint = f"offset {start} > 0; {total} total paths available"

    return BoundedResult(
        results=results,
        total=total,
        returned=returned,
        truncated=truncated,
        truncation_hint=hint,
    )


def bounded_search(engine: Any, pattern: str, bounds: QueryBounds) -> BoundedResult:
    """Regex search of function/method names with paging.

    Pattern is compiled case-insensitively and matched against both ``name``
    and ``qualified_name`` of every function/method node.
    """
    bounds = clamp_bounds(bounds)
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return BoundedResult(
            results=[],
            total=0,
            returned=0,
            truncated=False,
            truncation_hint=f"invalid regex: {exc}",
        )

    matches: list[dict[str, Any]] = []
    for node in _iter_function_nodes(engine):
        name = getattr(node, "name", "") or ""
        qname = getattr(node, "qualified_name", "") or ""
        if not (regex.search(name) or regex.search(qname)):
            continue
        kind = getattr(node, "kind", None)
        kind_value = getattr(kind, "value", kind)
        matches.append(
            {
                "id": getattr(node, "id", None),
                "name": name,
                "qualified_name": qname,
                "kind": kind_value,
                "file_path": getattr(node, "file_path", None),
                "line_start": getattr(node, "line_start", None),
                "line_end": getattr(node, "line_end", None),
                "cyclomatic_complexity": getattr(node, "cyclomatic_complexity", None),
            }
        )

    total = len(matches)
    start = bounds.offset
    end = start + bounds.limit
    page = matches[start:end]
    returned = len(page)
    truncated = end < total or start > 0
    hint = ""
    if truncated:
        if end < total:
            hint = (
                f"showing {start}..{start + returned} of {total} matches; "
                f"raise offset to {end} or refine the pattern"
            )
        else:
            hint = f"offset {start} > 0; {total} total matches available"

    return BoundedResult(
        results=page,
        total=total,
        returned=returned,
        truncated=truncated,
        truncation_hint=hint,
    )
