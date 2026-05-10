"""Lazy preanalysis wrapper around trailmark's QueryEngine.

Computes blast radius, taint propagation, and entrypoint reachability on
demand instead of eagerly across the entire graph. Caches results so
repeated lookups are O(1).
"""

from __future__ import annotations

from typing import Any

__all__ = ["LazyPreanalysis", "get_all_function_nodes"]


_FUNCTION_KINDS: frozenset[str] = frozenset({"function", "method"})


def get_all_function_nodes(engine: Any) -> list[Any]:
    """Return all CodeUnit nodes whose kind is function or method.

    Reads directly from ``engine._store._graph.nodes`` to avoid the cost
    of building intermediate dict views from the public query surface.
    """
    nodes = engine._store._graph.nodes.values()
    result: list[Any] = []
    for node in nodes:
        kind = getattr(node, "kind", None)
        kind_value = getattr(kind, "value", None)
        if kind_value in _FUNCTION_KINDS:
            result.append(node)
    return result


class LazyPreanalysis:
    """On-demand preanalysis — computes blast radius, taint, entrypoints lazily.

    When a ``gpu_engine`` is provided, blast radius computations use
    batched SpMV on the GPU (or scipy CPU fallback) instead of serial
    ``engine.reachable_from()`` calls.
    """

    __slots__ = (
        "_engine",
        "_gpu_engine",
        "_blast_cache",
        "_taint_cache",
        "_entrypoints",
        "_reachable_from_entrypoints",
    )

    def __init__(self, engine: Any, gpu_engine: Any = None) -> None:
        self._engine = engine
        self._gpu_engine = gpu_engine
        self._blast_cache: dict[str, int] = {}
        self._taint_cache: dict[str, list[dict[str, Any]]] = {}
        self._entrypoints: list[dict[str, Any]] | None = None
        self._reachable_from_entrypoints: set[str] | None = None

    def entrypoints(self) -> list[dict[str, Any]]:
        """Return cached attack-surface entrypoints (eager, O(V) pattern match)."""
        if self._entrypoints is None:
            self._entrypoints = list(self._engine.attack_surface())
        return self._entrypoints

    def blast_radius(self, name: str) -> int:
        """Return the count of nodes reachable from ``name``, cached."""
        cached = self._blast_cache.get(name)
        if cached is not None:
            return cached
        if self._gpu_engine is not None:
            size = len(self._gpu_engine.reachable_from(name, max_depth=20))
        else:
            size = len(self._engine.reachable_from(name))
        self._blast_cache[name] = size
        return size

    def blast_radius_top_n(self, n: int = 50) -> list[dict[str, Any]]:
        """Return the top ``n`` functions ranked by reachability size.

        Uses cyclomatic complexity as a coarse pre-filter to bound the
        number of expensive ``reachable_from`` calls. When a GPU engine is
        available, computes all candidates in one batched SpMV operation.
        """
        functions = get_all_function_nodes(self._engine)
        functions.sort(
            key=lambda node: getattr(node, "cyclomatic_complexity", 0) or 0,
            reverse=True,
        )
        candidates = functions[: max(n * 3, n)]

        # Collect candidate names
        cand_names: list[str] = []
        cand_complexity: dict[str, int] = {}
        for node in candidates:
            name = getattr(node, "name", None)
            if name:
                cand_names.append(name)
                cand_complexity[name] = getattr(node, "cyclomatic_complexity", 0) or 0

        # Batched computation when GPU engine is available
        if self._gpu_engine is not None and cand_names:
            batch = self._gpu_engine.blast_radius_batch(cand_names, max_depth=20)
            for name, radius in batch.items():
                self._blast_cache[name] = radius
        else:
            # Serial fallback — each call hits the per-name cache
            for name in cand_names:
                self.blast_radius(name)

        scored: list[dict[str, Any]] = [
            {
                "name": name,
                "blast_radius": self._blast_cache.get(name, 0),
                "complexity": cand_complexity.get(name, 0),
            }
            for name in cand_names
        ]
        scored.sort(key=lambda entry: entry["blast_radius"], reverse=True)
        return scored[:n]

    def reachable_from_entrypoints(self) -> set[str]:
        """Return the union of reachability sets for every entrypoint."""
        if self._reachable_from_entrypoints is not None:
            return self._reachable_from_entrypoints

        union: set[str] = set()
        for ep in self.entrypoints():
            ep_name = ep.get("name") if isinstance(ep, dict) else getattr(ep, "name", None)
            if not ep_name:
                continue
            for reached in self._engine.reachable_from(ep_name):
                if isinstance(reached, dict):
                    reached_name = reached.get("name")
                else:
                    reached_name = getattr(reached, "name", None)
                if reached_name:
                    union.add(reached_name)

        self._reachable_from_entrypoints = union
        return union

    def is_reachable(self, name: str) -> bool:
        """Return True when ``name`` is reachable from any entrypoint."""
        return name in self.reachable_from_entrypoints()

    def full_preanalysis(self) -> dict[str, Any]:
        """Return a summary bundle of preanalysis results."""
        eps = self.entrypoints()
        return {
            "entrypoints": eps,
            "entrypoint_count": len(eps),
            "blast_radius_top_50": self.blast_radius_top_n(50),
        }

    def invalidate(self) -> None:
        """Clear every cached preanalysis result."""
        self._blast_cache.clear()
        self._taint_cache.clear()
        self._entrypoints = None
        self._reachable_from_entrypoints = None
