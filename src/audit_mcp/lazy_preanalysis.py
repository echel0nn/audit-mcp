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
    """On-demand preanalysis - computes blast radius, taint, entrypoints lazily."""

    __slots__ = (
        "_engine",
        "_blast_cache",
        "_taint_cache",
        "_entrypoints",
        "_reachable_from_entrypoints",
    )

    def __init__(self, engine: Any) -> None:
        self._engine = engine
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
        reachable = self._engine.reachable_from(name)
        size = len(reachable)
        self._blast_cache[name] = size
        return size

    def blast_radius_top_n(self, n: int = 50) -> list[dict[str, Any]]:
        """Return the top ``n`` functions ranked by reachability size.

        Uses cyclomatic complexity as a coarse pre-filter to bound the
        number of expensive ``reachable_from`` calls. Picks the top
        ``n * 3`` candidates by complexity, computes blast radius for
        each, then keeps the top ``n`` by blast radius.
        """
        functions = get_all_function_nodes(self._engine)
        functions.sort(
            key=lambda node: getattr(node, "cyclomatic_complexity", 0) or 0,
            reverse=True,
        )
        candidates = functions[: max(n * 3, n)]

        scored: list[dict[str, Any]] = []
        for node in candidates:
            name = getattr(node, "name", None)
            if not name:
                continue
            radius = self.blast_radius(name)
            scored.append(
                {
                    "name": name,
                    "blast_radius": radius,
                    "complexity": getattr(node, "cyclomatic_complexity", 0) or 0,
                }
            )

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
