"""Tests for ``audit_mcp.lazy_preanalysis``.

Mocks trailmark's QueryEngine surface (``attack_surface``,
``reachable_from``, ``_store._graph.nodes``) so the test suite runs
without trailmark installed.
"""

from __future__ import annotations

from typing import Any

from audit_mcp.lazy_preanalysis import LazyPreanalysis, get_all_function_nodes

# ---------------------------------------------------------------------------
# Mock engine surface
# ---------------------------------------------------------------------------


class MockKind:
    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value


class MockCodeUnit:
    def __init__(
        self,
        node_id: str,
        name: str,
        kind_value: str,
        qualified_name: str = "",
        file_path: str = "",
        line_start: int = 0,
        line_end: int = 0,
        cyclomatic_complexity: int = 1,
    ) -> None:
        self.id = node_id
        self.name = name
        self.kind = MockKind(kind_value)
        self.qualified_name = qualified_name or name
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.cyclomatic_complexity = cyclomatic_complexity


class MockGraph:
    def __init__(self, nodes: dict[str, MockCodeUnit]) -> None:
        self.nodes = nodes


class MockStore:
    def __init__(self, graph: MockGraph) -> None:
        self._graph = graph


class MockEngine:
    """Minimal stand-in for trailmark's QueryEngine.

    Tracks call counts for ``attack_surface`` and ``reachable_from`` so
    tests can assert that ``LazyPreanalysis`` actually caches.
    """

    def __init__(
        self,
        graph: MockGraph,
        entrypoints: list[dict[str, Any]] | None = None,
        reachable_map: dict[str, list[str]] | None = None,
    ) -> None:
        self._store = MockStore(graph)
        self._entrypoints = entrypoints or []
        self._reachable_map = reachable_map or {}
        self.attack_surface_calls = 0
        self.reachable_from_calls: dict[str, int] = {}

    def attack_surface(self) -> list[dict[str, Any]]:
        self.attack_surface_calls += 1
        return list(self._entrypoints)

    def reachable_from(self, name: str) -> list[str]:
        self.reachable_from_calls[name] = self.reachable_from_calls.get(name, 0) + 1
        return list(self._reachable_map.get(name, []))


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _build_engine() -> MockEngine:
    """Build a 10-function engine with two non-function nodes mixed in."""
    # Ten function/method nodes with varied complexity.
    function_specs: list[tuple[str, str, str, int]] = [
        ("fn_main", "main", "function", 20),
        ("fn_handle_request", "handle_request", "function", 18),
        ("fn_router", "router", "function", 15),
        ("fn_validate", "validate", "function", 12),
        ("fn_normalize", "normalize", "function", 10),
        ("fn_render", "render", "function", 8),
        ("fn_log", "log", "function", 5),
        ("fn_format", "format", "function", 4),
        ("fn_to_str", "to_str", "method", 3),
        ("fn_noop", "noop", "function", 2),
    ]

    nodes: dict[str, MockCodeUnit] = {}
    for node_id, name, kind, complexity in function_specs:
        nodes[node_id] = MockCodeUnit(
            node_id=node_id,
            name=name,
            kind_value=kind,
            cyclomatic_complexity=complexity,
        )

    # Two non-function nodes that must be filtered out by get_all_function_nodes.
    nodes["cls_app"] = MockCodeUnit(node_id="cls_app", name="App", kind_value="class")
    nodes["mod_pkg"] = MockCodeUnit(node_id="mod_pkg", name="pkg", kind_value="module")

    graph = MockGraph(nodes)

    # Two entrypoints out of attack_surface.
    entrypoints: list[dict[str, Any]] = [
        {"name": "main", "kind": "function"},
        {"name": "handle_request", "kind": "function"},
    ]

    # Reachability: order matters for blast_radius_top_n ranking.
    # main reaches the most; handle_request reaches a few; router reaches
    # a moderate set; everyone else has small radii.
    reachable_map: dict[str, list[str]] = {
        "main": ["handle_request", "router", "validate", "normalize", "render", "log", "format"],
        "handle_request": ["router", "validate", "log"],
        "router": ["validate", "normalize", "render", "log"],
        "validate": ["log"],
        "normalize": ["format"],
        "render": ["format", "to_str"],
        "log": [],
        "format": ["to_str"],
        "to_str": [],
        "noop": [],
    }

    return MockEngine(graph=graph, entrypoints=entrypoints, reachable_map=reachable_map)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_entrypoints_cached() -> None:
    engine = _build_engine()
    pre = LazyPreanalysis(engine)

    first = pre.entrypoints()
    second = pre.entrypoints()

    assert first == second
    assert len(first) == 2
    assert engine.attack_surface_calls == 1


def test_blast_radius_lazy() -> None:
    engine = _build_engine()
    pre = LazyPreanalysis(engine)

    radius_first = pre.blast_radius("main")
    radius_second = pre.blast_radius("main")

    # main reaches 7 nodes per the fixture.
    assert radius_first == 7
    assert radius_second == 7
    assert engine.reachable_from_calls.get("main") == 1


def test_blast_radius_top_n() -> None:
    engine = _build_engine()
    pre = LazyPreanalysis(engine)

    top = pre.blast_radius_top_n(n=3)

    assert len(top) == 3
    for entry in top:
        assert set(entry.keys()) == {"name", "blast_radius", "complexity"}

    radii = [entry["blast_radius"] for entry in top]
    assert radii == sorted(radii, reverse=True)

    # main has the largest blast radius (7) and should rank first.
    assert top[0]["name"] == "main"
    assert top[0]["blast_radius"] == 7
    assert top[0]["complexity"] == 20


def test_full_preanalysis_shape() -> None:
    engine = _build_engine()
    pre = LazyPreanalysis(engine)

    bundle = pre.full_preanalysis()

    assert set(bundle.keys()) == {"entrypoints", "entrypoint_count", "blast_radius_top_50"}
    assert bundle["entrypoint_count"] == 2
    assert bundle["entrypoint_count"] == len(bundle["entrypoints"])
    # Only ten function/method nodes exist, so the top-50 list is bounded by that.
    assert len(bundle["blast_radius_top_50"]) <= 10
    assert all(
        set(entry.keys()) == {"name", "blast_radius", "complexity"}
        for entry in bundle["blast_radius_top_50"]
    )


def test_invalidate_clears_cache() -> None:
    engine = _build_engine()
    pre = LazyPreanalysis(engine)

    pre.entrypoints()
    pre.blast_radius("main")
    assert engine.attack_surface_calls == 1
    assert engine.reachable_from_calls.get("main") == 1

    pre.invalidate()

    pre.entrypoints()
    pre.blast_radius("main")

    assert engine.attack_surface_calls == 2
    assert engine.reachable_from_calls.get("main") == 2


def test_get_all_function_nodes() -> None:
    engine = _build_engine()

    nodes = get_all_function_nodes(engine)

    # Ten function/method nodes; the class and module entries must be filtered.
    assert len(nodes) == 10
    kinds = {node.kind.value for node in nodes}
    assert kinds == {"function", "method"}
    names = {node.name for node in nodes}
    assert "App" not in names
    assert "pkg" not in names
    assert "main" in names
