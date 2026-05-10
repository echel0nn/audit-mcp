"""Tests for ``audit_mcp.query_bounds`` — verify bounds clamping, hub
detection, paging, and BFS depth limits using a mock engine.

These tests deliberately avoid importing ``trailmark`` itself; they build a
minimal ``MockEngine`` that exposes the same surface area
(``_store._graph.nodes``, ``callers_of``, ``callees_of``) consumed by the
bounded-query helpers.
"""

from __future__ import annotations

from typing import Any

import pytest

from audit_mcp.query_bounds import (
    HARD_DEPTH_CAP,
    HARD_LIMIT_CAP,
    BoundedResult,
    QueryBounds,
    _hub_set_cached,
    bounded_ancestors,
    bounded_callers,
    bounded_reachable,
    bounded_search,
    clamp_bounds,
    hub_set,
)


class _Kind:
    def __init__(self, value: str) -> None:
        self.value = value


class MockCodeUnit:
    def __init__(
        self,
        id: int,
        name: str,
        kind_value: str = "function",
        qualified_name: str = "",
        file_path: str = "",
        line_start: int = 0,
        line_end: int = 0,
        cyclomatic_complexity: int = 1,
    ) -> None:
        self.id = id
        self.name = name
        self.kind = _Kind(kind_value)
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
    """Mimics the slice of ``trailmark.QueryEngine`` consumed by query_bounds."""

    def __init__(
        self,
        nodes: dict[str, MockCodeUnit],
        callers_map: dict[str, list[dict[str, Any]]] | None = None,
        callees_map: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self._store = MockStore(MockGraph(nodes))
        self._callers: dict[str, list[dict[str, Any]]] = callers_map or {}
        self._callees: dict[str, list[dict[str, Any]]] = callees_map or {}

    def callers_of(self, name: str) -> list[dict[str, Any]]:
        return list(self._callers.get(name, []))

    def callees_of(self, name: str) -> list[dict[str, Any]]:
        return list(self._callees.get(name, []))


@pytest.fixture(autouse=True)
def _clear_hub_cache() -> Any:
    """Drop the lru_cache between tests so engine-id reuse never leaks state."""
    _hub_set_cached.cache_clear()
    yield
    _hub_set_cached.cache_clear()


def _ref(unit: MockCodeUnit) -> dict[str, Any]:
    return {"id": unit.id, "name": unit.name}


def _build_engine() -> MockEngine:
    """Build an engine with 20 function nodes and the assignment's call graph.

    Forward edges:
        main -> parse_input, validate, process
        parse_input -> read_buffer, decode
        validate -> check_bounds, check_type
        process -> transform, write_output
        write_output -> flush

    ``log_debug`` is called by 15 distinct functions (in-degree > 10) so it
    becomes a hub when ``hub_threshold <= 14``.
    """
    names = [
        "main",
        "parse_input",
        "validate",
        "process",
        "read_buffer",
        "decode",
        "check_bounds",
        "check_type",
        "transform",
        "write_output",
        "flush",
        "log_debug",
        # Eight extra synthetic callers — together with the eleven concrete
        # functions above, log_debug ends up with fifteen distinct callers.
        "caller_a",
        "caller_b",
        "caller_c",
        "caller_d",
        "caller_e",
        "caller_f",
        "caller_g",
        "caller_h",
    ]
    assert len(names) == 20

    nodes: dict[str, MockCodeUnit] = {
        n: MockCodeUnit(
            id=i,
            name=n,
            kind_value="function",
            qualified_name=f"mod.{n}",
            file_path=f"src/{n}.py",
            line_start=i * 10,
            line_end=i * 10 + 5,
        )
        for i, n in enumerate(names)
    }

    callees: dict[str, list[dict[str, Any]]] = {
        "main": [_ref(nodes["parse_input"]), _ref(nodes["validate"]), _ref(nodes["process"])],
        "parse_input": [_ref(nodes["read_buffer"]), _ref(nodes["decode"])],
        "validate": [_ref(nodes["check_bounds"]), _ref(nodes["check_type"])],
        "process": [_ref(nodes["transform"]), _ref(nodes["write_output"])],
        "write_output": [_ref(nodes["flush"])],
    }

    callers: dict[str, list[dict[str, Any]]] = {
        "parse_input": [_ref(nodes["main"])],
        "validate": [_ref(nodes["main"])],
        "process": [_ref(nodes["main"])],
        "read_buffer": [_ref(nodes["parse_input"])],
        "decode": [_ref(nodes["parse_input"])],
        "check_bounds": [_ref(nodes["validate"])],
        "check_type": [_ref(nodes["validate"])],
        "transform": [_ref(nodes["process"])],
        "write_output": [_ref(nodes["process"])],
        "flush": [_ref(nodes["write_output"])],
    }

    log_debug_caller_names = [
        "main",
        "parse_input",
        "validate",
        "process",
        "read_buffer",
        "decode",
        "check_bounds",
        "check_type",
        "transform",
        "write_output",
        "flush",
        "caller_a",
        "caller_b",
        "caller_c",
        "caller_d",
    ]
    assert len(log_debug_caller_names) == 15
    callers["log_debug"] = [_ref(nodes[n]) for n in log_debug_caller_names]

    return MockEngine(nodes, callers_map=callers, callees_map=callees)


# ---------------------------------------------------------------------------
# clamp_bounds
# ---------------------------------------------------------------------------


def test_clamp_bounds() -> None:
    clamped = clamp_bounds(QueryBounds(depth=999, limit=99_999, offset=-5))
    assert HARD_DEPTH_CAP == 20
    assert clamped.depth == HARD_DEPTH_CAP
    assert clamped.limit == HARD_LIMIT_CAP
    assert clamped.offset == 0

    # Sane inputs survive unchanged.
    sane = clamp_bounds(QueryBounds(depth=3, limit=50, offset=10, hub_threshold=42))
    assert sane.depth == 3
    assert sane.limit == 50
    assert sane.offset == 10
    assert sane.hub_threshold == 42


# ---------------------------------------------------------------------------
# hub_set
# ---------------------------------------------------------------------------


def test_hub_set() -> None:
    eng = _build_engine()
    hubs = hub_set(eng, threshold=10)
    assert "log_debug" in hubs
    # No other function in the graph crosses 10 callers.
    assert "main" not in hubs
    assert "parse_input" not in hubs
    assert "validate" not in hubs
    # Cache hit on the second call returns the same frozenset.
    assert hub_set(eng, threshold=10) is hubs


# ---------------------------------------------------------------------------
# bounded_callers
# ---------------------------------------------------------------------------


def test_bounded_callers_basic() -> None:
    eng = _build_engine()
    # exclude_hubs=False so hub-status of log_debug never filters anything.
    bounds = QueryBounds(limit=5, exclude_hubs=False)
    result = bounded_callers(eng, "log_debug", bounds)
    assert result.total == 15
    assert result.returned == 5
    assert len(result.results) == 5
    assert result.truncated is True
    assert "raise offset" in result.truncation_hint


def test_bounded_callers_hub_exclusion() -> None:
    eng = _build_engine()
    # Inject log_debug as an additional caller of "validate" — it should be
    # filtered out when exclude_hubs=True with a low hub_threshold.
    log_debug_node = eng._store._graph.nodes["log_debug"]
    eng._callers["validate"] = [
        *eng._callers["validate"],
        _ref(log_debug_node),
    ]
    bounds = QueryBounds(exclude_hubs=True, hub_threshold=10)
    result = bounded_callers(eng, "validate", bounds)
    names = [item["name"] for item in result.results]
    assert "log_debug" not in names
    assert "main" in names
    # 2 raw callers, log_debug filtered out, so total after filtering is 1.
    assert result.total == 1


# ---------------------------------------------------------------------------
# bounded_ancestors
# ---------------------------------------------------------------------------


def test_bounded_ancestors_depth() -> None:
    eng = _build_engine()

    r1 = bounded_ancestors(eng, "flush", QueryBounds(depth=1, exclude_hubs=False))
    names1 = [item["name"] for item in r1.results]
    assert names1 == ["write_output"]

    r2 = bounded_ancestors(eng, "flush", QueryBounds(depth=2, exclude_hubs=False))
    names2 = [item["name"] for item in r2.results]
    assert set(names2) == {"write_output", "process"}

    r3 = bounded_ancestors(eng, "flush", QueryBounds(depth=3, exclude_hubs=False))
    names3 = [item["name"] for item in r3.results]
    assert set(names3) == {"write_output", "process", "main"}


def test_bounded_ancestors_limit() -> None:
    eng = _build_engine()
    bounds = QueryBounds(depth=10, limit=2, exclude_hubs=False)
    result = bounded_ancestors(eng, "flush", bounds)
    assert result.total == 3
    assert result.returned == 2
    assert len(result.results) == 2
    assert result.truncated is True


# ---------------------------------------------------------------------------
# bounded_reachable
# ---------------------------------------------------------------------------


def test_bounded_reachable() -> None:
    eng = _build_engine()
    bounds = QueryBounds(depth=1, exclude_hubs=False)
    result = bounded_reachable(eng, "main", bounds)
    names = sorted(item["name"] for item in result.results)
    assert names == ["parse_input", "process", "validate"]
    assert result.total == 3
    assert result.truncated is False


# ---------------------------------------------------------------------------
# bounded_search
# ---------------------------------------------------------------------------


def test_bounded_search() -> None:
    eng = _build_engine()
    bounds = QueryBounds(exclude_hubs=False)

    parse_hits = bounded_search(eng, "parse_*", bounds)
    parse_names = {m["name"] for m in parse_hits.results}
    assert "parse_input" in parse_names
    # Pattern "parse_*" (regex: 'parse' + zero-or-more underscores) only hits
    # functions whose name or qualified_name contains the substring "parse".
    for n in parse_names:
        assert "parse" in n

    bound_hits = bounded_search(eng, ".*bound.*", bounds)
    bound_names = {m["name"] for m in bound_hits.results}
    assert "check_bounds" in bound_names
    # No false positives — "bound" doesn't appear in any other function name.
    assert all("bound" in n for n in bound_names)


def test_bounded_search_pagination() -> None:
    nodes = {
        f"patfn_{i}": MockCodeUnit(
            id=1000 + i,
            name=f"patfn_{i}",
            kind_value="function",
            qualified_name=f"pkg.patfn_{i}",
        )
        for i in range(10)
    }
    eng = MockEngine(nodes)

    page1 = bounded_search(eng, r"patfn_\d", QueryBounds(limit=3, offset=0, exclude_hubs=False))
    assert page1.total == 10
    assert page1.returned == 3
    assert len(page1.results) == 3
    assert page1.truncated is True

    page2 = bounded_search(eng, r"patfn_\d", QueryBounds(limit=3, offset=3, exclude_hubs=False))
    assert page2.total == 10
    assert page2.returned == 3
    assert len(page2.results) == 3
    assert page2.truncated is True

    page1_names = [m["name"] for m in page1.results]
    page2_names = [m["name"] for m in page2.results]
    # Pages must be disjoint slices of the same total.
    assert set(page1_names).isdisjoint(set(page2_names))


# ---------------------------------------------------------------------------
# BoundedResult.to_dict
# ---------------------------------------------------------------------------


def test_bounded_result_to_dict() -> None:
    r = BoundedResult(
        results=[{"name": "foo"}],
        total=42,
        returned=1,
        truncated=True,
        truncation_hint="hint",
    )
    d = r.to_dict()
    assert set(d.keys()) == {
        "results",
        "total",
        "returned",
        "truncated",
        "truncation_hint",
    }
    assert d["results"] == [{"name": "foo"}]
    assert d["total"] == 42
    assert d["returned"] == 1
    assert d["truncated"] is True
    assert d["truncation_hint"] == "hint"
