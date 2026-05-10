"""Tests for LRU engine eviction in IndexManager."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from audit_mcp.indexer import IndexEntry, IndexManager


def _make_manager(max_loaded: int) -> IndexManager:
    """Create an IndexManager with a mocked store (no disk I/O)."""
    with patch("audit_mcp.indexer.IndexManager._recover_from_store"):
        mgr = IndexManager(max_loaded_engines=max_loaded)
    # Replace the store with a mock that never returns engines from disk.
    mgr._store = MagicMock()
    mgr._store.list_indexes.return_value = []
    mgr._store.get_engine.return_value = None
    return mgr


def _add_ready_entry(mgr: IndexManager, index_id: str) -> IndexEntry:
    """Insert a fake ready entry with a mock engine."""
    entry = IndexEntry(
        index_id=index_id,
        root_path=f"/fake/{index_id}",
        language="python",
        status="ready",
        started_at=time.time(),
        finished_at=time.time(),
        engine=MagicMock(name=f"engine-{index_id}"),
        summary={"functions": 10},
    )
    mgr._indexes[index_id] = entry
    mgr._access_order.append(index_id)
    return entry


class TestLRUEviction:
    def test_no_eviction_under_budget(self) -> None:
        mgr = _make_manager(max_loaded=3)
        _add_ready_entry(mgr, "a")
        _add_ready_entry(mgr, "b")

        # Access both — both should stay loaded.
        assert mgr.get_engine("a") is not None
        assert mgr.get_engine("b") is not None
        stats = mgr.memory_stats()
        assert stats["loaded_engines"] == 2
        assert stats["eviction_count"] == 0

    def test_eviction_over_budget(self) -> None:
        mgr = _make_manager(max_loaded=2)
        _add_ready_entry(mgr, "a")
        _add_ready_entry(mgr, "b")

        # Access a then b — both loaded, at budget.
        mgr.get_engine("a")
        mgr.get_engine("b")
        assert mgr.memory_stats()["loaded_engines"] == 2

        # Add a third — should evict "a" (LRU).
        _add_ready_entry(mgr, "c")
        mgr.get_engine("c")  # triggers eviction check

        stats = mgr.memory_stats()
        # c was added with engine already set + touched via get_engine,
        # so eviction should have run.
        assert stats["loaded_engines"] <= 2
        assert stats["eviction_count"] >= 1

    def test_lru_ordering(self) -> None:
        mgr = _make_manager(max_loaded=2)
        _add_ready_entry(mgr, "a")
        _add_ready_entry(mgr, "b")

        # Access b then a — a is MRU, b is LRU.
        mgr.get_engine("b")
        mgr.get_engine("a")

        # Add c — should evict b (LRU), not a.
        _add_ready_entry(mgr, "c")
        mgr.get_engine("c")

        entry_a = mgr._indexes["a"]
        entry_b = mgr._indexes["b"]
        # b should be evicted (engine=None), a should remain.
        assert entry_b.engine is None
        assert entry_a.engine is not None

    def test_evicted_engine_reloads_from_store(self) -> None:
        mgr = _make_manager(max_loaded=1)
        _add_ready_entry(mgr, "a")
        _add_ready_entry(mgr, "b")

        # Access a — touches a, evicts b (LRU), budget=1.
        mgr.get_engine("a")
        assert mgr._indexes["b"].engine is None  # b evicted
        assert mgr._indexes["a"].engine is not None  # a still loaded

        # Reload b from store — this evicts a (now LRU).
        reloaded_b = MagicMock(name="reloaded-b")
        mgr._store.get_engine.return_value = reloaded_b
        result_b = mgr.get_engine("b")
        assert result_b is reloaded_b
        assert mgr._indexes["a"].engine is None  # a evicted

        # Reload a from store.
        reloaded_a = MagicMock(name="reloaded-a")
        mgr._store.get_engine.return_value = reloaded_a
        result_a = mgr.get_engine("a")
        assert result_a is reloaded_a

    def test_memory_stats_shape(self) -> None:
        mgr = _make_manager(max_loaded=4)
        _add_ready_entry(mgr, "x")
        stats = mgr.memory_stats()
        assert "loaded_engines" in stats
        assert "total_indexes" in stats
        assert "max_loaded_engines" in stats
        assert "eviction_count" in stats
        assert stats["max_loaded_engines"] == 4
        assert stats["total_indexes"] == 1
