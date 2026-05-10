"""Background codebase indexing manager.

Manages multiple indexed codebases via trailmark's QueryEngine. Indexing runs
in a background thread per codebase. The registry and per-entry mutations are
guarded by a single lock; the heavy parse/analysis work runs outside the lock
so that pollers and other indexes are never blocked.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = ["IndexManager", "IndexEntry"]

_log = logging.getLogger(__name__)


@dataclass
class IndexEntry:
    """In-memory record of one indexed codebase."""

    index_id: str
    root_path: str
    language: str
    status: str = "pending"  # pending | indexing | ready | error
    error: str | None = None
    started_at: float = 0.0
    finished_at: float = 0.0
    engine: Any = None  # trailmark QueryEngine once status == "ready"
    summary: dict[str, Any] = field(default_factory=dict)
    preanalysis: dict[str, Any] = field(default_factory=dict)


class IndexManager:
    """Thread-safe registry of indexed codebases with durable persistence.

    ``start_index`` returns immediately with a stable ``index_id``; the parse
    and pre-analysis run on a daemon thread. Ready indexes are persisted to disk
    via ``DurableIndexStore`` and survive process restarts.

    Engine lifecycle is memory-bounded: when more than ``max_loaded_engines``
    engines are resident, the least-recently-used engine is evicted (set to
    None). Evicted engines reload from disk on next ``get_engine`` call.
    """

    def __init__(
        self,
        max_loaded_engines: int | None = None,
    ) -> None:
        from audit_mcp.store import DurableIndexStore

        self._lock = threading.Lock()
        self._indexes: dict[str, IndexEntry] = {}
        self._store = DurableIndexStore()
        self._access_order: list[str] = []  # LRU: oldest first
        self._max_loaded = max_loaded_engines or int(
            os.environ.get("AUDIT_MCP_MAX_ENGINES", "8")
        )
        self._eviction_count: int = 0
        self._recover_from_store()

    def start_index(self, path: str, language: str = "auto") -> str:
        """Begin indexing ``path``. Returns the index id (idempotent if ready)."""
        index_id = hashlib.sha256(f"{path}:{language}".encode()).hexdigest()[:12]
        with self._lock:
            existing = self._indexes.get(index_id)
            if existing is not None and existing.status in {"ready", "indexing"}:
                return index_id
            entry = IndexEntry(
                index_id=index_id,
                root_path=path,
                language=language,
                status="indexing",
                started_at=time.time(),
            )
            self._indexes[index_id] = entry
        thread = threading.Thread(
            target=self._index_worker,
            args=(index_id,),
            name=f"trailmark-index-{index_id}",
            daemon=True,
        )
        thread.start()
        return index_id

    def poll(self, index_id: str) -> dict[str, Any]:
        """Return a JSON-safe snapshot of the index entry."""
        with self._lock:
            entry = self._indexes.get(index_id)
            if entry is None:
                return {"status": "error", "error": f"Unknown index_id: {index_id}"}
            snapshot = {
                "index_id": entry.index_id,
                "root_path": entry.root_path,
                "language": entry.language,
                "status": entry.status,
                "error": entry.error,
                "started_at": entry.started_at,
                "finished_at": entry.finished_at,
                "summary": dict(entry.summary),
            }
        result: dict[str, Any] = {
            "index_id": snapshot["index_id"],
            "root_path": snapshot["root_path"],
            "language": snapshot["language"],
            "status": snapshot["status"],
        }
        if snapshot["error"]:
            result["error"] = snapshot["error"]
        if snapshot["summary"]:
            result["summary"] = snapshot["summary"]
        if snapshot["finished_at"] > 0:
            result["elapsed_seconds"] = round(
                snapshot["finished_at"] - snapshot["started_at"], 2
            )
        return result

    def get_engine(self, index_id: str) -> Any:
        """Return the QueryEngine if ready, else ``None``.

        Marks the index as most-recently-used. May evict the LRU engine
        if the loaded engine count exceeds the budget.
        """
        with self._lock:
            entry = self._indexes.get(index_id)
            if entry is None or entry.status != "ready":
                return None
            if entry.engine is not None:
                self._touch_locked(index_id)
                self._maybe_evict_locked()
                return entry.engine

        # Engine is None (evicted or recovered from store without engine).
        # Try loading from disk outside the lock (I/O heavy).
        engine = self._store.get_engine(index_id)
        if engine is not None:
            with self._lock:
                entry_again = self._indexes.get(index_id)
                if entry_again is not None:
                    entry_again.engine = engine
                    self._touch_locked(index_id)
                    self._maybe_evict_locked()
        return engine

    def list_indexes(self) -> list[dict[str, Any]]:
        """Return a snapshot of every index entry."""
        with self._lock:
            ids = list(self._indexes.keys())
        return [self.poll(i) for i in ids]

    def _index_worker(self, index_id: str) -> None:
        with self._lock:
            entry = self._indexes.get(index_id)
        if entry is None:
            return
        try:
            from audit_mcp.fast_indexer import FastIndexer, IndexProgress

            progress = IndexProgress()
            indexer = FastIndexer()
            engine = indexer.index(
                entry.root_path,
                language=entry.language,
                progress=progress,
            )
            summary = engine.summary()
            preanalysis = engine.preanalysis()
            with self._lock:
                entry.engine = engine
                entry.summary = summary
                entry.preanalysis = preanalysis
                entry.status = "ready"
                entry.finished_at = time.time()
            # Persist to durable store so index survives restart
            self._store.register(index_id, entry.root_path, entry.language)
            self._store.mark_ready(index_id, engine, summary, preanalysis)
            _log.info(
                "index %s ready: %d functions, %d edges (%.1fs) "
                "[%d parsed, %d cached, %d failed]",
                index_id,
                summary.get("functions", 0),
                summary.get("call_edges", 0),
                entry.finished_at - entry.started_at,
                progress.parsed_files,
                progress.cached_files,
                progress.failed_files,
            )
        except (OSError, ValueError, RuntimeError, ImportError) as exc:
            _log.exception("index %s failed", index_id)
            with self._lock:
                entry.status = "error"
                entry.error = f"{type(exc).__name__}: {exc}"
                entry.finished_at = time.time()
            self._store.mark_error(index_id, f"{type(exc).__name__}: {exc}")

    def _recover_from_store(self) -> None:
        """Hydrate in-memory registry from durable store on startup."""
        for record_dict in self._store.list_indexes():
            if record_dict.get("status") == "ready":
                index_id = record_dict["index_id"]
                with self._lock:
                    if index_id not in self._indexes:
                        self._indexes[index_id] = IndexEntry(
                            index_id=index_id,
                            root_path=record_dict.get("root_path", ""),
                            language=record_dict.get("language", "auto"),
                            status="ready",
                            started_at=record_dict.get("created_at", 0.0),
                            finished_at=record_dict.get("finished_at", 0.0),
                            summary=record_dict.get("summary", {}),
                        )
        recovered = sum(1 for e in self._indexes.values() if e.status == "ready")
        if recovered:
            _log.info("recovered %d ready indexes from durable store", recovered)

    def close_index(self, index_id: str) -> bool:
        """Release in-memory engine, keep persistent data."""
        with self._lock:
            entry = self._indexes.pop(index_id, None)
        if entry is None:
            return False
        self._store.close_index(index_id)
        return True

    # ------------------------------------------------------------------
    # LRU engine management
    # ------------------------------------------------------------------

    def _touch_locked(self, index_id: str) -> None:
        """Move *index_id* to most-recently-used (must hold _lock)."""
        try:
            self._access_order.remove(index_id)
        except ValueError:
            pass
        self._access_order.append(index_id)

    def _maybe_evict_locked(self) -> None:
        """Evict LRU engines until loaded count <= budget (must hold _lock)."""
        loaded = [
            iid for iid, e in self._indexes.items()
            if e.engine is not None
        ]
        while len(loaded) > self._max_loaded and self._access_order:
            victim_id = self._access_order.pop(0)
            victim = self._indexes.get(victim_id)
            if victim is not None and victim.engine is not None:
                _log.info(
                    "evicting engine %s (loaded=%d, budget=%d)",
                    victim_id, len(loaded), self._max_loaded,
                )
                victim.engine = None
                self._eviction_count += 1
                loaded = [
                    iid for iid, e in self._indexes.items()
                    if e.engine is not None
                ]

    def memory_stats(self) -> dict[str, Any]:
        """Return engine loading stats for the memory_usage tool."""
        with self._lock:
            loaded = sum(1 for e in self._indexes.values() if e.engine is not None)
            total = len(self._indexes)
        return {
            "loaded_engines": loaded,
            "total_indexes": total,
            "max_loaded_engines": self._max_loaded,
            "eviction_count": self._eviction_count,
        }
