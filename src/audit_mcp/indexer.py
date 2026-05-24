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
from collections import OrderedDict
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
    gpu_engine: Any = None  # GpuGraphEngine (optional, built at index time)
    semble_index: Any = None  # semble.SembleIndex (lazy-built on first use)
    semble_lock: Any = None  # threading.Lock — initialized on first use
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
        self._access_order: OrderedDict[str, None] = OrderedDict()
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

    def get_gpu_engine(self, index_id: str) -> Any:
        """Return the GpuGraphEngine, building it lazily if needed.

        Indexes recovered from the durable store on process restart
        come back with ``entry.gpu_engine = None`` because the GPU
        engine isn't persisted (it's a derived CSR + CuPy state).
        On first ``get_gpu_engine`` after such a recovery, rebuild
        the GPU engine from the CPU engine's call graph — costs one
        ``from_trailmark(engine)`` invocation (a few seconds even on
        monorepo-scale graphs because it's a single CSR build, not a
        re-index). Subsequent calls hit the cached engine.
        """
        from audit_mcp.gpu_graph import from_trailmark  # noqa: PLC0415

        with self._lock:
            entry = self._indexes.get(index_id)
            if entry is None or entry.status != "ready":
                return None
            if entry.gpu_engine is not None:
                return entry.gpu_engine
            cpu_engine = entry.engine
        if cpu_engine is None:
            # CPU engine evicted under LRU — trigger reload via get_engine
            # which knows how to pull from the disk store.
            cpu_engine = self.get_engine(index_id)
            if cpu_engine is None:
                return None
        gpu_engine = from_trailmark(cpu_engine)
        with self._lock:
            entry_again = self._indexes.get(index_id)
            if entry_again is not None:
                entry_again.gpu_engine = gpu_engine
        return gpu_engine

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
            from audit_mcp.gpu_graph import from_trailmark

            progress = IndexProgress()
            indexer = FastIndexer()
            engine = indexer.index(
                entry.root_path,
                language=entry.language,
                progress=progress,
            )
            summary = engine.summary()
            preanalysis = engine.preanalysis()

            # Build GPU graph engine (CSR adjacency + optional CUDA)
            gpu_engine = from_trailmark(engine)
            with self._lock:
                entry.engine = engine
                entry.gpu_engine = gpu_engine
                entry.summary = summary
                entry.preanalysis = preanalysis
                entry.status = "ready"
                entry.finished_at = time.time()
            # Persist to durable store so index survives restart
            self._store.register(index_id, entry.root_path, entry.language)
            self._store.mark_ready(index_id, engine, summary, preanalysis)
            gpu_info = gpu_engine.info() if gpu_engine else {"backend": "unavailable"}
            _log.info(
                "index %s ready: %d functions, %d edges (%.1fs) "
                "[parsed=%d cached=%d failed=%d] gpu=%s",
                index_id,
                summary.get("functions", 0),
                summary.get("call_edges", 0),
                entry.finished_at - entry.started_at,
                progress.parsed_files,
                progress.cached_files,
                progress.failed_files,
                gpu_info.get("backend", "?"),
            )
        except (OSError, ValueError, RuntimeError, ImportError, MemoryError) as exc:
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
        """Move *index_id* to most-recently-used (must hold _lock). O(1)."""
        self._access_order.pop(index_id, None)
        self._access_order[index_id] = None

    def _maybe_evict_locked(self) -> None:
        """Evict LRU engines until loaded count <= budget (must hold _lock)."""
        loaded_count = sum(1 for e in self._indexes.values() if e.engine is not None)
        while loaded_count > self._max_loaded and self._access_order:
            victim_id, _ = self._access_order.popitem(last=False)  # pop oldest
            victim = self._indexes.get(victim_id)
            if victim is not None and victim.engine is not None:
                _log.info(
                    "evicting engine %s (loaded=%d, budget=%d)",
                    victim_id, loaded_count, self._max_loaded,
                )
                victim.engine = None
                self._eviction_count += 1
                loaded_count -= 1

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

    # ------------------------------------------------------------------
    # Semble integration — semantic + BM25 chunk retrieval
    # ------------------------------------------------------------------
    #
    # semble is a CPU-only chunk-retrieval engine (static Model2Vec
    # embeddings + BM25 + RRF + heuristic reranker). Built lazily per
    # index on first ``get_semble_index`` call: indexing nginx takes
    # ~250ms and even firefox-scale only ~13s, so blocking the first
    # caller is cheaper than blocking every index-start with a long
    # cold-build path.
    #
    # The semble index lives in RAM next to the trailmark engine. They
    # share the same ``root_path``; semble chunks files with tree-sitter
    # (its own parse, independent of trailmark's graph parse) so it can
    # answer "give me chunks containing X" queries without touching the
    # graph engine at all.

    _SEMBLE_MODEL: Any = None  # singleton, loaded once per process

    @classmethod
    def _semble_model(cls) -> Any:
        """Load and cache the potion-code-16M static embedding model.

        Returns None when semble is not installed — get_semble_index
        then returns None too and callers fall back to legacy paths.
        """
        if cls._SEMBLE_MODEL is not None:
            return cls._SEMBLE_MODEL
        try:
            from model2vec import StaticModel
        except ImportError:
            return None
        # Prefer a local-dir copy when present (avoids HF symlink-
        # permission issues on Windows). Falls back to HF cache.
        local_paths = [
            os.environ.get("AUDIT_MCP_SEMBLE_MODEL_DIR", ""),
            os.path.join(os.path.expanduser("~"), ".semble-models", "potion-code-16M"),
        ]
        for p in local_paths:
            if p and os.path.isdir(p):
                try:
                    cls._SEMBLE_MODEL = StaticModel.from_pretrained(p)
                    return cls._SEMBLE_MODEL
                except (OSError, RuntimeError):
                    continue
        try:
            cls._SEMBLE_MODEL = StaticModel.from_pretrained("minishlab/potion-code-16M")
        except (OSError, RuntimeError) as exc:
            _log.warning(
                "semble model load failed: %s — semantic_search/find_related disabled",
                exc,
            )
            return None
        return cls._SEMBLE_MODEL

    def get_semble_index(self, index_id: str) -> Any:
        """Return the semble.SembleIndex for ``index_id``, building it
        on first call. Returns None when semble isn't installed or the
        index is unknown / not ready.

        Per-entry double-checked locking: only one thread builds while
        others wait, so a 13s firefox cold build doesn't fan out to 3
        parallel builds when three branches all need it at once.
        """
        with self._lock:
            entry = self._indexes.get(index_id)
            if entry is None or entry.status != "ready":
                return None
            if entry.semble_index is not None:
                return entry.semble_index
            if entry.semble_lock is None:
                entry.semble_lock = threading.Lock()
            lock = entry.semble_lock
            root_path = entry.root_path

        with lock:
            # Re-check inside lock — another thread may have built it.
            with self._lock:
                entry = self._indexes.get(index_id)
                if entry is None:
                    return None
                if entry.semble_index is not None:
                    return entry.semble_index

            try:
                from semble import SembleIndex
            except ImportError:
                _log.warning("semble not installed; semantic_search/find_related disabled")
                return None

            model = self._semble_model()
            if model is None:
                return None

            # Persistence cache: semble has no save/load API but pickle
            # works on the SembleIndex object. We cache to disk under
            # ~/.audit-mcp/semble-cache/<index_id>.pkl so cold-restart
            # cost is paid ONCE per index, not per process. Cache is
            # keyed by index_id + root_path (root_path embedded in the
            # pickled instance so a different repo at the same index_id
            # — never happens but safety — won't load).
            import pickle  # noqa: PLC0415
            from pathlib import Path  # noqa: PLC0415

            cache_dir = Path.home() / ".audit-mcp" / "semble-cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path = cache_dir / f"{index_id}.pkl"

            sidx = None
            if cache_path.exists():
                t0 = time.time()
                try:
                    with cache_path.open("rb") as f:
                        loaded = pickle.load(f)
                    # Validate: must be a SembleIndex with matching root.
                    if (
                        isinstance(loaded, SembleIndex)
                        and getattr(loaded, "_root", None) is not None
                        and str(loaded._root).replace("\\", "/").lower()
                        == root_path.replace("\\", "/").lower()
                    ):
                        # Re-attach the live model (encoders may not
                        # pickle cleanly across versions; safer to use
                        # the singleton).
                        loaded.model = model
                        sidx = loaded
                        _log.info(
                            "semble index loaded for %s from cache in %.1fs",
                            index_id, time.time() - t0,
                        )
                    else:
                        _log.warning(
                            "semble cache stale for %s (root mismatch) — rebuilding",
                            index_id,
                        )
                except (pickle.UnpicklingError, AttributeError, EOFError,
                        OSError, ImportError) as exc:
                    _log.warning(
                        "semble cache unreadable for %s (%s) — rebuilding",
                        index_id, exc,
                    )

            if sidx is None:
                t0 = time.time()
                try:
                    sidx = SembleIndex.from_path(root_path, model=model)
                except (OSError, ValueError, RuntimeError) as exc:
                    _log.warning("semble build failed for %s: %s", index_id, exc)
                    return None
                elapsed = time.time() - t0
                _log.info(
                    "semble index built for %s in %.1fs (root=%s)",
                    index_id, elapsed, root_path,
                )
                # Persist for next process: pickle the freshly-built
                # index. Strip the model field first (don't re-pickle
                # the singleton Encoder — it'll be re-attached on load).
                try:
                    saved_model = sidx.model
                    sidx.model = None  # type: ignore[assignment]
                    with cache_path.open("wb") as f:
                        pickle.dump(sidx, f, protocol=pickle.HIGHEST_PROTOCOL)
                    sidx.model = saved_model
                    _log.info(
                        "semble cache written for %s -> %s",
                        index_id, cache_path,
                    )
                except (pickle.PicklingError, OSError, RecursionError) as exc:
                    _log.warning(
                        "semble cache write failed for %s: %s "
                        "(continuing without cache)",
                        index_id, exc,
                    )
                    try:
                        sidx.model = model
                    except AttributeError:
                        pass

            with self._lock:
                entry = self._indexes.get(index_id)
                if entry is not None:
                    entry.semble_index = sidx
            return sidx
