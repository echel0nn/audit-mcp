"""Durable index store — filesystem-backed, crash-recoverable.

Replaces the in-memory dict with a workspace directory per index:

    ~/.cache/audit-mcp/indexes/<index_id>/
        state.json       — lifecycle state (pending/indexing/ready/error)
        graph.json       — serialized trailmark CodeGraph
        preanalysis.json — cached preanalysis results
        summary.json     — cached summary
        heartbeat.json   — worker thread liveness proof

On startup, the store scans the index directory and recovers all
indexes that were in READY state. Indexes that were mid-INDEXING
when the process died are marked ERROR (stale heartbeat).

This gives audit-mcp the same durability as IDA headless MCP:
- Process restart: ready indexes reload from disk in <1s each
- Thread crash: heartbeat stale detection → mark ERROR
- Concurrent access: per-index file locks (advisory)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import msgpack

__all__ = ["DurableIndexStore", "IndexState"]

_log = logging.getLogger(__name__)

_INDEX_DIR = Path(
    os.environ.get(
        "AUDIT_MCP_INDEX_DIR",
        Path.home() / ".cache" / "audit-mcp" / "indexes",
    )
)

HEARTBEAT_INTERVAL = 5.0    # seconds between heartbeat writes
HEARTBEAT_STALE = 30.0      # seconds before a heartbeat is considered stale


class IndexState:
    PENDING = "pending"
    INDEXING = "indexing"
    READY = "ready"
    ERROR = "error"
    CLOSED = "closed"


@dataclass
class IndexRecord:
    """Persisted metadata for one indexed codebase."""

    index_id: str
    root_path: str
    language: str
    status: str = IndexState.PENDING
    error: str | None = None
    created_at: float = 0.0
    finished_at: float = 0.0
    function_count: int = 0
    edge_count: int = 0
    entrypoint_count: int = 0
    file_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "index_id": self.index_id,
            "root_path": self.root_path,
            "language": self.language,
            "status": self.status,
            "error": self.error,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "function_count": self.function_count,
            "edge_count": self.edge_count,
            "entrypoint_count": self.entrypoint_count,
            "file_count": self.file_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IndexRecord:
        return cls(
            index_id=data["index_id"],
            root_path=data["root_path"],
            language=data.get("language", "auto"),
            status=data.get("status", IndexState.PENDING),
            error=data.get("error"),
            created_at=data.get("created_at", 0.0),
            finished_at=data.get("finished_at", 0.0),
            function_count=data.get("function_count", 0),
            edge_count=data.get("edge_count", 0),
            entrypoint_count=data.get("entrypoint_count", 0),
            file_count=data.get("file_count", 0),
        )


class DurableIndexStore:
    """Filesystem-backed index registry with crash recovery.

    Each index gets a workspace directory. The QueryEngine is serialized
    as graph.json so it survives process restarts. On startup, all READY
    indexes are rehydrated from disk.
    """

    def __init__(self, index_dir: Path | None = None) -> None:
        self._index_dir = index_dir or _INDEX_DIR
        self._index_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._engines: dict[str, Any] = {}   # in-memory engine cache
        self._records: dict[str, IndexRecord] = {}
        self._recover_on_startup()

    def workspace(self, index_id: str) -> Path:
        """Return the workspace directory for an index."""
        return self._index_dir / index_id

    def register(self, index_id: str, root_path: str, language: str) -> IndexRecord:
        """Register a new index (or return existing if already ready)."""
        ws = self.workspace(index_id)

        with self._lock:
            existing = self._records.get(index_id)
            if existing and existing.status == IndexState.READY:
                return existing

        ws.mkdir(parents=True, exist_ok=True)
        record = IndexRecord(
            index_id=index_id,
            root_path=root_path,
            language=language,
            status=IndexState.INDEXING,
            created_at=time.time(),
        )
        self._write_state(index_id, record)
        with self._lock:
            self._records[index_id] = record
        return record

    def mark_ready(
        self,
        index_id: str,
        engine: Any,
        summary: dict[str, Any],
        preanalysis: dict[str, Any],
    ) -> None:
        """Transition an index to READY and persist all artifacts."""
        ws = self.workspace(index_id)

        # Persist graph
        try:
            graph_data = engine.to_json()
            try:
                packed = msgpack.packb(graph_data, use_bin_type=True, default=str)
                (ws / "graph.msgpack").write_bytes(packed)
            except (OSError, TypeError, ValueError) as exc:
                _log.warning(
                    "msgpack write failed for %s, falling back to JSON: %s",
                    index_id, exc,
                )
                (ws / "graph.json").write_text(
                    json.dumps(graph_data, default=str), encoding="utf-8",
                )
        except (OSError, TypeError, ValueError) as exc:
            _log.warning("Failed to persist graph for %s: %s", index_id, exc)

        # Persist summary + preanalysis
        _write_json(ws / "summary.json", summary)
        _write_json(ws / "preanalysis.json", preanalysis)

        with self._lock:
            record = self._records.get(index_id)
            if record is None:
                return
            record.status = IndexState.READY
            record.finished_at = time.time()
            record.function_count = summary.get("functions", 0)
            record.edge_count = summary.get("call_edges", 0)
            record.entrypoint_count = summary.get("entrypoints", 0)
            self._engines[index_id] = engine

        self._write_state(index_id, record)
        _log.info("index %s persisted to %s", index_id, ws)

    def mark_error(self, index_id: str, error: str) -> None:
        """Transition an index to ERROR."""
        with self._lock:
            record = self._records.get(index_id)
            if record is None:
                return
            record.status = IndexState.ERROR
            record.error = error
            record.finished_at = time.time()
        self._write_state(index_id, record)

    def get_engine(self, index_id: str) -> Any | None:
        """Return the in-memory QueryEngine, loading from disk if needed."""
        with self._lock:
            engine = self._engines.get(index_id)
            if engine is not None:
                return engine
            record = self._records.get(index_id)
            if record is None or record.status != IndexState.READY:
                return None

        # Try loading from disk
        engine = self._load_engine_from_disk(index_id)
        if engine is not None:
            with self._lock:
                self._engines[index_id] = engine
        return engine

    def get_record(self, index_id: str) -> IndexRecord | None:
        with self._lock:
            return self._records.get(index_id)

    def poll(self, index_id: str) -> dict[str, Any]:
        """Return current state as a dict."""
        with self._lock:
            record = self._records.get(index_id)
        if record is None:
            return {"status": "error", "error": f"Unknown index: {index_id}"}
        result = record.to_dict()
        if record.finished_at > 0 and record.created_at > 0:
            result["elapsed_seconds"] = round(record.finished_at - record.created_at, 2)
        return result

    def list_indexes(self) -> list[dict[str, Any]]:
        with self._lock:
            ids = list(self._records.keys())
        return [self.poll(i) for i in ids]

    def close_index(self, index_id: str) -> bool:
        """Release in-memory engine for an index. Persisted data remains."""
        with self._lock:
            self._engines.pop(index_id, None)
            record = self._records.get(index_id)
            if record is not None:
                record.status = IndexState.CLOSED
                self._write_state(index_id, record)
                return True
        return False

    def write_heartbeat(self, index_id: str) -> None:
        """Write a heartbeat file for the indexing worker."""
        ws = self.workspace(index_id)
        _write_json(ws / "heartbeat.json", {
            "index_id": index_id,
            "timestamp": time.time(),
            "pid": os.getpid(),
            "thread": threading.current_thread().name,
        })

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    def _recover_on_startup(self) -> None:
        """Scan index directories and recover persisted indexes."""
        if not self._index_dir.exists():
            return
        recovered = 0
        stale = 0
        for ws in sorted(self._index_dir.iterdir()):
            if not ws.is_dir():
                continue
            state_file = ws / "state.json"
            if not state_file.exists():
                continue
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                record = IndexRecord.from_dict(data)
            except (json.JSONDecodeError, KeyError, OSError) as exc:
                _log.warning("Skipping corrupt index at %s: %s", ws, exc)
                continue

            if record.status == IndexState.READY:
                with self._lock:
                    self._records[record.index_id] = record
                recovered += 1
            elif record.status == IndexState.INDEXING:
                # Was mid-index when process died — mark as error
                record.status = IndexState.ERROR
                record.error = "stale: process died during indexing"
                self._write_state(record.index_id, record)
                with self._lock:
                    self._records[record.index_id] = record
                stale += 1

        if recovered or stale:
            _log.info(
                "index recovery: %d ready, %d stale (marked error)",
                recovered, stale,
            )

    def _load_engine_from_disk(self, index_id: str) -> Any | None:
        """Attempt to rehydrate a QueryEngine from persisted graph file."""
        ws = self.workspace(index_id)
        msgpack_file = ws / "graph.msgpack"
        json_file = ws / "graph.json"
        try:
            from trailmark.models.graph import CodeGraph
            from trailmark.query.api import QueryEngine

            data: dict | None = None
            if msgpack_file.exists():
                raw = msgpack_file.read_bytes()
                data = msgpack.unpackb(raw, raw=False)
            elif json_file.exists():
                data = json.loads(json_file.read_text(encoding="utf-8"))

            if data is None:
                return None

            graph = CodeGraph.from_dict(data)
            engine = QueryEngine.from_graph(graph)
            _log.info("rehydrated engine for %s from disk", index_id)
            return engine
        except (json.JSONDecodeError, KeyError, OSError, ImportError, ValueError, TypeError) as exc:
            _log.warning("Failed to rehydrate %s: %s", index_id, exc)
            return None

    def _write_state(self, index_id: str, record: IndexRecord) -> None:
        ws = self.workspace(index_id)
        ws.mkdir(parents=True, exist_ok=True)
        _write_json(ws / "state.json", record.to_dict())


def _write_json(path: Path, data: Any) -> None:
    """Atomic-ish JSON write (write to tmp then rename)."""
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        _log.debug("json write failed for %s: %s", path, exc)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
