"""Thread-based background task runner with poll-for-result semantics.

Long-running tools (scanners, dead-code analysis, unreachable analysis) submit
work to a :class:`TaskRunner`, which dispatches it on a daemon thread and
records progress in an in-memory registry. Callers poll by ``task_id`` to
retrieve status, result, or error.

The runner is intentionally minimal: no priority queue, no cancellation, no
persistence across process restarts. It is the smallest abstraction that
allows MCP tool handlers to return immediately while expensive work proceeds
in the background.
"""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

__all__ = ["TaskRunner", "TaskRecord"]


_RUN_EXCEPTIONS: tuple[type[BaseException], ...] = (
    OSError,
    ValueError,
    RuntimeError,
    TypeError,
    KeyError,
    subprocess.SubprocessError,
)


@dataclass(slots=True)
class TaskRecord:
    """In-memory record for a background task.

    Attributes mirror the JSON shape returned by :meth:`TaskRunner.poll`. All
    mutations are performed by :class:`TaskRunner` under its lock; consumers
    should treat instances as read-only snapshots.
    """

    task_id: str
    kind: str
    index_id: str
    status: str = "running"
    progress_pct: int = 0
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: float = 0.0
    finished_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to a plain dict suitable for JSON encoding."""
        payload: dict[str, Any] = {
            "task_id": self.task_id,
            "kind": self.kind,
            "index_id": self.index_id,
            "status": self.status,
            "progress_pct": self.progress_pct,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
        if self.result is not None:
            payload["result"] = self.result
        if self.error is not None:
            payload["error"] = self.error
        if self.finished_at > 0.0 and self.started_at > 0.0:
            payload["elapsed_seconds"] = self.finished_at - self.started_at
        return payload


@dataclass(slots=True)
class TaskRunner:
    """Daemon-thread task runner with a thread-safe in-memory registry.

    Submitted callables run on dedicated daemon threads and write their result
    or error back into the registry. Threads are not joined on shutdown; the
    daemon flag ensures they do not block process exit.
    """

    _tasks: dict[str, TaskRecord] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def submit(
        self,
        kind: str,
        index_id: str,
        fn: Callable[..., dict[str, Any]],
        **kwargs: Any,
    ) -> str:
        """Submit ``fn`` for background execution and return the task id.

        ``fn`` is invoked as ``fn(**kwargs)`` on a daemon thread. The return
        value (a dict) is stored on the task record; exceptions in
        :data:`_RUN_EXCEPTIONS` are captured into ``record.error``. Other
        exceptions propagate out of the worker thread and crash it; this is
        intentional — unexpected exception types signal programmer error and
        should not be silently swallowed.
        """
        task_id = uuid4().hex[:12]
        record = TaskRecord(
            task_id=task_id,
            kind=kind,
            index_id=index_id,
            started_at=time.time(),
        )
        with self._lock:
            self._tasks[task_id] = record
        thread = threading.Thread(
            target=self._run_task,
            args=(task_id, fn, kwargs),
            name=f"task-{kind}-{task_id}",
            daemon=True,
        )
        thread.start()
        return task_id

    def poll(self, task_id: str) -> dict[str, Any]:
        """Return the serialized status of ``task_id``.

        Unknown ids resolve to a synthetic error payload rather than raising,
        so MCP clients can poll without first checking existence.
        """
        with self._lock:
            record = self._tasks.get(task_id)
            if record is None:
                return {
                    "status": "error",
                    "error": f"Unknown task_id: {task_id}",
                }
            return record.to_dict()

    def list_tasks(self) -> list[dict[str, Any]]:
        """Return a snapshot of every registered task as a dict list."""
        with self._lock:
            return [record.to_dict() for record in self._tasks.values()]

    def _run_task(
        self,
        task_id: str,
        fn: Callable[..., dict[str, Any]],
        kwargs: dict[str, Any],
    ) -> None:
        """Worker entrypoint executed on the daemon thread."""
        try:
            result = fn(**kwargs)
        except _RUN_EXCEPTIONS as exc:
            finished = time.time()
            with self._lock:
                record = self._tasks.get(task_id)
                if record is not None:
                    record.status = "error"
                    record.error = str(exc)
                    record.finished_at = finished
            return
        finished = time.time()
        with self._lock:
            record = self._tasks.get(task_id)
            if record is not None:
                record.status = "completed"
                record.result = result
                record.progress_pct = 100
                record.finished_at = finished
