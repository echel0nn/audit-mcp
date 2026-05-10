"""Tests for the thread-based TaskRunner."""

from __future__ import annotations

import time

import pytest

from audit_mcp.tasks import TaskRecord, TaskRunner

_POLL_INTERVAL = 0.05
_POLL_TIMEOUT = 5.0


def _wait_for_terminal(runner: TaskRunner, task_id: str) -> dict:
    """Poll ``task_id`` until status is no longer 'running' or timeout expires."""
    deadline = time.monotonic() + _POLL_TIMEOUT
    while time.monotonic() < deadline:
        snapshot = runner.poll(task_id)
        if snapshot.get("status") != "running":
            return snapshot
        time.sleep(_POLL_INTERVAL)
    raise AssertionError(f"task {task_id} did not finish within {_POLL_TIMEOUT}s")


def test_submit_and_poll_success() -> None:
    runner = TaskRunner()

    def work() -> dict:
        time.sleep(0.05)
        return {"status": "ready", "count": 42}

    task_id = runner.submit("unit-test", "idx-1", work)
    assert isinstance(task_id, str) and task_id

    snapshot = _wait_for_terminal(runner, task_id)

    assert snapshot["status"] == "completed"
    assert snapshot["progress_pct"] == 100
    assert snapshot["task_id"] == task_id
    assert snapshot["kind"] == "unit-test"
    assert snapshot["index_id"] == "idx-1"
    assert snapshot["result"] == {"status": "ready", "count": 42}
    assert "error" not in snapshot
    assert "elapsed_seconds" in snapshot


def test_submit_and_poll_error() -> None:
    runner = TaskRunner()

    def boom() -> dict:
        time.sleep(0.05)
        raise ValueError("boom")

    task_id = runner.submit("unit-test", "idx-err", boom)

    snapshot = _wait_for_terminal(runner, task_id)

    assert snapshot["status"] == "error"
    assert "error" in snapshot
    assert "boom" in snapshot["error"]
    assert "result" not in snapshot


def test_poll_unknown_task() -> None:
    runner = TaskRunner()

    snapshot = runner.poll("does-not-exist")

    assert snapshot["status"] == "error"
    assert "Unknown task_id" in snapshot["error"]
    assert "does-not-exist" in snapshot["error"]


def test_list_tasks() -> None:
    runner = TaskRunner()

    def quick() -> dict:
        return {"ok": True}

    ids = [runner.submit("unit-test", f"idx-{i}", quick) for i in range(3)]

    # Wait for all to finish so list output is stable.
    for task_id in ids:
        _wait_for_terminal(runner, task_id)

    listed = runner.list_tasks()
    assert isinstance(listed, list)
    assert len(listed) == 3

    listed_ids = {entry["task_id"] for entry in listed}
    assert listed_ids == set(ids)
    for entry in listed:
        assert entry["status"] == "completed"


def test_concurrent_tasks() -> None:
    runner = TaskRunner()

    def sleeper() -> dict:
        time.sleep(0.1)
        return {"ok": True}

    start = time.monotonic()
    ids = [runner.submit("unit-test", f"idx-{i}", sleeper) for i in range(5)]
    for task_id in ids:
        snapshot = _wait_for_terminal(runner, task_id)
        assert snapshot["status"] == "completed"
    elapsed = time.monotonic() - start

    # Sequential execution would take ~0.5s; concurrent should be well under 2s.
    assert elapsed < 2.0, f"concurrent tasks took {elapsed:.2f}s, expected <2.0s"


def test_task_record_to_dict() -> None:
    record = TaskRecord(
        task_id="abc123",
        kind="scan",
        index_id="idx-7",
        status="completed",
        progress_pct=100,
        result={"hits": 3},
        started_at=1000.0,
        finished_at=1002.5,
    )

    payload = record.to_dict()

    assert payload["task_id"] == "abc123"
    assert payload["kind"] == "scan"
    assert payload["index_id"] == "idx-7"
    assert payload["status"] == "completed"
    assert payload["progress_pct"] == 100
    assert payload["started_at"] == 1000.0
    assert payload["finished_at"] == 1002.5
    assert payload["result"] == {"hits": 3}
    assert "error" not in payload
    assert payload["elapsed_seconds"] == pytest.approx(2.5)


def test_elapsed_seconds() -> None:
    runner = TaskRunner()

    def slow() -> dict:
        time.sleep(0.2)
        return {"ok": True}

    task_id = runner.submit("unit-test", "idx-elapsed", slow)
    snapshot = _wait_for_terminal(runner, task_id)

    assert snapshot["status"] == "completed"
    assert "elapsed_seconds" in snapshot
    assert snapshot["elapsed_seconds"] >= 0.2
