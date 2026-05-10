"""Codebase partitioning for large-scale indexing.

Solves the Chromium problem: 35M LOC cannot be loaded into one in-memory
graph. Instead, we partition the codebase into components (directories,
modules, build targets) and index each one independently. Cross-partition
edges are tracked separately as "boundary edges."

Strategy:
1. Discover partitions (top-level dirs, or build system modules)
2. Index each partition as a separate trailmark graph
3. Record cross-partition calls as boundary edges
4. Queries spanning partitions resolve via boundary lookup

This gives O(partition_size) memory per index instead of O(codebase_size).
A 35M LOC codebase with 200 partitions = ~175K LOC average per partition,
which trailmark handles in <10 seconds.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Partitioner", "PartitionPlan", "Partition"]

_log = logging.getLogger(__name__)

# Directories commonly excluded from security analysis
_DEFAULT_EXCLUDE: frozenset[str] = frozenset({
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "venv", ".venv", "__pycache__",
    "build", "out", "dist", "target",
    ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "docs", "doc", "documentation",
    "test", "tests", "testing", "test_data", "testdata",
    "examples", "samples", "demo", "demos",
    "benchmarks", "perf",
})

# Directories that are third-party / vendored code
_THIRD_PARTY_MARKERS: frozenset[str] = frozenset({
    "third_party", "thirdparty", "3rdparty", "external", "extern",
    "vendor", "vendored", "deps",
})

# Max files per partition before auto-splitting
_MAX_FILES_PER_PARTITION = 5000

# Max total files before forcing partitioned mode
_FORCE_PARTITION_THRESHOLD = 10000


@dataclass(frozen=True, slots=True)
class Partition:
    """One indexable unit of a codebase."""

    name: str
    path: str
    is_third_party: bool = False
    estimated_files: int = 0


@dataclass
class PartitionPlan:
    """A plan for indexing a large codebase in parts."""

    root_path: str
    partitions: list[Partition] = field(default_factory=list)
    excluded_dirs: list[str] = field(default_factory=list)
    total_files: int = 0
    total_partitions: int = 0
    needs_partitioning: bool = False
    reason: str = ""


class Partitioner:
    """Analyze a codebase and produce a partition plan."""

    def __init__(
        self,
        exclude: frozenset[str] | None = None,
        third_party_markers: frozenset[str] | None = None,
        max_files_per_partition: int = _MAX_FILES_PER_PARTITION,
    ) -> None:
        self._exclude = exclude or _DEFAULT_EXCLUDE
        self._third_party = third_party_markers or _THIRD_PARTY_MARKERS
        self._max_files = max_files_per_partition

    def plan(self, root_path: str) -> PartitionPlan:
        """Analyze the codebase and produce a partition plan.

        Returns a plan describing how to index the codebase:
        - If total files < threshold: single partition (no splitting needed)
        - If total files >= threshold: multiple partitions by top-level directory
        """
        root = Path(root_path).resolve()
        if not root.is_dir():
            return PartitionPlan(
                root_path=str(root),
                reason=f"Not a directory: {root}",
            )

        # Count files and discover top-level structure
        top_dirs: list[tuple[str, Path, int, bool]] = []  # (name, path, file_count, is_3p)
        excluded: list[str] = []
        loose_files = 0

        for entry in sorted(root.iterdir()):
            if entry.name.startswith("."):
                continue
            if entry.name.lower() in self._exclude:
                excluded.append(entry.name)
                continue
            if entry.is_file():
                loose_files += 1
                continue
            if entry.is_dir():
                is_3p = entry.name.lower() in self._third_party
                count = self._count_source_files(entry)
                if count > 0:
                    top_dirs.append((entry.name, entry, count, is_3p))

        total = sum(c for _, _, c, _ in top_dirs) + loose_files

        if total < _FORCE_PARTITION_THRESHOLD:
            # Small enough for single-graph indexing
            return PartitionPlan(
                root_path=str(root),
                partitions=[Partition(
                    name="root",
                    path=str(root),
                    estimated_files=total,
                )],
                excluded_dirs=excluded,
                total_files=total,
                total_partitions=1,
                needs_partitioning=False,
                reason=f"Single partition: {total} files < {_FORCE_PARTITION_THRESHOLD} threshold",
            )

        # Large codebase — partition by top-level directory
        partitions: list[Partition] = []

        for name, path, count, is_3p in top_dirs:
            if count > self._max_files:
                # Sub-partition large directories
                sub_parts = self._sub_partition(name, path, is_3p)
                partitions.extend(sub_parts)
            else:
                partitions.append(Partition(
                    name=name,
                    path=str(path),
                    is_third_party=is_3p,
                    estimated_files=count,
                ))

        if loose_files > 0:
            partitions.append(Partition(
                name="__root_files__",
                path=str(root),
                estimated_files=loose_files,
            ))

        return PartitionPlan(
            root_path=str(root),
            partitions=partitions,
            excluded_dirs=excluded,
            total_files=total,
            total_partitions=len(partitions),
            needs_partitioning=True,
            reason=(
                f"Partitioned: {total} files across {len(partitions)} partitions "
                f"(threshold={_FORCE_PARTITION_THRESHOLD})"
            ),
        )

    def _sub_partition(
        self, parent_name: str, path: Path, is_3p: bool,
    ) -> list[Partition]:
        """Split a large directory into sub-partitions by its children."""
        result: list[Partition] = []
        remaining_files = 0

        for entry in sorted(path.iterdir()):
            if not entry.is_dir():
                remaining_files += 1
                continue
            if entry.name.startswith(".") or entry.name.lower() in self._exclude:
                continue
            count = self._count_source_files(entry)
            if count > 0:
                child_3p = is_3p or entry.name.lower() in self._third_party
                result.append(Partition(
                    name=f"{parent_name}/{entry.name}",
                    path=str(entry),
                    is_third_party=child_3p,
                    estimated_files=count,
                ))

        if remaining_files > 0:
            result.append(Partition(
                name=f"{parent_name}/__files__",
                path=str(path),
                is_third_party=is_3p,
                estimated_files=remaining_files,
            ))

        return result

    def _count_source_files(self, directory: Path) -> int:
        """Count source files (by extension) under a directory."""
        count = 0
        try:
            for root_str, dirs, files in os.walk(directory):
                # Prune excluded directories
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in self._exclude and not d.startswith(".")
                ]
                for f in files:
                    if _is_source_file(f):
                        count += 1
        except PermissionError:
            pass
        return count


_SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".java", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cc", ".hh", ".cxx",
    ".cs", ".php", ".rb", ".kt", ".kts", ".swift", ".m", ".mm",
    ".sol", ".cairo", ".circom", ".hs", ".erl", ".dart",
})


def _is_source_file(filename: str) -> bool:
    """Check if a filename has a recognized source code extension."""
    _, ext = os.path.splitext(filename)
    return ext.lower() in _SOURCE_EXTENSIONS
