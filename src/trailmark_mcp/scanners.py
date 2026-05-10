"""Source code scanner orchestration — run SAST tools and import results.

Discovers installed scanners, executes them against indexed codebases,
imports SARIF results into the trailmark graph, and correlates findings
with graph properties (taint, blast radius, entrypoints).

Supported scanners (when installed on the system):
  - semgrep    : 30+ languages, pattern-based (injection, auth, crypto)
  - bandit     : Python, CWE-mapped (eval, exec, subprocess, secrets)
  - trivy      : All languages, secrets + misconfig + dep vulns + IaC
  - bearer     : Ruby/JS/TS/Java/Go/PHP, data flow + PII + OWASP Top 10
  - gosec      : Go-specific (crypto, SQL, file perms)
  - phpstan    : PHP type-level + taint analysis
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["ScannerRunner", "ScannerInfo", "SCANNERS"]

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ScannerInfo:
    """Static metadata for a supported scanner."""

    name: str
    binary: str
    languages: tuple[str, ...]
    description: str
    sarif_args: tuple[str, ...]  # args appended AFTER the target path


SCANNERS: dict[str, ScannerInfo] = {
    "semgrep": ScannerInfo(
        name="semgrep",
        binary="semgrep",
        languages=("python", "java", "javascript", "typescript", "go", "rust",
                    "c", "cpp", "c_sharp", "ruby", "php", "kotlin", "swift"),
        description="Pattern-based SAST: injection, auth bypass, crypto misuse, SSRF, XSS",
        sarif_args=("scan", "--config", "auto", "--sarif", "--quiet"),
    ),
    "bandit": ScannerInfo(
        name="bandit",
        binary="bandit",
        languages=("python",),
        description="Python SAST: eval, exec, subprocess, yaml.load, hardcoded secrets (CWE-mapped)",
        sarif_args=("-r", "{path}", "-f", "sarif", "-q"),
    ),
    "trivy": ScannerInfo(
        name="trivy",
        binary="trivy",
        languages=("python", "java", "javascript", "typescript", "go", "rust",
                    "c", "cpp", "ruby", "php"),
        description="Secrets, misconfig, license issues, dependency vulns, IaC scanning",
        sarif_args=("fs", "--format", "sarif", "--quiet"),
    ),
    "bearer": ScannerInfo(
        name="bearer",
        binary="bearer",
        languages=("ruby", "javascript", "typescript", "java", "go", "php"),
        description="Data flow analysis: PII leaks, OWASP Top 10, sensitive data exposure",
        sarif_args=("scan", "--format", "sarif", "--quiet"),
    ),
    "gosec": ScannerInfo(
        name="gosec",
        binary="gosec",
        languages=("go",),
        description="Go security: crypto misuse, SQL injection, file permissions",
        sarif_args=("-fmt", "sarif", "-quiet"),
    ),
    "phpstan": ScannerInfo(
        name="phpstan",
        binary="phpstan",
        languages=("php",),
        description="PHP static analysis: type errors, taint analysis, dead code",
        sarif_args=("analyse", "--error-format", "sarif", "--no-progress"),
    ),
}


class ScannerRunner:
    """Discover, execute, and import results from SAST scanners."""

    @staticmethod
    def list_installed() -> list[dict[str, Any]]:
        """Return metadata for every scanner whose binary is on PATH."""
        result: list[dict[str, Any]] = []
        for info in SCANNERS.values():
            installed = shutil.which(info.binary) is not None
            result.append({
                "name": info.name,
                "installed": installed,
                "binary": info.binary,
                "languages": list(info.languages),
                "description": info.description,
            })
        return result

    @staticmethod
    def run(scanner_name: str, target_path: str, timeout_seconds: int = 600) -> Path:
        """Execute a scanner and return the path to the SARIF output file.

        Raises RuntimeError if the scanner is not installed or fails.
        """
        info = SCANNERS.get(scanner_name)
        if info is None:
            raise ValueError(f"Unknown scanner: {scanner_name!r}. Available: {sorted(SCANNERS)}")
        if shutil.which(info.binary) is None:
            raise RuntimeError(f"Scanner {scanner_name!r} not installed (binary {info.binary!r} not on PATH)")

        sarif_file = Path(tempfile.mktemp(suffix=".sarif", prefix=f"trailmark_{scanner_name}_"))

        # Build command. Some scanners take the path as a positional arg at the end,
        # others need it interpolated (bandit uses -r {path}).
        cmd: list[str] = [info.binary]
        for arg in info.sarif_args:
            cmd.append(arg.replace("{path}", target_path))

        # Append output redirect or target path depending on scanner
        if scanner_name == "semgrep":
            cmd.extend(["--output", str(sarif_file), target_path])
        elif scanner_name == "bandit":
            cmd.extend(["-o", str(sarif_file)])
        elif scanner_name == "trivy":
            cmd.extend(["--output", str(sarif_file), target_path])
        elif scanner_name == "bearer":
            cmd.extend(["--output", str(sarif_file), target_path])
        elif scanner_name == "gosec":
            cmd.extend(["-out", str(sarif_file), target_path + "/..."])
        elif scanner_name == "phpstan":
            cmd.extend([target_path])
            # phpstan writes to stdout in sarif mode — redirect
            cmd = cmd  # handled below via stdout capture

        _log.info("running scanner: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Scanner {scanner_name} timed out after {timeout_seconds}s") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(f"Scanner binary not found: {info.binary}") from exc

        # Some scanners exit non-zero when they find issues (that's normal)
        # Only treat as error if no SARIF was produced
        if scanner_name == "phpstan":
            # phpstan outputs sarif to stdout
            sarif_file.write_text(result.stdout, encoding="utf-8")

        if not sarif_file.exists() or sarif_file.stat().st_size == 0:
            stderr_preview = (result.stderr or "")[:500]
            raise RuntimeError(
                f"Scanner {scanner_name} produced no SARIF output "
                f"(exit={result.returncode}): {stderr_preview}"
            )

        _log.info("scanner %s produced %d bytes SARIF", scanner_name, sarif_file.stat().st_size)
        return sarif_file

    @staticmethod
    def correlate_findings(engine: Any, preanalysis: dict[str, Any]) -> dict[str, Any]:
        """Correlate SARIF-augmented findings with graph properties.

        After augment_sarif has been called, this examines each finding
        node and enriches it with: is it tainted? what's its blast radius?
        is it reachable from an entrypoint?

        Returns a prioritized finding list sorted by risk score.
        """
        from trailmark.models.annotations import AnnotationKind

        finding_nodes = engine.nodes_with_annotation(AnnotationKind.FINDING)
        if not finding_nodes:
            finding_nodes = engine.nodes_with_annotation(AnnotationKind.SARIF_FINDING)

        enriched: list[dict[str, Any]] = []
        for node in finding_nodes:
            node_name = node.get("name", "")
            node_id = node.get("id", "")

            # Check taint status via annotations
            annotations = engine.annotations_of(node_name)
            is_tainted = any(
                a.get("kind") == "taint" for a in annotations
            )

            # Check blast radius
            blast_ann = [
                a for a in annotations
                if a.get("kind") == "blast_radius"
            ]
            blast_desc = blast_ann[0].get("description", "") if blast_ann else ""

            # Check if reachable from entrypoints
            entrypoint_paths = engine.entrypoint_paths_to(node_name, max_depth=10)
            reachable_from_entrypoint = len(entrypoint_paths) > 0

            # Risk score: tainted + high blast + entrypoint-reachable = critical
            risk_score = 0
            if is_tainted:
                risk_score += 40
            if reachable_from_entrypoint:
                risk_score += 40
            if blast_desc:
                # Parse downstream count from "N downstream, M upstream"
                try:
                    downstream = int(blast_desc.split(" ")[0])
                    if downstream >= 50:
                        risk_score += 20
                    elif downstream >= 10:
                        risk_score += 10
                except (ValueError, IndexError):
                    pass

            finding_annotations = [
                a for a in annotations
                if a.get("kind") in ("finding", "sarif_finding")
            ]

            enriched.append({
                "node_id": node_id,
                "name": node_name,
                "file": node.get("location", {}).get("file_path", ""),
                "line": node.get("location", {}).get("start_line", 0),
                "is_tainted": is_tainted,
                "blast_radius": blast_desc,
                "reachable_from_entrypoint": reachable_from_entrypoint,
                "entrypoint_path_count": len(entrypoint_paths),
                "risk_score": risk_score,
                "findings": finding_annotations,
                "complexity": node.get("cyclomatic_complexity", 0),
            })

        enriched.sort(key=lambda x: x["risk_score"], reverse=True)

        # Summary stats
        tainted_count = sum(1 for e in enriched if e["is_tainted"])
        entrypoint_reachable = sum(1 for e in enriched if e["reachable_from_entrypoint"])

        return {
            "total_findings": len(enriched),
            "tainted_findings": tainted_count,
            "entrypoint_reachable_findings": entrypoint_reachable,
            "critical_findings": sum(1 for e in enriched if e["risk_score"] >= 60),
            "findings": enriched,
        }
