# Audit-MCP Fuzzing Subsystem Design

## Goal

Add a first-class fuzzing capability to audit-mcp so callers can:
1. Configure and start fuzzing campaigns from MCP tools
2. Check live stats (executions/sec, crashes, coverage) at any time
3. Retrieve crashes with auto-triage (sandbox violation vs harmless)
4. Manage corpus (seeds, interesting inputs) per campaign
5. Compose multiple strategies (mutational, generative, differential, coverage-guided)

Non-goal for v1: distributed fuzzing across machines (FUZZILLI tree hierarchy). Single-machine multi-process.

## Best practices synthesized

### From FUZZILLI (saelo / Project Zero)
- **REPRL** (read-eval-print-reset-loop) avoids process spawn overhead per testcase. ~10-100x faster than `--script.js` runs.
- **Custom IR** (FuzzIL) for mutation. Mutating IR > mutating JS source because syntactic validity is preserved.
- **Mutators**: Input, CodeGen, Combine, Operation. Each preserves a semantic property.
- **Event-driven**: components communicate via events for decoupling and observability.
- **Coverage-guided**: testcases that hit new edges are kept in corpus; mutations are biased toward novel coverage.
- **Minimization**: crashes are auto-shrunk to minimal reproducer.

### From ClusterFuzz (Google production)
- **Operations**: `fuzz`, `progression`, `regression`, `minimize`, `corpus_pruning`, `analyze`. Each is a separate task type.
- **Two-tier**: control plane (job scheduler) + worker bots (execute tasks).
- **Primitives**: Job (target+config), Testcase (crashing input), Corpus (interesting inputs), Stats (time series).
- **Auto-triage**: dedupe by stack hash; classify by sanitizer report.

### From audit-mcp existing patterns
- `@mcp.tool()` decorator on top-level functions in `server.py`.
- Dict envelopes with `status` field (`ready`/`pending`/`error`) for poll-friendly UX.
- Singleton managers (`index_manager`, `task_runner`) hold cross-call state.
- `TaskRunner` for blocking work that returns immediately with `task_id`, then poll.
- Existing `GeneratorFuzzer` (`generator_fuzzer.py`) is single-shot blocking — needs to be wrapped or replaced for campaigns.

## Module layout

```
audit_mcp/fuzzing/
├── __init__.py
├── manager.py           # CampaignManager singleton (mirrors IndexManager)
├── campaign.py          # Campaign dataclass + lifecycle states
├── triage.py            # Classify crashes (sandbox_violation, in_sandbox, timeout, oom, etc.)
├── storage.py           # FS-backed corpus + crash store under ~/.audit-mcp/fuzz/
├── stats.py             # Time-series stats aggregator
├── strategies/
│   ├── __init__.py
│   ├── base.py          # FuzzStrategy ABC
│   ├── mutational.py    # In-process JS mutator using L2 forge + descriptor swap (existing primitives)
│   ├── differential.py  # Run same input through Ignition, Liftoff, Maglev, TurboFan; report divergence
│   └── fuzzilli.py      # FUZZILLI subprocess wrapper (when binary detected)
└── engines/
    ├── __init__.py
    ├── base.py          # FuzzEngine ABC (binary path, args, REPRL support)
    ├── v8.py            # V8 d8 with --sandbox-testing
    └── pdfium.py        # pdfium_test.exe with --js-flags=--sandbox-testing
```

## Data model

### Campaign
```python
@dataclass
class Campaign:
    campaign_id: str           # short hex, like task_id
    strategy: str              # "mutational" | "differential" | "fuzzilli"
    engine: str                # "v8_sbx" | "v8_asan" | "pdfium_sbx"
    target_path: str           # absolute path to engine binary
    config: dict[str, Any]     # strategy-specific config
    status: str                # "starting" | "running" | "paused" | "stopped" | "error"
    started_at: float          # unix ts
    stopped_at: float | None
    workdir: Path              # ~/.audit-mcp/fuzz/<campaign_id>/
    process_ids: list[int]     # spawned subprocesses
    stats_snapshot: dict       # latest stats
```

### Finding (crash or interesting)
```python
@dataclass
class Finding:
    finding_id: str            # short hex
    campaign_id: str
    kind: str                  # "crash" | "interesting" | "divergence"
    classification: str        # "sandbox_violation" | "in_sandbox" | "csa_check" | "timeout" | "oom" | "harmless"
    reproducer_path: Path      # absolute path to reproducer file
    stack_hash: str            # for dedup
    discovered_at: float
    details: dict              # full sanitizer/crash output
```

### Stats snapshot
```python
{
    "campaign_id": ...,
    "uptime_seconds": ...,
    "iterations": ...,
    "execs_per_sec": ...,
    "crashes_total": ...,
    "crashes_by_classification": {"sandbox_violation": 0, "in_sandbox": 1234, ...},
    "unique_crashes": ...,           # by stack hash
    "corpus_size": ...,
    "coverage_edges": ...,           # if FUZZILLI/coverage-guided
    "last_crash_at": ...,
    "last_finding_at": ...,
}
```

## MCP tools (final list)

### Campaign lifecycle
```
fuzz_start(strategy, engine, config={}) -> {campaign_id, status, workdir}
fuzz_stop(campaign_id) -> {status}
fuzz_pause(campaign_id) -> {status}
fuzz_resume(campaign_id) -> {status}
fuzz_list_campaigns() -> {campaigns: [...]}
fuzz_campaign_info(campaign_id) -> {full campaign details + stats snapshot}
```

### Stats (read-only, fast)
```
fuzz_stats(campaign_id) -> {stats snapshot}
fuzz_stats_summary() -> {aggregate across all campaigns}
fuzz_stats_timeline(campaign_id, metric, since=None) -> {time series}
```

### Findings
```
fuzz_list_findings(campaign_id=None, classification=None, since=None, limit=50) -> {findings: [...]}
fuzz_finding_info(finding_id) -> {finding + reproducer content}
fuzz_minimize_finding(finding_id) -> {task_id (background minimization)}
```

### Strategy/engine catalog
```
fuzz_list_strategies() -> {strategies: [{name, description, config_schema}, ...]}
fuzz_list_engines() -> {engines: [{name, binary_path, status}, ...]}
fuzz_register_engine(name, binary_path, default_args=[]) -> {engine_id}
```

## Strategies for v1

### `mutational`
Uses our proven L2 byte_length forge + descriptor swap primitives in JS. Runs the existing `fuzz_v8_sbx_v3.js`-style harness.

Config:
```python
{
    "iterations_per_seed": 30,        # iterations before respawn
    "seeds_per_minute": None,         # rate limit (None = unlimited)
    "primitives": ["forge", "descswap", "field_corrupt"],
    "operations": ["json", "structuredClone", "iter", "wasm", "regex"],
}
```

### `differential`
Run same JS through V8's interpreter (Ignition), baseline JIT (Sparkplug), Maglev, TurboFan. Compare outputs. Divergence = JIT bug.

Config:
```python
{
    "tiers": ["ignition", "sparkplug", "maglev", "turbofan"],
    "test_duration_ms": 100,
    "compare_strategy": "exact_output",  # or "side_effects" or "exception_kind"
}
```

Engine support: V8 d8 with `%PrepareFunctionForOptimization`, `%OptimizeFunctionOnNextCall` etc.

### `fuzzilli` (when available)
Subprocess wrapper around FUZZILLI. Requires:
- `fuzzilli` binary at known path (configured via `fuzz_register_engine`)
- V8 built with REPRL+coverage (see FUZZILLI's `Targets/V8/Patches/v8.patch`)

Config:
```python
{
    "profile": "v8",
    "jobs": 4,                      # parallel REPRL workers
    "engine_args": [],
    "minimization_limit": 1000,
}
```

## Triage logic

For V8 sandbox fuzzing, classify by output string match:
- `"## V8 sandbox violation detected!"` → **sandbox_violation** (HIGHEST PRIORITY)
- `"AddressSanitizer:"` (without containment in safe region) → **asan**
- `"harmless memory access violation (inside sandbox)"` → **in_sandbox**
- `"harmless memory access violation (safe region)"` → **safe_region**
- `"CSA check failure"` → **csa_check**
- `"AllowHeapAllocation"` → **gc_check**
- timeout (no output in N sec) → **timeout**
- exit code OOM → **oom**
- everything else → **unknown** (kept for manual review)

Stack hash: SHA-256 of normalized stack trace (strip addresses, line numbers within file).

## Storage layout

```
~/.audit-mcp/fuzz/
├── <campaign_id>/
│   ├── campaign.json           # serialized Campaign
│   ├── corpus/
│   │   ├── seed_0.js
│   │   └── ...
│   ├── findings/
│   │   ├── <finding_id>/
│   │   │   ├── reproducer.js
│   │   │   ├── output.txt      # full stderr
│   │   │   └── meta.json
│   │   └── ...
│   ├── stats.jsonl             # append-only stat snapshots
│   └── worker.log              # worker stdout/stderr
```

## Implementation phases

**Phase 1 (this implementation):**
- Core data model (`Campaign`, `Finding`, `StatsSnapshot`)
- `CampaignManager` singleton
- `mutational` strategy using existing v3 fuzzer JS
- V8 engine wrapper (Linux d8 with --sandbox-testing)
- Triage logic
- 9 MCP tools (start, stop, pause, resume, list, info, stats, findings, finding_info)

**Phase 2 (follow-up if value proven):**
- `differential` strategy
- `fuzzilli` strategy
- Minimization
- Corpus management tools
- Time-series stats with aggregation

**Phase 3 (later):**
- Multi-machine distribution
- Web UI for campaign monitoring
- ClusterFuzz integration (push findings to Monorail)

## Anti-goals (what we explicitly do NOT do)

- Re-implement FUZZILLI's mutation engine. We wrap, not replace.
- Implement our own coverage instrumentation. Use sancov/AFL when available.
- Try to find ALL crashes. Auto-classify aggressively, surface only sandbox violations + ASAN findings + divergence by default.
- Support every JS engine. V8 first, others as needed.
- Build a full ClusterFuzz. We're the toolkit, not the platform.
