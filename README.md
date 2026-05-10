# audit-mcp

Graph-first source code audit MCP server. Parses codebases into a queryable call graph, maps attack surfaces, runs SAST scanners, and tells you which 5 of 200 findings actually matter.

Built on [Trail of Bits Trailmark](https://github.com/trailofbits/trailmark) (21 languages). Not another semgrep wrapper.

## Install

```bash
pip install -e .
```

Requires Python 3.12+. Installs `trailmark`, `fastmcp`, `fastapi`, `uvicorn`, `msgpack`.

## Run

### As MCP server (stdio — for Claude Desktop, Cursor, etc.)

```bash
audit-mcp
# or
python -m audit_mcp
```

### As HTTP server (for programmatic access)

```bash
audit-mcp --mode http --port 18822
# API docs at http://127.0.0.1:18822/docs
```

## Configure with Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "audit-mcp": {
      "command": "audit-mcp",
      "args": []
    }
  }
}
```

Or if not installed globally:

```json
{
  "mcpServers": {
    "audit-mcp": {
      "command": "python",
      "args": ["-m", "audit_mcp"],
      "cwd": "/path/to/audit-mcp"
    }
  }
}
```

## Configure with Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "audit-mcp": {
      "command": "audit-mcp",
      "args": []
    }
  }
}
```

## What It Does

### 1. Index a codebase (any of 21 languages)
```
index_codebase(path="/path/to/project")
-> {index_id: "a1b2c3", status: "indexing"}

poll_index(index_id="a1b2c3")
-> {status: "ready", summary: {functions: 4812, call_edges: 18234, entrypoints: 47}}
```

### 2. Map the attack surface
```
attack_surface(index_id="a1b2c3")
-> entrypoints with trust levels, blast radius, framework detection

preanalysis(index_id="a1b2c3")
-> blast radius top-50, privilege boundaries, taint propagation
```

### 3. Run scanners + correlate with graph
```
scan_and_correlate(index_id="a1b2c3", scanner="semgrep")
-> {task_id: "d4e5f6", status: "running"}

poll_task(task_id="d4e5f6")
-> findings sorted by risk_score (tainted + reachable + high blast radius)
```

### 4. Ask security questions
```
taint_paths_to(index_id="a1b2c3", sink_name="eval")
-> all entrypoint-to-eval call paths

callers_of(index_id="a1b2c3", name="parse_input", exclude_hubs=true)
-> direct callers, excluding logging/utility functions

dead_code(index_id="a1b2c3")
-> {task_id: ..., status: "running"}  # async, poll for result

paths_between(index_id="a1b2c3", source="handle_request", target="execute_query")
-> top 5 shortest call paths
```

### 5. Diff versions
```
diff_codebases(index_id_a="v1", index_id_b="v2")
-> added/removed/changed functions, attack surface delta

attack_surface_diff(index_id_a="v1", index_id_b="v2")
-> new entrypoints, removed validation, blast radius changes
```

## Tools (41 total)

| Category | Tools | What |
|---|---|---|
| **Index lifecycle** | `index_codebase`, `poll_index`, `list_indexes` | Parse + analyze codebases |
| **Graph queries** | `callers_of`, `callees_of`, `ancestors_of`, `reachable_from`, `paths_between`, `search_functions` | Navigate the call graph |
| **Security analysis** | `attack_surface`, `preanalysis`, `complexity_hotspots`, `entrypoint_paths_to`, `taint_paths_to` | Map attack surface + taint |
| **Deep audit** | `dead_code`, `unreachable_from_entrypoints`, `fuzzing_targets` | Graph-aware security analysis |
| **Scanners** | `list_scanners`, `run_scanner`, `scan_and_correlate`, `augment_sarif` | Run SAST tools + correlate |
| **Annotations** | `annotate_function`, `annotations_of`, `findings`, `clear_annotations`, `nodes_with_annotation`, `functions_that_raise` | Tag + query findings |
| **Diffing** | `diff_codebases`, `attack_surface_diff` | Version comparison |
| **Scale** | `plan_partitions`, `export_graph`, `cache_stats`, `clear_cache`, `memory_usage` | Large codebase support |
| **Async** | `poll_task`, `list_tasks` | Background task management |
| **Utilities** | `supported_languages`, `detect_languages` | Language detection |

## Supported Scanners

| Scanner | Languages | Install |
|---|---|---|
| [semgrep](https://semgrep.dev) | 13 languages | `pip install semgrep` |
| [bandit](https://bandit.readthedocs.io) | Python | `pip install bandit` |
| [trivy](https://trivy.dev) | 10 languages | [install guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| [bearer](https://bearer.com) | 6 languages | [install guide](https://docs.bearer.com/reference/installation/) |
| [gosec](https://securego.io) | Go | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| [phpstan](https://phpstan.org) | PHP | `composer require --dev phpstan/phpstan` |

Scanners are optional. Install whichever ones cover your stack. `list_scanners()` shows which are available.

## Large Codebase Support

Optimized for Chromium-scale (35M LOC, 350K files):

- **Bounded queries** — all graph traversals have depth, limit, offset, hub-exclusion. No OOM on `ancestors_of("main")`.
- **Graph cache** — merged graph serialized to msgpack. Warm re-index with no changes: <30s instead of 12 min.
- **Lazy preanalysis** — blast radius computed on demand, not eagerly for all 500K functions.
- **Async heavy tools** — scanners, dead_code analysis return task_id + poll pattern.
- **LRU eviction** — configurable engine budget (`AUDIT_MCP_MAX_ENGINES`, default 8). Engines reload from disk when needed.
- **Partitioned indexing** — `plan_partitions()` splits large codebases by directory.

## Environment Variables

| Variable | Default | What |
|---|---|---|
| `AUDIT_MCP_INDEX_DIR` | `~/.cache/audit-mcp/indexes` | Persistent index storage |
| `AUDIT_MCP_MAX_ENGINES` | `8` | Max engines loaded in memory before LRU eviction |
| `AUDIT_MCP_HTTP_HOST` | `127.0.0.1` | HTTP server bind address |
| `AUDIT_MCP_HTTP_PORT` | `18822` | HTTP server port |

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
python -m ruff check src/audit_mcp/
```

## License

AGPL-3.0-or-later
