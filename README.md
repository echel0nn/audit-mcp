# audit-mcp

This is the greatest source code audit tool of all time.

Every other security scanner on the planet does the same thing: it scans your code like a flat bag of text files, pukes out 200 findings, and then just leaves. Just absolutely dumps a mountain of alerts on your desk and walks away like it didn't just ruin your afternoon. "Good luck figuring out which of these actually matter, dipshit." That's literally every SAST tool in existence.

audit-mcp doesn't do that. It builds a full call graph of your entire codebase first — every function, every call, every entrypoint, every trust boundary — and THEN it scans. So when semgrep says "line 42 has a SQL injection," this thing actually checks: is line 42 reachable from the network? Or is it in a test helper that nobody calls? Because those are two magnificently different situations.

Built on [Trail of Bits Trailmark](https://github.com/trailofbits/trailmark). 21 languages. Not another semgrep wrapper. Not a vendor-locked cloud subscription that costs more than your rent.

## Install

```bash
pip install -e .
```

That's it. Python 3.12+. It pulls in `trailmark`, `fastmcp`, `fastapi`, `uvicorn`, and `msgpack`. If you can install a pip package, you can install this. The bar is literally on the floor.

## Run This Thing

### MCP mode (stdio — for Claude Desktop, Cursor, whatever)

```bash
audit-mcp
```

Just type that. It starts. It works. Incredible.

```bash
python -m audit_mcp
```

Same thing for people who don't trust console scripts. Both valid. Both work. Moving on.

### HTTP mode (for when you want to hit it with curl like a normal person)

```bash
audit-mcp --mode http --port 18822
```

API docs show up at `http://127.0.0.1:18822/docs`. FastAPI swagger and everything. Beautiful.

## Wire It Into Claude Desktop

Add this to your `claude_desktop_config.json`:

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

If you didn't `pip install` it globally and you're one of those people:

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

## Wire It Into Cursor

Drop this in `.cursor/mcp.json`:

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

## What It Actually Does

Let me walk you through the gameplay loop here because it's genuinely incredible.

### Step 1: Index the codebase

You point it at a directory. It parses everything. 21 languages. Builds the full call graph. Returns immediately and does the work in the background like a responsible adult.

```
index_codebase(path="/path/to/project")
-> {index_id: "a1b2c3", status: "indexing"}

poll_index(index_id="a1b2c3")
-> {status: "ready", summary: {functions: 4812, call_edges: 18234, entrypoints: 47}}
```

4,812 functions. 18,234 call edges. 47 entrypoints. It just mapped your entire attack surface in seconds. That's pretty solid.

### Step 2: See where the danger is

```
attack_surface(index_id="a1b2c3")
-> entrypoints with trust levels, blast radius, framework detection

preanalysis(index_id="a1b2c3")
-> blast radius top-50, privilege boundaries, taint propagation
```

It tells you which functions are exposed to the internet. Which ones have the highest blast radius. Which ones cross privilege boundaries. This is the information that every other tool just doesn't give you. Absolutely magnificent.

### Step 3: Run scanners and correlate

Here's where the magic happens. You run semgrep or bandit or whatever scanner you want, and this thing takes the raw findings and overlays them on the graph. The result is findings ranked by actual exploitability, not alphabetical order.

```
scan_and_correlate(index_id="a1b2c3", scanner="semgrep")
-> {task_id: "d4e5f6", status: "running"}

poll_task(task_id="d4e5f6")
-> findings sorted by risk_score (tainted + reachable + high blast radius = highest priority)
```

"Semgrep found 47 SQL injections. Of those, 12 are tainted from entrypoints. Of those, 3 have blast radius over 50. Start there." That's the output. That's the value proposition. You're welcome.

### Step 4: Ask it security questions

This is the part that goes absolutely dummy hard.

```
taint_paths_to(index_id="a1b2c3", sink_name="eval")
-> all entrypoint-to-eval call paths

callers_of(index_id="a1b2c3", name="parse_input", exclude_hubs=true)
-> direct callers, minus the logging/utility noise

dead_code(index_id="a1b2c3")
-> {task_id: ..., status: "running"}  # runs async because it's a big operation

paths_between(index_id="a1b2c3", source="handle_request", target="execute_query")
-> top 5 shortest call paths between two functions
```

"Is `eval()` reachable from the network?" One call. Answer. Done. No grepping through 50,000 files like a caveman.

### Step 5: Diff versions

```
diff_codebases(index_id_a="v1", index_id_b="v2")
-> added/removed/changed functions, attack surface delta

attack_surface_diff(index_id_a="v1", index_id_b="v2")
-> new entrypoints, removed validation, blast radius changes
```

"This PR added 3 new entrypoints and removed a validation check. Attack surface grew by 8%." That's the kind of sentence that makes security reviews actually useful instead of just theater.

## The Full Arsenal (41 Tools)

| Category | Tools | What They Do |
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

41 tools. Every single one returns structured JSON. No parsing stdout like it's 2003.

## Scanners

These are optional. Install whichever ones cover your stack. `list_scanners()` tells you what's available on your machine.

| Scanner | Languages | How to Get It |
|---|---|---|
| [semgrep](https://semgrep.dev) | 13 languages | `pip install semgrep` |
| [bandit](https://bandit.readthedocs.io) | Python | `pip install bandit` |
| [trivy](https://trivy.dev) | 10 languages | [install guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| [bearer](https://bearer.com) | 6 languages | [install guide](https://docs.bearer.com/reference/installation/) |
| [gosec](https://securego.io) | Go | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| [phpstan](https://phpstan.org) | PHP | `composer require --dev phpstan/phpstan` |

You don't need all of them. You don't need any of them. The graph analysis works standalone. The scanners are just extra firepower when you want to go absolutely nuclear on a codebase.

## Large Codebase Support (Yes, It Handles Chromium)

Most tools implode on anything bigger than a weekend project. This one was specifically designed to handle Chromium-scale codebases. 35 million lines of code. 350,000 files. The kind of thing that makes other tools curl up and die.

- **Bounded queries** — every graph traversal has depth limits, result caps, pagination, and hub exclusion. `ancestors_of("main")` on the Linux kernel doesn't OOM your machine. It returns 100 results and says "49,900 more available, refine your query." Responsible behavior.
- **Graph cache** — the merged graph gets serialized to msgpack. Warm re-index with no changes: under 30 seconds instead of 12 minutes. Content-hash based. If nothing changed, nothing recomputes.
- **Lazy preanalysis** — blast radius is computed on demand, not eagerly for all 500,000 functions. Because computing transitive closure for half a million nodes on startup is psychotic behavior.
- **Async heavy tools** — scanners and full-codebase analysis return a task ID. Poll for results. Don't block the server for 10 minutes waiting for semgrep to finish.
- **LRU eviction** — configurable engine budget. Load 8 codebases, evict the oldest when you load the 9th. Engines reload from disk when you need them again. Memory stays bounded.
- **Partitioned indexing** — `plan_partitions()` splits a massive codebase into indexable chunks by directory. Each chunk indexes independently.

## Environment Variables

| Variable | Default | What It Controls |
|---|---|---|
| `AUDIT_MCP_INDEX_DIR` | `~/.cache/audit-mcp/indexes` | Where indexes live on disk |
| `AUDIT_MCP_MAX_ENGINES` | `8` | Max engines in memory before LRU eviction kicks in |
| `AUDIT_MCP_HTTP_HOST` | `127.0.0.1` | HTTP bind address |
| `AUDIT_MCP_HTTP_PORT` | `18822` | HTTP port |

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
python -m ruff check src/audit_mcp/
```

28 tests. All pass. Takes under a second. The way it should be.

## License

AGPL-3.0-or-later. Because if you're going to build on a security tool, you should contribute back. That's the social contract.
