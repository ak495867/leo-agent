<p align="center">
<img src="https://img.shields.io/npm/v/@leo-agent/cli" alt="npm version">
<img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0">
<img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen" alt="Node >=20">
</p>

<h1 align="center">🦁 Leo</h1>
<p align="center"><strong>Multi-agent security auditing CLI</strong></p>

Leo combines LLM-assisted reconnaissance and vulnerability analysis with deterministic static taint heuristics, OSV dependency advisories, cross-batch correlation, and independent finding verification. Findings retain evidence and verification status; patches are generated only for independently confirmed findings and are not applied automatically by default.

## Install

```bash
npm install -g @leo-agent/cli
```

Requires Node.js 20+ and an OpenRouter API key.

## Quick start

```bash
leo config
leo scan
```

Set `OPENROUTER_API_KEY` to use an environment variable instead of storing the key in `~/.leo/config.json`.

## Analysis pipeline

1. **Snapshot:** captures supported source files and dependency manifests/lockfiles. Symlinks and binary files are excluded; skipped files are recorded.
2. **Batching:** partitions files deterministically into bounded, file-safe batches. Each batch receives its own Recon → Exploit → Audit pass. Per-batch checkpoints support resume.
3. **Cross-batch correlation:** interleaves findings from different batches, deduplicates candidates, and asks a correlation agent to identify evidence-backed multi-file chains. The agent cannot invent new findings or rewrite grounded fields.
4. **Project program analysis:** JavaScript/TypeScript use the TypeScript compiler AST with relative-import resolution, exported-function sink summaries, structured branch/loop flow graphs, bounded field-sensitive object aliases, and SSA-like definition versions. Python uses the standard-library AST. Java uses the JDK `javac` Tree API when a JDK is available. Other languages retain clearly labelled conservative lexical adapters.
5. **Interprocedural analysis (0.6):** TypeScript summaries are propagated to a bounded fixed point across local and relative-import calls, including recursive summary propagation. Recovered path conditions receive bounded syntactic contradiction checks. The engine records convergence and analysis-model limits in `project_analysis.json`.
6. **Dependency advisories:** queries the OSV API for exact versions extracted from supported manifests and lockfiles. Network failures are reported as unavailable/partial, never as a clean bill of health.
7. **Independent verification:** a separate verifier challenges every candidate. Findings are marked `confirmed`, `rejected`, or `needs_review`; rejected candidates are retained in the rejection artefact.
8. **Patch generation:** patch proposals are generated only for confirmed findings. Applying patches remains opt-in and is constrained to the project root.
9. **Session memory:** vulnerability patterns are stored per project; benchmark runs can disable memory.

## Supported dependency inputs

- npm: `package-lock.json`, `npm-shrinkwrap.json`, and exact versions in `package.json`
- Python: pinned `requirements*.txt` and `poetry.lock`
- Go: `go.mod`
- Rust: `Cargo.lock`
- PHP: `composer.lock`
- Ruby: `Gemfile.lock`
- Java: Maven `pom.xml` and Gradle `gradle.lockfile`

Only versions that can be resolved exactly are queried. Ranges, floating tags, missing lockfiles, and unsupported manifest formats are not treated as safe; inspect the dependency audit's query count and errors.

## Static program analysis: scope

The static layer is deliberately bounded and evidence-oriented:

- **JavaScript/TypeScript:** TypeScript compiler AST, relative named-import resolution, exported function summaries for parameter-to-sink flows, simple return propagation, branch/loop flow graph nodes, selected rejecting guards, direct object-field aliases, and SSA-like local definition versions.
- **Python:** the Python standard-library `ast` module extracts function assignments and calls; current taint propagation is local to a function and recognizes selected request/input sources and dangerous calls.
- **Java:** the JDK `javac` public Tree API extracts method, assignment, and call facts; current taint propagation is local to a method. A JDK is required for this adapter.
- **Other languages:** conservative lexical heuristics remain in place and must not be described as AST-backed.

The 0.6 summary engine is context-insensitive at the function-summary level: it iterates summaries to a bounded fixed point but does not yet implement true k-call-string contexts, object-sensitive dispatch, or call/return matching for arbitrary higher-order callbacks. This is not a full compiler-grade analysis. The TypeScript flow graph is not a complete CFG/SSA implementation; heap modelling does not cover arbitrary pointers, reflection, prototypes, or escape analysis; package exports, path aliases, dynamic imports, and complete type resolution are not modelled. Python and Java do not yet have cross-module call graphs. The per-session `project_analysis.json` records parser availability and these limitations. Findings are candidates with trace evidence, not formal proofs of exploitability.

## Commands

| Command | Description |
|---|---|
| `leo scan` | Scan the current project |
| `leo config` | Configure API key/model/depth |
| `leo history` | List sessions for the current project |
| `leo resume <id>` | Resume compatible batch checkpoints |
| `leo restore [id]` | Restore session backups |
| `leo ui` | Launch the interactive terminal UI |

## Session artefacts

Session data is written under `~/.leo/sessions/<project-hash>/<session-id>/`:

- `snapshot_manifest.json` — snapshot hash, file count, skipped paths
- `batch_manifest.json` and `batches/*.json` — deterministic batch definitions and resumable Recon/Exploit/Audit checkpoints
- `recon.json`, `exploit.json`, `audit.json`, `patches.json`
- `taint_report.json`, `project_analysis.json` (module graph, flow graphs, parser status and limitations), `dependency_audit.json`, `correlations.json`, `verification.json`
- `session.json`, `log.txt`, and `memory_update.json`

Configuration and session artefacts use restrictive permissions where supported. Memory is project-scoped. Patch application is disabled by default; inspect `patches.json` before enabling `auto_apply_patches`.

## Development

```bash
npm install
npm test
npm run build
```

The regression suite includes deterministic vulnerable and safe fixtures and reports TP/FP/TN/FN, precision, recall, and F1 for the built-in heuristic rules only. These are rule-regression results, not Leo's end-to-end benchmark scores. End-to-end precision/recall requires a separately labeled benchmark and its official scorer.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Labeled evaluation

To evaluate a saved `audit.json` against a JSON ground-truth array:

```bash
leo evaluate fixtures/security/ground-truth.json path/to/audit.json
```

Each truth row has `id`, `file`, and `expected` (`vulnerable` or `safe`); vulnerable rows may also specify `category` and `line`. The evaluator reports TP/FP/TN/FN, precision, recall, F1, matched finding IDs, and findings outside the labeled file set. It uses a default ±5-line matching tolerance. Only labeled cases contribute to the metrics.

## Project AST and data-flow analysis (0.4.0)

Leo now performs project-aware AST analysis for JavaScript/TypeScript, AST-backed local flow analysis for Python, and javac Tree API-backed local flow analysis for Java. Relative named imports and exported function sink summaries are resolved for TypeScript/JavaScript. The verifier receives source excerpts from both the caller and sink file when the source is known. `project_analysis.json` records the module graph, flow graph, parser status, and limitations.

This release does not claim complete CFG/SSA, arbitrary heap/pointer analysis, full package/type resolution, or cross-module Python/Java analysis. See the Static program analysis scope above.


## Evidence-driven analysis (0.5.0)

Leo now emits a unified project call-graph artifact, path-condition annotations, explicit analysis-uncertainty metadata, exploitability evidence graphs and counterexample challenge inputs. The evidence graph separates source, propagation, security boundary and sink, and lists proof obligations that remain to be checked.

Counterexample records are **generated but not executed**. They are test hypotheses, not proof of exploitability. The multi-language call graph marks name-only Python and Java edges as low confidence; TypeScript/JavaScript compiler-AST call sites receive stronger structural evidence. Path conditions are syntax-derived rather than SMT-solved, and dynamic dispatch, full heap modelling and runtime reachability remain incomplete. See `CHANGELOG-0.5.0.md` for details.


## Leo 1.0 analysis engine

Leo 1.0 adds a bounded k-call-string context graph (default k=2), allocation-site/direct-field heap facts, path-condition collection, optional Z3-backed feasibility checks, an opt-in Docker/Podman counterexample runner, and a labeled-corpus benchmark command. Project scans serialize context and heap analysis in `project_analysis.json`.

### Reproducible benchmark

Provide a JSON array containing `{ "id", "file", "source", "expected": "safe" | "vulnerable" }` records, then run:

```bash
leo benchmark ./examples/benchmark-cases.example.json ./benchmark-report.json
```

The report includes a SHA-256 hash of the exact corpus file, detector version, TP/FP/TN/FN, precision, recall and F1. These numbers describe only the supplied labeled corpus and detector configuration; they are not a claim of general accuracy.

### Optional path solver

If Z3 is installed and available on `PATH`, Leo attempts SMT-LIB feasibility checks for a restricted expression subset. Otherwise it uses a bounded contradiction checker. Unsupported expressions return `unknown`; unknown is never treated as safe or infeasible. This is not full symbolic execution.

### Opt-in runtime challenge sandbox (API)

`runCounterexampleInSandbox` is an explicit API, also exposed through the opt-in CLI command below. It requires Docker or Podman and a pre-pulled image, runs with image pulling disabled, networking disabled, a read-only source mount/root filesystem, dropped capabilities, no-new-privileges, and CPU/memory/PID/file-size/open-file limits. Leo does not automatically execute generated payloads during a scan.

```bash
leo sandbox ./counterexample-fixture node:22-alpine node ./repro.js
# or
leo sandbox --runtime podman --timeout 8000 ./counterexample-fixture python:3.12-alpine python repro.py
``` Container isolation is defense-in-depth, not a guarantee against every kernel/runtime escape; use a disposable hardened host for hostile samples.

### 1.0 scope and limits

The context graph currently resolves local statically named functions; it does not implement complete dynamic dispatch, package-wide call/return matching, object-sensitive method dispatch, or context-sensitive taint summaries across every language. Heap analysis is allocation-site and direct-field based, not a complete points-to engine. The optional Z3 adapter supports only a small expression subset; arithmetic symbolic execution, path explosion management, and solver-backed exploit generation remain future work. The runtime sandbox API executes only when explicitly called and does not prove production exploitability. Benchmark results require an independently labeled corpus and should include false-positive/false-negative analysis.
