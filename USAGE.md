# Leo Usage Guide

## Setup

```powershell
npm install -g @leo-agent/cli
leo config
```

Alternatively set `OPENROUTER_API_KEY` in your environment. Leo requires Node.js 20+.

## Scan a project

Run from the repository root:

```powershell
leo scan
```

Leo captures source files and dependency manifests, splits them into deterministic bounded batches, and runs Recon, Exploit, and Audit on each batch. A global correlation pass deduplicates findings and looks for multi-file chains. Static taint heuristics and OSV dependency advisory checks add non-LLM evidence. A separate verifier marks findings `confirmed`, `rejected`, or `needs_review`.

## Read results

Open the latest session under:

```text
~/.leo/sessions/<project-hash>/<session-id>/
```

Key files:

| File | Purpose |
|---|---|
| `audit.json` | Retained candidate findings and verification status |
| `verification.json` | Independent verifier decisions and rationales |
| `taint_report.json` | Deterministic source-to-sink candidates |
| `project_analysis.json` | Resolved TypeScript module graph, flow graphs, parser availability, and explicit analysis limitations |
| `dependency_audit.json` | OSV query count, advisory findings, and network errors |
| `correlations.json` | Cross-file attack chains supported by existing findings |
| `batch_manifest.json` | Batch layout and file coverage |
| `snapshot_manifest.json` | Snapshot hash and skipped files |
| `patches.json` | Proposed patches for confirmed findings |

`needs_review` is not equivalent to confirmed. Rejected candidates remain in `audit.json`'s `rejected_findings` list with a reason.

## Resume

```powershell
leo resume <session-id>
```

Leo reuses a batch checkpoint only if the project snapshot hash matches the original session. Missing or corrupt checkpoints are recomputed. A changed source snapshot is rejected rather than mixed with stale findings.

## Patch safety

Patch application is disabled by default. Leo proposes patches for independently confirmed findings, saves them for review, and does not modify source files unless `auto_apply_patches` is explicitly enabled. Commit or back up your work before opting into patch application. Restore from a session with:

```powershell
leo restore <session-id>
```

## Dependency audit caveats

OSV lookups require network access. The audit reports `complete`, `partial`, or `unavailable`, along with how many exact dependency versions were queried. An unavailable lookup is not evidence that dependencies are safe. Version ranges and unsupported lockfile formats may not be resolvable.

## Test the built-in rules

From the Leo source checkout:

```powershell
npm test
```

The fixture suite measures TP/FP/TN/FN, precision, recall, and F1 for deterministic heuristic rules. These figures do not measure the LLM agents or end-to-end benchmark performance.

## Evaluate a labeled audit

Use a ground-truth JSON array and an `audit.json` from a completed scan:

```powershell
leo evaluate .\fixtures\security\ground-truth.json .\path\to\audit.json
```

Rows require `id`, `file`, and `expected` (`vulnerable` or `safe`). Vulnerable rows can include `category` and `line`. The evaluator reports TP/FP/TN/FN, precision, recall, F1, matched findings, and unscored findings. Its default line tolerance is five lines.

### Understanding AST findings

For JavaScript and TypeScript, inspect the finding's `evidence` JSON. `source_origins` identifies attacker-controlled expressions, `sink` identifies the dangerous operation, and `analysis` identifies the TypeScript compiler AST engine. Verification records may include `attacker_controlled_source`, `propagation_path`, `security_boundary`, `exploitable_sink`, and `mitigations_reviewed`. A `needs_review` disposition is not a confirmed vulnerability.

## Project AST analysis requirements

- JavaScript/TypeScript analysis uses the bundled TypeScript compiler dependency.
- Python AST analysis requires `python3` or `python` on PATH.
- Java AST extraction requires a JDK with both `javac` and `java` on PATH. A JRE-only installation is insufficient.
- If an optional language runtime/parser is unavailable, Leo records that status; absence of findings is not evidence that the language is safe.

For cross-file TypeScript findings, `audit.json` evidence includes `source_file` and `source_origins`. The independent verifier receives the caller-side source excerpt and the callee-side sink excerpt.
