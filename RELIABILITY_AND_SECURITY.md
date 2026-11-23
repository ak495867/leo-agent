# Leo 0.2.0 — Reliability, Analysis and Security

## Implemented analysis capabilities

### 1. Multi-batch repository analysis

The snapshot now includes supported source extensions plus dependency manifests/lockfiles. It no longer stops after an aggregate 250 KB budget. Files are grouped deterministically into batches with a 48 KB target budget; larger files up to the snapshot's 200 KB per-file ceiling are isolated into their own batch. Files are never silently truncated. Files exceeding the per-file ceiling, binaries, symlinks, and unreadable files are listed in `snapshot_manifest.json` as skipped.

Each batch receives a Recon → Exploit → Audit pass. Checkpoints are persisted in `batches/`. Resume checks the complete snapshot hash and reuses only checkpoints from an identical source snapshot. Legacy sessions without batch checkpoints are recomputed.

### 2. Cross-batch evidence and deduplication

Findings are interleaved across batches, deduplicated by normalized file, line, category and description, then passed to a bounded global correlation agent. The correlation agent can add cross-references and evidence-backed chains, but cannot create new findings or replace grounded finding fields. Chains are written to `correlations.json`.

### 3. Dependency advisory analysis

Leo queries the OSV batch API using exact versions resolved from npm package manifests/lockfiles, pinned Python requirements and Poetry lockfiles, Go modules, Cargo lockfiles, Composer lockfiles, Ruby lockfiles, Maven POMs, and Gradle lockfiles. Queries are sent in groups of at most 100. Network failures are represented as `partial` or `unavailable` in `dependency_audit.json`; an unavailable query is never represented as a clean result. Only dependencies with resolvable exact versions are queried.

### 4. Static taint heuristics

A deterministic source-to-sink pass recognizes selected untrusted-input sources and dangerous sinks for dynamic code execution, shell execution, SQL queries, and unsafe deserialization. It tracks simple same-file assignments and aliases and suppresses some obvious parameterized SQL and explicit allowlist cases. Results are stored in `taint_report.json` and enter the global finding correlation and verification stages.

This is intentionally a lightweight heuristic layer. It is not compiler-grade, interprocedural, path-sensitive or framework-complete. It can miss flows and can still produce false positives. Do not interpret the absence of a taint result as proof of safety.

### 5. Independent finding verification

A separate verifier receives each candidate with a bounded source excerpt and attempts to falsify the claim. It emits `confirmed`, `rejected`, or `needs_review`, with confidence and rationale. Invalid, missing or failed verifier responses become `needs_review`; they do not silently erase candidates. Rejected candidates are preserved in `rejected_findings` and `verification.json`.

Patch proposals are generated only for `confirmed` findings. Patch application remains disabled by default and is constrained to the project root. Session backups preserve the pristine original file.

### 6. False-positive / false-negative regression

The test suite includes safe and vulnerable fixtures for the deterministic taint rules. `runRuleRegression` measures TP/FP/TN/FN, precision, recall and F1 for those rules. `leo evaluate <truth.json> <audit.json>` evaluates a complete saved audit against explicit labeled cases, using exact file/category matching and a default ±5-line tolerance. Findings outside the labeled file set are returned as unscored.

These tests validate the deterministic rule layer and evaluator mechanics. They are not a claim of end-to-end detection accuracy. Real Leo precision/recall must be measured against a labeled benchmark using the benchmark's own ground truth and official scorer.

## Operational guarantees

- Oversized model requests fail explicitly; no mid-JSON truncation.
- Dependency API outages are explicit and non-fatal to source analysis.
- Memory extraction is bounded and best-effort; a memory failure does not invalidate completed scan results.
- Project memory remains isolated by project hash.
- Config and session artefacts use restrictive permissions where supported.
- Patch application requires explicit opt-in.
- No precision/recall score is inferred from the number of patches or findings.

## Validation performed

`npm test` builds TypeScript and runs 14 deterministic tests. The suite covers source and manifest snapshotting, batch partitioning, taint detection and safe controls, alias tracking, deduplication, OSV success/offline handling, verifier rejection, patch backup/path safety, config permissions, and labeled TP/FP/TN/FN evaluation.

A full live scan against a real repository and live OpenRouter/OSV services has not been performed as part of this source-only validation. End-to-end quality and provider-specific model behavior remain to be measured in the target environment.
