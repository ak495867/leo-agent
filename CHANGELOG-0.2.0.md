# Leo 0.2.0

## Security analysis pipeline
- Added deterministic multi-batch repository scanning and resumable per-batch Recon/Exploit/Audit checkpoints.
- Added cross-batch finding interleaving, normalized deduplication, and evidence-constrained cross-file chain correlation.
- Added OSV dependency advisory queries for supported npm, Python, Go, Rust, PHP, Ruby, and Java dependency manifests/lockfiles.
- Added conservative source-to-sink taint heuristics with simple assignment and alias propagation.
- Added an independent verification agent with confirmed/rejected/needs-review outcomes.
- Restricted patch generation to independently confirmed findings; patch application remains opt-in.
- Added labeled audit evaluation and vulnerable/safe regression fixtures.

## Reliability
- Dependency lookup and memory extraction failures no longer invalidate a completed source audit.
- Resume checkpoints are tied to the snapshot, model, scan depth, pipeline version, and memory-pattern fingerprint.
- Added manifest/lockfile snapshot coverage and removed the aggregate 250 KB snapshot ceiling.
- Added tests for offline advisory behavior, false positives/negatives, cross-file correlation validation, and verifier decisions.

## Validation
- `npm test`: 16 tests passed.
- `node bin/leo --version`: 0.2.0.
- `npm pack --dry-run`: package contents generated successfully.
- A live scan was not executed in this build environment because its mounted `better-sqlite3` native binary is for a different platform. The delivered source archive excludes `node_modules`; install dependencies on the target OS before running Leo.
