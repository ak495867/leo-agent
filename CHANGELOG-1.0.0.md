# Leo 1.0.0 — Unified evidence and validation foundation

## Major additions

- Bounded k-call-string context exploration (default k=2) for statically resolved local TypeScript/JavaScript call edges, with context caps and explicit truncation reporting.
- Allocation-site and direct-field-sensitive heap facts for object construction, aliases and direct property writes.
- Branch path-condition collection and path checks associated with call sites.
- Optional Z3 SMT-LIB feasibility checks for a restricted expression subset, with a bounded internal contradiction fallback. Unsupported cases remain `unknown`.
- Explicit Docker/Podman counterexample execution API and `leo sandbox` CLI with image pulling disabled, no network, read-only filesystem/source, dropped capabilities, no-new-privileges, and CPU/memory/PID/open-file/file-size/time bounds. It is opt-in and not invoked by ordinary scans.
- `leo benchmark <casesFile> [outputFile]` for deterministic evaluation against an explicitly labeled safe/vulnerable corpus, including a SHA-256 fingerprint of the exact corpus file.
- Project scan metadata now includes context/heap facts and path checks in `project_analysis.json`.

## Verification

- TypeScript build passed.
- Regression suite: 38/38 passed.
- Context graph and allocation-site heap tests passed.
- Contradiction and unknown-path solver tests passed.
- Sandbox traversal rejection test passed.
- Labeled benchmark report test passed.
- Package dry-run and archive integrity checked separately at release time.

## Important limits

This is a practical analysis foundation, not a claim of complete compiler-grade static analysis. Context-sensitive taint summaries are not yet fully implemented across all languages. The call graph does not resolve arbitrary dynamic dispatch, reflection or higher-order behavior. Heap analysis is not a full points-to/escape analysis. Z3 is optional and only a restricted path-expression subset is translated; there is no general symbolic execution engine. Runtime checks require a local Docker/Podman runtime and operator-supplied fixture, image and command; they do not prove production exploitability. Container isolation is defense-in-depth, not a perfect security boundary. Benchmark metrics apply only to the supplied labeled corpus.

### Environment-specific validation notes

- Z3 was not installed in the build environment, so the internal fallback and `unknown` behavior were tested; a live Z3 process invocation was not.
- Docker and Podman were not installed, so sandbox path rejection and graceful `runtime unavailable` behavior were tested; untrusted code was not executed in a container here.
- The example benchmark CLI smoke test completed on its two labeled examples (1 TP, 0 FP, 1 TN, 0 FN). This is a command-path check, not a meaningful accuracy estimate.
