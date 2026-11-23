# Leo 0.4.0 — Project-wide AST and evidence-backed dataflow

## Added
- Project-wide TypeScript/JavaScript analysis using the TypeScript compiler AST.
- Relative named-import resolution and exported-function summaries for parameter-to-sink flows.
- Bounded propagation through local aliases and selected return-value paths.
- Structured branch/loop flow graph output with explicit branch and phi-merge nodes.
- Field-sensitive handling for direct object-property aliases and SSA-like local definition versions in finding evidence.
- Python AST extraction using the Python standard-library `ast` module, with local assignment-to-call taint checks.
- Java AST extraction using the JDK's public `javac` Tree API, with local method assignment-to-call taint checks.
- Cross-file source excerpt support in the independent verifier: source-side and sink-side excerpts can come from different files.
- `project_analysis.json` records module relationships, flow graphs, parser status, and known limitations.
- Public exports for `runProjectAnalysis` and `analyzeProject`.

## Validation
- TypeScript compilation passed.
- 27 regression tests passed, including relative-import taint flow, CFG branch/phi structure, object-field aliases, Python AST, javac AST, and cross-file verifier evidence.

## Scope and limitations
- TypeScript/JavaScript resolution currently handles relative named imports; package exports, path aliases, dynamic imports, and complete type resolution are not covered.
- The generated flow graph is a structured CFG approximation, not a complete compiler CFG or SSA conversion. SSA-like versions are evidence metadata, not a full SSA IR.
- Heap modelling is limited to direct object-field aliases; arbitrary pointers, reflection, prototypes, and escape analysis are not covered.
- Python AST analysis is local to a function; Python project-wide import/call-graph analysis is not implemented.
- Java uses javac Tree API extraction but its taint propagation is local to a method; Java project-wide interprocedural summaries are not implemented.
- Python and JDK runtimes are optional external prerequisites. If unavailable, the parser status is explicit and no clean bill of health is implied.
- Findings remain static-analysis candidates, not formal exploit proofs. The verifier may retain `needs_review` when evidence is incomplete.
