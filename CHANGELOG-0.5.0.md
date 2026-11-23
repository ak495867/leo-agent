# Leo 0.5.0 — Evidence-driven analysis

## Added

- A project-wide call graph artifact spanning TypeScript/JavaScript, Python and Java source files. Compiler-AST TypeScript call sites are distinguished from lower-confidence name-only Python and Java edges.
- Finding evidence enrichment with recovered enclosing path conditions and explicit uncertainty fields for path sensitivity, dynamic dispatch, runtime reachability and alias precision.
- Structured exploitability graphs for every static finding, separating source, propagation, security boundary and sink nodes, and retaining proof obligations.
- Counterexample challenge generation for common vulnerability classes. Generated inputs are explicitly marked `generated_not_executed`; Leo does not claim they exploit the target.
- Regression coverage for graph structure, counterexample status, path-condition metadata and cross-language call graph output.

## Important limits

- Context sensitivity is still bounded: recursive, polymorphic, dynamic and higher-order dispatch are not fully resolved.
- Path conditions are recovered from enclosing syntax; no SMT solver or complete path-feasibility engine is included.
- Python and Java call-graph edges are name-based and low confidence unless independently resolved. Their taint engines remain less interprocedural than TypeScript.
- Heap modelling is still limited to direct named object fields and aliases.
- Exploitability graphs are evidence structures, not formal proofs. Counterexample inputs are not executed. Runtime reachability and exploitability remain unconfirmed until a separate controlled test executes successfully.
