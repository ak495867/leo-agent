import ts from "typescript";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname, relative, isAbsolute, sep } from "node:path";

export interface ContextCallEdge { caller: string; callee: string; file: string; line: number; context: string[]; }
export interface HeapFact { allocation: string; variable: string; field: string; value: string; confidence: "static" | "approximate"; }
export interface ContextHeapResult { call_edges: ContextCallEdge[]; contexts: Array<{ function: string; call_string: string[] }>; heap_facts: HeapFact[]; path_checks: Array<{ file: string; line: number; constraints: PathConstraint[]; result: PathSolveResult }>; truncated_contexts: number; limitations: string[]; }
export interface PathConstraint { expression: string; polarity: boolean; file: string; line: number; }
export interface PathSolveResult { status: "sat" | "unsat" | "unknown"; solver: "z3" | "bounded_internal"; constraints: PathConstraint[]; model?: Record<string, string | number | boolean>; reason?: string; }
export interface SandboxResult { status: "executed" | "unavailable" | "rejected" | "timeout" | "failed"; runtime?: string; exit_code?: number | null; stdout?: string; stderr?: string; reason?: string; isolation: string[]; }
export interface BenchmarkReport { schema_version: "1.0"; detector_version: "1.0.0"; created_at: string; corpus: string; corpus_sha256: string | null; cases: number; tp: number; fp: number; tn: number; fn: number; precision: number; recall: number; f1: number; limitations: string[]; }

const norm = (s: string) => s.replace(/\\/g, "/").replace(/^\.\//, "");
const line = (n: ts.Node, sf: ts.SourceFile) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;

/** Bounded k-call-string context graph plus a field-sensitive, allocation-site heap abstraction. */
export function analyzeContextsAndHeap(files: Record<string, string>, k = 2, maxContexts = 20_000): ContextHeapResult {
  const safeK = Math.max(0, Math.min(4, Math.floor(k)));
  const sources = new Map<string, ts.SourceFile>();
  for (const [file, code] of Object.entries(files).filter(([f]) => /\.[cm]?[jt]sx?$/i.test(f))) {
    const sf = ts.createSourceFile(norm(file), code, ts.ScriptTarget.Latest, true);
    if (!(sf as any).parseDiagnostics?.length) sources.set(norm(file), sf);
  }
  const functions = new Map<string, { file: string; name: string; node: ts.FunctionLikeDeclaration }>();
  for (const [file, sf] of sources) {
    const visit = (n: ts.Node) => {
      if ((ts.isFunctionDeclaration(n) && n.name) || (ts.isMethodDeclaration(n) && n.name)) {
        const name = n.name!.getText(sf); functions.set(`${file}::${name}`, { file, name, node: n as ts.FunctionLikeDeclaration });
      } else if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) {
        functions.set(`${file}::${n.name.text}`, { file, name: n.name.text, node: n.initializer });
      }
      n.forEachChild(visit);
    }; visit(sf);
  }
  const edges: ContextCallEdge[] = [];
  const callSites = new Map<string, Array<{ target: string; site: string; file: string; line: number }>>();
  for (const [key, fn] of functions) {
    const sites: Array<{ target: string; site: string; file: string; line: number }> = [];
    const body = fn.node.body;
    if (body) {
      const visit = (n: ts.Node) => {
        if (ts.isCallExpression(n)) {
          const expr = n.expression;
          const name = ts.isIdentifier(expr) ? expr.text : ts.isPropertyAccessExpression(expr) ? expr.name.text : "";
          const local = `${fn.file}::${name}`;
          if (name && functions.has(local)) sites.push({ target: local, site: `${fn.file}:${line(n, n.getSourceFile())}`, file: fn.file, line: line(n, n.getSourceFile()) });
        }
        n.forEachChild(visit);
      }; visit(body);
    }
    callSites.set(key, sites);
  }
  const queue: Array<{ fn: string; context: string[] }> = [...functions.keys()].map(fn => ({ fn, context: [] }));
  const seen = new Set<string>(); let truncated = 0;
  while (queue.length) {
    const current = queue.shift()!; const id = `${current.fn}|${current.context.join("|")}`;
    if (seen.has(id)) continue;
    if (seen.size >= maxContexts) { truncated++; continue; }
    seen.add(id);
    for (const edge of callSites.get(current.fn) ?? []) {
      const next = [...current.context, edge.site].slice(-safeK);
      edges.push({ caller: current.fn, callee: edge.target, file: edge.file, line: edge.line, context: next });
      queue.push({ fn: edge.target, context: next });
    }
  }
  const heap = new Map<string, HeapFact>();
  const pathChecks: ContextHeapResult["path_checks"] = [];
  for (const [file, sf] of sources) {
    const aliases = new Map<string, string>();
    const collectPaths = (node: ts.Node, inherited: PathConstraint[] = []) => {
      if (ts.isIfStatement(node)) {
        const condition: PathConstraint = { expression: node.expression.getText(sf), polarity: true, file, line: line(node, sf) };
        const falseCondition: PathConstraint = { ...condition, polarity: false };
        collectPaths(node.thenStatement, [...inherited, condition]);
        if (node.elseStatement) collectPaths(node.elseStatement, [...inherited, falseCondition]);
        return;
      }
      if (ts.isCallExpression(node) && inherited.length) pathChecks.push({ file, line: line(node, sf), constraints: inherited, result: solvePathConditions(inherited) });
      node.forEachChild(child => collectPaths(child, inherited));
    };
    collectPaths(sf);
    const visit = (n: ts.Node) => {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
        const v = n.name.text; const init = n.initializer;
        if (ts.isNewExpression(init) || ts.isObjectLiteralExpression(init) || ts.isArrayLiteralExpression(init)) aliases.set(v, `${file}@${line(n, sf)}`);
        else if (ts.isIdentifier(init) && aliases.has(init.text)) aliases.set(v, aliases.get(init.text)!);
      }
      if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(n.left)) {
        const receiver = n.left.expression.getText(sf); const alloc = aliases.get(receiver);
        if (alloc) { const fact: HeapFact = { allocation: alloc, variable: receiver, field: n.left.name.text, value: n.right.getText(sf), confidence: "approximate" }; heap.set(`${alloc}.${fact.field}`, fact); }
      }
      n.forEachChild(visit);
    }; visit(sf);
  }
  const contexts = [...seen].map(x => { const i = x.indexOf("|"); return { function: x.slice(0, i), call_string: x.slice(i + 1).split("|").filter(Boolean) }; });
  return { call_edges: edges, contexts, heap_facts: [...heap.values()], path_checks: pathChecks, truncated_contexts: truncated, limitations: ["Call targets are resolved by local function name; dynamic dispatch, reflection and imported package resolution are not complete.", "Heap facts are allocation-site and direct-field approximations, not a full points-to or escape analysis.", ...(truncated ? ["Context exploration hit maxContexts and was truncated."] : [])] };
}

function smtExpr(expr: string): string | null {
  const s = expr.trim().replace(/===/g, "=").replace(/!==/g, "distinct").replace(/&&/g, " and ").replace(/\|\|/g, " or ");
  if (/^[\w.$\s()!<>=+\-*/%"']+$/.test(s)) {
    let x = s.replace(/\btrue\b/g, "true").replace(/\bfalse\b/g, "false");
    x = x.replace(/!\s*([\w.]+)/g, "(not $1)");
    const ops: Array<[RegExp,string]> = [[/\s+and\s+/g," and "],[/\s+or\s+/g," or "]];
    for (const [re] of ops) if (re.test(x)) return null;
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(x)) return x;
    const m = x.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*(==|=|!=|distinct|>=|<=|>|<)\s*(.+)$/);
    if (m) { const op = ({"==":"=","!=":"distinct","distinct":"distinct",">=":">=","<=":"<=",">":">","<":"<","=":"="} as Record<string,string>)[m[2]]; const rhs = m[3].trim(); if (/^-?\d+(?:\.\d+)?$/.test(rhs)) return `(${op} ${m[1]} ${rhs})`; if (/^(true|false)$/.test(rhs)) return `(${op} ${m[1]} ${rhs})`; if (/^".*"$/.test(rhs)) return `(${op} ${m[1]} ${rhs})`; if (/^'.*'$/.test(rhs)) return `(${op} ${m[1]} "${rhs.slice(1,-1).replace(/"/g, '\\"')}")`; }
    if (/^(true|false)$/.test(x)) return x;
  }
  return null;
}

/** Attempts Z3 via SMT-LIB. Falls back to explicit bounded contradiction checks; never treats unknown as safe. */
export function solvePathConditions(constraints: PathConstraint[], timeoutMs = 1500): PathSolveResult {
  const rawSeen = new Map<string, boolean>();
  for (const c of constraints) {
    const key = c.expression.trim().replace(/\s+/g, " ");
    if (rawSeen.has(key) && rawSeen.get(key) !== c.polarity) return { status: "unsat", solver: "bounded_internal", constraints, reason: `Contradictory polarity for ${key}` };
    rawSeen.set(key, c.polarity);
  }
  const active = constraints.map(c => ({ ...c, smt: smtExpr(c.expression) })).filter(c => c.smt !== null) as Array<PathConstraint & { smt: string }>;
  const names = new Set<string>(); for (const c of active) for (const m of c.expression.matchAll(/[A-Za-z_$][\w.$]*/g)) if (!/^(true|false)$/.test(m[0])) names.add(m[0]);
  const booleanNames = new Set<string>(); const stringNames = new Set<string>();
  for (const c of active) {
    const bare = c.expression.trim().match(/^([A-Za-z_][A-Za-z0-9_]*)$/);
    const boolEq = c.expression.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:===|==|=|!==|!=)\s*(?:true|false)\s*$/i);
    const stringEq = c.expression.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:===|==|=|!==|!=)\s*(?:".*"|'.*')\s*$/);
    if (bare) booleanNames.add(bare[1]);
    if (boolEq) booleanNames.add(boolEq[1]);
    if (stringEq) stringNames.add(stringEq[1]);
  }
  const decls = [...names].map(n => `(declare-const ${n} ${booleanNames.has(n) ? "Bool" : stringNames.has(n) ? "String" : "Int"})`).join("\n");
  const assertions = active.map(c => `(assert ${c.polarity ? c.smt : `(not ${c.smt})`})`).join("\n");
  if (active.length && active.length === constraints.length) {
    for (const cmd of ["z3"]) {
      const r = spawnSync(cmd, ["-in", "-smt2"], { input: `(set-option :timeout ${Math.max(100, timeoutMs)})\n${decls}\n${assertions}\n(check-sat)\n(get-model)\n`, encoding: "utf8", timeout: timeoutMs + 300, windowsHide: true });
      if (!r.error && r.status === 0) {
        const first = r.stdout.trim().split(/\s+/)[0];
        if (first === "sat") return { status: "sat", solver: "z3", constraints };
        if (first === "unsat") return { status: "unsat", solver: "z3", constraints };
      }
    }
  }
  const normalized = active.map(c => ({ key: c.expression.trim().replace(/\s+/g," "), value: c.polarity }));
  const seen = new Map<string, boolean>();
  for (const c of normalized) { if (seen.has(c.key) && seen.get(c.key) !== c.value) return { status: "unsat", solver: "bounded_internal", constraints, reason: `Contradictory polarity for ${c.key}` }; seen.set(c.key,c.value); }
  const equalities = new Map<string, string>();
  for (const c of active) { const m = c.expression.match(/^\s*([\w.$]+)\s*={2,3}\s*(.+?)\s*$/); if (m && c.polarity) { const k=m[1],v=m[2]; if (equalities.has(k) && equalities.get(k)!==v) return { status:"unsat", solver:"bounded_internal", constraints, reason:`Conflicting equalities for ${k}` }; equalities.set(k,v); } }
  if (active.length === constraints.length && active.length > 0 && active.every(c => /^(true|false)$/i.test(c.expression.trim()))) {
    const values = active.map(c => c.expression.trim().toLowerCase() === "true" ? c.polarity : !c.polarity);
    if (values.some(v => v !== values[0])) return { status: "unsat", solver: "bounded_internal", constraints, reason: "Boolean path conditions contradict." };
  }
  return { status: "unknown", solver: "bounded_internal", constraints, reason: "No SMT solver was available or the path used unsupported expressions. Unknown is not equivalent to feasible or safe." };
}

/** Executes only inside Docker/Podman with no network, read-only source, dropped capabilities and hard resource limits. */
export function runCounterexampleInSandbox(options: { files: Record<string,string>; image: string; command: string[]; runtime?: "docker"|"podman"; timeoutMs?: number }): SandboxResult {
  const { files, image, command } = options; const runtime = options.runtime ?? "docker";
  const isolation = ["container runtime", "network disabled", "read-only root filesystem", "source mounted read-only", "all Linux capabilities dropped", "no-new-privileges", "PID, memory and CPU limits"];
  if (!/^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,180}$/.test(image) || !command.length || command.length > 32 || command.some(x => typeof x !== "string" || x.length > 2048 || /[\0\r\n]/.test(x))) return { status: "rejected", reason: "Invalid image or command arguments.", isolation };
  const entries = Object.entries(files);
  const totalBytes = entries.reduce((n, [, content]) => n + Buffer.byteLength(content), 0);
  if (entries.length > 5000 || totalBytes > 20 * 1024 * 1024) return { status: "rejected", reason: "Sandbox fixture exceeds 5,000 files or 20 MiB.", isolation };
  const root = mkdtempSync(join(tmpdir(), "leo-sandbox-"));
  try {
    for (const [name, content] of entries) {
      const rel = name.replace(/\\/g,"/"); if (!rel || isAbsolute(rel) || rel.split("/").some(p => p === "..") || rel.includes("\0")) return { status: "rejected", reason: `Unsafe sandbox path: ${name}`, isolation };
      const target = resolve(root, rel); const inside = relative(root, target); if (!inside || inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) return { status: "rejected", reason: `Sandbox path escapes root: ${name}`, isolation };
      mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, content, { mode: 0o400 });
    }
    const args = ["run","--rm","--pull=never","--network","none","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges","--pids-limit=64","--memory=256m","--memory-swap=256m","--cpus=1","--ulimit","nofile=128:128","--ulimit","fsize=10485760:10485760","--user=65534:65534","--tmpfs","/tmp:rw,noexec,nosuid,size=32m,mode=1777","-v",`${root}:/workspace:ro`,"-w","/workspace",image,...command];
    const r = spawnSync(runtime, args, { encoding:"utf8", timeout: Math.max(100, Math.min(30_000, options.timeoutMs ?? 5000)), maxBuffer: 1024*1024, windowsHide:true });
    if (r.error && (r.error as NodeJS.ErrnoException).code === "ENOENT") return { status:"unavailable", reason:`${runtime} is not installed. No code was executed.`, isolation };
    if (r.error && (r.error as NodeJS.ErrnoException).code === "ETIMEDOUT") return { status:"timeout", runtime, stdout:r.stdout ?? "", stderr:r.stderr ?? "", reason:"Sandbox execution exceeded its timeout.", isolation };
    return { status: r.status === 0 ? "executed" : "failed", runtime, exit_code:r.status, stdout:(r.stdout ?? "").slice(0,20000), stderr:(r.stderr ?? "").slice(0,20000), isolation };
  } finally { rmSync(root,{recursive:true,force:true}); }
}

/** Reproducible labeled-corpus benchmark. Metrics are only meaningful for the supplied ground truth. */
export function buildBenchmarkReport(corpus: string, result: {tp:number;fp:number;tn:number;fn:number;precision:number;recall:number;f1:number}, cases: number, corpusSha256?: string): BenchmarkReport {
  return { schema_version:"1.0", detector_version:"1.0.0", created_at:new Date().toISOString(), corpus, corpus_sha256: corpusSha256 ?? null, cases, tp:result.tp, fp:result.fp, tn:result.tn, fn:result.fn, precision:result.precision, recall:result.recall, f1:result.f1, limitations:["Metrics apply only to the supplied labeled corpus and detector configuration.","They do not establish performance on unseen repositories or production exploitability.","Unlabeled findings must be reported separately and are not silently scored as false positives."] };
}
