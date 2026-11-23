import ts from "typescript";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";

import { AuditFinding } from "../agents/audit.js";
import { analyzeContextsAndHeap, ContextHeapResult } from "./engine-v1.js";

export interface ProjectAnalysisResult {
  findings: AuditFinding[];
  module_graph: Array<{ file: string; imports: string[] }>;
  flow_graphs: Array<{ file: string; function: string; nodes: Array<{ id: string; kind: string; line: number; successors: string[] }> }>;
  parser_status: { typescript: string; python: string; java: string };
  limitations: string[];
  call_graph: Array<{ caller: string; callee: string; file: string; line: number; language: string; resolution: "resolved" | "name_only"; confidence: "high" | "low" }>;
  exploitability_graphs: Array<{ finding_id: string; nodes: Array<{ id: string; kind: string; label: string; file?: string; line?: number }>; edges: Array<{ from: string; to: string; relation: string }>; proof_obligations: string[]; uncertainty: string[] }>;
  counterexamples: Array<{ finding_id: string; status: "generated_not_executed"; challenge: string; candidate_input: string; expected_observation: string; limitations: string[] }>;
  context_heap_analysis: ContextHeapResult;
  analysis_metadata: { summary_iterations: number; summary_fixed_point_reached: boolean; context_sensitivity: string; path_solver: string; heap_abstraction: string };
}

const PY_AST = String.raw`
import ast,json,sys
payload=json.loads(sys.stdin.read()); result={}
for filename,src in payload.items():
 try: tree=ast.parse(src, filename=filename)
 except SyntaxError as e: result[filename]={"error":str(e)}; continue
 class V(ast.NodeVisitor):
  def __init__(self): self.functions=[]; self.stack=[]; self.imports=[]
  def visit_FunctionDef(self,n):
   item={"name":n.name,"line":n.lineno,"params":[a.arg for a in n.args.args],"calls":[],"assignments":[],"returns":[],"guards":[]}
   self.functions.append(item); self.stack.append(item)
   for x in n.body:self.visit(x)
   self.stack.pop()
  def visit_AsyncFunctionDef(self,n): self.visit_FunctionDef(n)
  def visit_Assign(self,n):
   if self.stack:
    for t in n.targets:
     if isinstance(t,ast.Name): self.stack[-1]["assignments"].append({"target":t.id,"expr":ast.unparse(n.value),"line":n.lineno})
   self.generic_visit(n)
  def visit_Call(self,n):
   if self.stack: self.stack[-1]["calls"].append({"name":ast.unparse(n.func),"args":[ast.unparse(a) for a in n.args],"keywords":{k.arg:ast.unparse(k.value) for k in n.keywords if k.arg},"full":ast.unparse(n),"line":n.lineno})
   self.generic_visit(n)
  def visit_Return(self,n):
   if self.stack and n.value:self.stack[-1]["returns"].append({"expr":ast.unparse(n.value),"line":n.lineno})
   self.generic_visit(n)
  def visit_If(self,n):
   if self.stack:
    terminating=any(isinstance(x,(ast.Raise,ast.Return,ast.Break,ast.Continue)) for x in n.body)
    self.stack[-1]["guards"].append({"test":ast.unparse(n.test),"terminating":terminating})
   self.generic_visit(n)
  def visit_ImportFrom(self,n): self.imports.append({"module":n.module or "","names":[a.name for a in n.names]})
 v=V(); v.visit(tree); result[filename]={"functions":v.functions,"imports":v.imports}
print(json.dumps(result,separators=(",",":")))
`

const JAVA_HELPER = String.raw`
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.net.URI;
import java.util.*;
import java.io.*;
public class LeoJavaAst {
 static String q(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")+"\"";}
 public static void main(String[] args)throws Exception{
  JavaCompiler c=ToolProvider.getSystemJavaCompiler(); if(c==null){System.out.println("{\"error\":\"JDK compiler unavailable\"}");return;}
  StandardJavaFileManager fm=c.getStandardFileManager(null,null,null); Iterable<? extends JavaFileObject> units=fm.getJavaFileObjects(Arrays.copyOfRange(args,1,args.length));
  JavacTask task=(JavacTask)c.getTask(null,fm,null,Arrays.asList("-proc:none"),null,units); Iterable<? extends CompilationUnitTree> parsed=task.parse(); Trees trees=Trees.instance(task);
  StringBuilder out=new StringBuilder("{\"files\":["); boolean firstFile=true;
  for(CompilationUnitTree cu:parsed){if(!firstFile)out.append(',');firstFile=false; String file=cu.getSourceFile().getName(); out.append("{\"file\":").append(q(file)).append(",\"methods\":[");
   final boolean[] first={true}; new TreePathScanner<Void,Void>(){
    public Void visitMethod(MethodTree m,Void p){if(!first[0])out.append(',');first[0]=false;out.append("{\"name\":").append(q(m.getName().toString())).append(",\"params\":[");for(int i=0;i<m.getParameters().size();i++){if(i>0)out.append(',');out.append(q(m.getParameters().get(i).getName().toString()));}out.append("],\"calls\":["); final boolean[] fc={true}; new TreePathScanner<Void,Void>(){public Void visitMethodInvocation(MethodInvocationTree n,Void x){if(!fc[0])out.append(',');fc[0]=false;long pos=trees.getSourcePositions().getStartPosition(cu,n);long line=cu.getLineMap().getLineNumber(pos);out.append("{\"name\":").append(q(n.getMethodSelect().toString())).append(",\"args\":[");for(int i=0;i<n.getArguments().size();i++){if(i>0)out.append(',');out.append(q(n.getArguments().get(i).toString()));}out.append("],\"line\":").append(line).append('}');return super.visitMethodInvocation(n,x);}}.scan(new TreePath(getCurrentPath(),m.getBody()),null);out.append("]}");return null;}
   }.scan(cu,null); out.append("]}"); }
  out.append("]}");System.out.println(out.toString());fm.close();
 }
}
`;

function normalize(file: string): string { return file.replace(/\\/g, "/").replace(/^\.\//, ""); }
function lineOf(node: ts.Node, sf: ts.SourceFile): number { return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1; }
function exprText(node: ts.Node): string { return node.getText(); }
function isSourceText(s: string): boolean { return /\b(?:req|request)\.(?:body|query|params|headers|cookies)|process\.argv|request\.(?:args|form|GET|POST|data)|input\s*\(/i.test(s); }
function sinkCategory(s: string): { category: string; severity: AuditFinding["severity"] } | null {
  if (/\b(?:eval|new\s+Function)\s*\(/i.test(s)) return { category: "CODE_INJECTION", severity: "CRITICAL" };
  if (/\b(?:exec|execSync|execFileSync|spawn|system|popen|Runtime\.getRuntime\(\)\.exec)\s*\(/i.test(s)) return { category: "COMMAND_INJECTION", severity: "HIGH" };
  if (/\b(?:query|execute|raw|prepareStatement)\s*\(/i.test(s)) return { category: "SQL_INJECTION", severity: "HIGH" };
  if (/\b(?:innerHTML|outerHTML|document\.write)\b/i.test(s)) return { category: "XSS", severity: "HIGH" };
  if (/\b(?:ObjectInputStream|readObject|yaml\.load|pickle\.loads)\b/i.test(s)) return { category: "INSECURE_DESERIALIZATION", severity: "HIGH" };
  return null;
}
function hasSanitizer(s: string, category: string): boolean {
  if (category === "XSS") return /DOMPurify\.sanitize|escapeHtml|sanitizeHtml|textContent/i.test(s);
  if (category === "SQL_INJECTION") return /prepareStatement|\.bind\w*\s*\(/i.test(s);
  if (category === "COMMAND_INJECTION") return /shell\s*:\s*false|ProcessBuilder\s*\(/i.test(s);
  return false;
}
interface Fn { file: string; name: string; node: ts.FunctionLikeDeclaration; exported: boolean; params: string[]; }
interface Summary { sinkParams: Map<number, Array<{ category: string; severity: AuditFinding["severity"]; line: number; sink: string }>>; returnParams: Set<number>; returnsSource: boolean; }

function buildFlowGraph(file: string, fn: Fn): ProjectAnalysisResult["flow_graphs"][number] {
  const nodes: ProjectAnalysisResult["flow_graphs"][number]["nodes"] = [];
  let id = 0;
  const add = (kind: string, node: ts.Node, successors: string[] = []) => { const key = `n${++id}`; nodes.push({ id: key, kind, line: lineOf(node, node.getSourceFile()), successors }); return key; };
  const walk = (statements: readonly ts.Statement[], next: string[] = []): string[] => {
    let continuation = next;
    for (let i = statements.length - 1; i >= 0; i--) {
      const stmt = statements[i];
      if (ts.isIfStatement(stmt)) {
        const merge = add("phi_merge", stmt, continuation);
        const thenEntry = walk(ts.isBlock(stmt.thenStatement) ? stmt.thenStatement.statements : [stmt.thenStatement], [merge]);
        const elseEntry = stmt.elseStatement ? walk(ts.isBlock(stmt.elseStatement) ? stmt.elseStatement.statements : [stmt.elseStatement], [merge]) : [merge];
        continuation = [add("branch", stmt, [...thenEntry, ...elseEntry])];
      } else if (ts.isWhileStatement(stmt) || ts.isForStatement(stmt) || ts.isForOfStatement(stmt) || ts.isForInStatement(stmt)) {
        const loop = add("loop", stmt, continuation); const body = walk(ts.isBlock(stmt.statement) ? stmt.statement.statements : [stmt.statement], [loop]); nodes.find(n => n.id === loop)!.successors = [...body, ...continuation]; continuation = [loop];
      } else continuation = [add(ts.isReturnStatement(stmt) ? "return" : ts.isVariableStatement(stmt) ? "definition" : "statement", stmt, continuation)];
    }
    return continuation;
  };
  if (fn.node.body && ts.isBlock(fn.node.body)) walk(fn.node.body.statements);
  return { file, function: fn.name, nodes };
}

function analyzeTypeScriptProject(files: Record<string, string>): { findings: AuditFinding[]; module_graph: ProjectAnalysisResult["module_graph"]; flow_graphs: ProjectAnalysisResult["flow_graphs"]; summary_iterations: number; summary_fixed_point_reached: boolean } {
  const tsFiles = Object.entries(files).filter(([f]) => /\.(?:ts|tsx|js|jsx|mjs|cjs)$/i.test(f));
  const sourceFiles = new Map<string, ts.SourceFile>();
  for (const [f, source] of tsFiles) {
    const script = /\.tsx$/i.test(f) ? ts.ScriptKind.TSX : /\.jsx$/i.test(f) ? ts.ScriptKind.JSX : /\.(?:m?js|cjs)$/i.test(f) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
    const sf = ts.createSourceFile(normalize(f), source, ts.ScriptTarget.Latest, true, script);
    if (!(sf as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics?.length) sourceFiles.set(normalize(f), sf);
  }
  const module_graph: ProjectAnalysisResult["module_graph"] = [];
  const importBindings = new Map<string, Map<string, string>>();
  const resolveModule = (from: string, spec: string): string | null => {
    if (!spec.startsWith(".")) return null;
    const base = normalize(from).split("/").slice(0, -1).concat(spec.split("/")).reduce<string[]>((a, p) => { if (p === ".") return a; if (p === "..") a.pop(); else a.push(p); return a; }, []).join("/");
    for (const candidate of [base, ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js"].map(ext => base + ext)]) if (sourceFiles.has(candidate)) return candidate;
    return null;
  };
  for (const [file, sf] of sourceFiles) {
    const imports: string[] = []; const bindings = new Map<string, string>();
    sf.forEachChild(node => {
      if (!ts.isImportDeclaration(node) || !ts.isStringLiteral(node.moduleSpecifier)) return;
      const target = resolveModule(file, node.moduleSpecifier.text); if (!target) return; imports.push(target);
      const clause = node.importClause; if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) for (const el of clause.namedBindings.elements) bindings.set(el.name.text, `${target}::${el.propertyName?.text ?? el.name.text}`);
      if (clause?.name) bindings.set(clause.name.text, `${target}::default`);
    });
    importBindings.set(file, bindings); module_graph.push({ file, imports });
  }
  const functions: Fn[] = [];
  for (const [file, sf] of sourceFiles) {
    const collect = (node: ts.Node) => {
      if (ts.isFunctionDeclaration(node) && node.name && node.body) {
        const exported = node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
        functions.push({ file, name: node.name.text, node, exported, params: node.parameters.map(p => ts.isIdentifier(p.name) ? p.name.text : "") });
      } else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) && ts.isBlock(node.initializer.body)) {
        functions.push({ file, name: node.name.text, node: node.initializer, exported: false, params: node.initializer.parameters.map(p => ts.isIdentifier(p.name) ? p.name.text : "") });
      }
      node.forEachChild(collect);
    }; collect(sf);
  }
  const fnByKey = new Map(functions.map(fn => [`${fn.file}::${fn.name}`, fn]));
  const summaries = new Map<string, Summary>();
  const flows: ProjectAnalysisResult["flow_graphs"] = functions.map(fn => buildFlowGraph(fn.file, fn));
  // Seed direct summaries, then compute a bounded monotone fixed point over local/imported calls.
  // This captures multi-hop and recursive parameter-to-sink / parameter-to-return propagation.
  const resolveFunction = (fromFile: string, call: ts.CallExpression): string | undefined => {
    const expression = call.expression;
    const name = ts.isIdentifier(expression) ? expression.text : ts.isPropertyAccessExpression(expression) ? expression.name.text : "";
    if (!name) return undefined;
    const importedTarget = importBindings.get(fromFile)?.get(name);
    if (importedTarget && fnByKey.has(importedTarget)) return importedTarget;
    const localTarget = `${fromFile}::${name}`;
    return fnByKey.has(localTarget) ? localTarget : undefined;
  };
  for (const fn of functions) {
    const sinkParams = new Map<number, Array<{ category: string; severity: AuditFinding["severity"]; line: number; sink: string }>>();
    const returnParams = new Set<number>(); let returnsSource = false;
    for (let paramIndex = 0; paramIndex < fn.params.length; paramIndex++) {
      const param = fn.params[paramIndex]; if (!param) continue;
      const tainted = new Set<string>([param]);
      const walk = (node: ts.Node) => {
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && [...tainted].some(v => new RegExp(`\\b${v}\\b`).test(node.initializer!.getText()))) tainted.add(node.name.text);
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left) && [...tainted].some(v => new RegExp(`\\b${v}\\b`).test(node.right.getText()))) tainted.add(node.left.text);
        if (ts.isCallExpression(node)) {
          const category = sinkCategory(node.getText());
          if (category) for (const arg of node.arguments) if ([...tainted].some(v => new RegExp(`\\b${v}\\b`).test(arg.getText()))) sinkParams.set(paramIndex, [...(sinkParams.get(paramIndex) ?? []), { ...category, line: lineOf(node, node.getSourceFile()), sink: node.getText() }]);
        }
        if (ts.isReturnStatement(node) && node.expression) {
          if ([...tainted].some(v => new RegExp(`\\b${v}\\b`).test(node.expression!.getText()))) returnParams.add(paramIndex);
          if (isSourceText(node.expression.getText())) returnsSource = true;
        }
        node.forEachChild(walk);
      };
      if (fn.node.body) walk(fn.node.body);
    }
    summaries.set(`${fn.file}::${fn.name}`, { sinkParams, returnParams, returnsSource });
  }
  const summaryLimit = Math.max(4, Math.min(32, functions.length + 1));
  let summaryIterations = 0; let summariesChanged = true;
  while (summariesChanged && summaryIterations < summaryLimit) {
    summariesChanged = false; summaryIterations++;
    for (const fn of functions) {
      const summary = summaries.get(`${fn.file}::${fn.name}`)!;
      if (!fn.node.body) continue;
      for (let paramIndex = 0; paramIndex < fn.params.length; paramIndex++) {
        const param = fn.params[paramIndex]; if (!param) continue;
        const tainted = new Set<string>([param]);
        const walk = (node: ts.Node) => {
          if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && [...tainted].some(v => new RegExp(`\\b${v}\\b`).test(node.initializer!.getText()))) tainted.add(node.name.text);
          if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left) && [...tainted].some(v => new RegExp(`\\b${v}\\b`).test(node.right.getText()))) tainted.add(node.left.text);
          if (ts.isCallExpression(node)) {
            const targetKey = resolveFunction(fn.file, node); const callee = targetKey ? summaries.get(targetKey) : undefined;
            if (callee) for (const [calleeParam, sinks] of callee.sinkParams) {
              const arg = node.arguments[calleeParam];
              if (arg && [...tainted].some(v => new RegExp(`\\b${v}\\b`).test(arg.getText()))) {
                const existing = summary.sinkParams.get(paramIndex) ?? [];
                for (const sink of sinks) if (!existing.some(x => x.category === sink.category && x.line === sink.line && x.sink === sink.sink)) { existing.push(sink); summary.sinkParams.set(paramIndex, existing); summariesChanged = true; }
              }
            }
            if (callee?.returnParams.size && [...node.arguments].some((arg, i) => callee.returnParams.has(i) && [...tainted].some(v => new RegExp(`\\b${v}\\b`).test(arg.getText())))) {
              // The call result is tainted; track common assignment and return forms.
              const parent = node.parent;
              if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) tainted.add(parent.name.text);
            }
          }
          if (ts.isReturnStatement(node) && node.expression && [...tainted].some(v => new RegExp(`\\b${v}\\b`).test(node.expression!.getText())) && !summary.returnParams.has(paramIndex)) { summary.returnParams.add(paramIndex); summariesChanged = true; }
          node.forEachChild(walk);
        };
        walk(fn.node.body);
      }
    }
  }
  const findings: AuditFinding[] = [];
  const addFinding = (file: string, line: number, category: { category: string; severity: AuditFinding["severity"] }, source: string, sink: string, path: string[], fnName: string, ssaVersions: string[] = [], sourceFile = file) => {
    const id = `project-${category.category.toLowerCase()}-${file}-${line}-${findings.length}`;
    findings.push({ id, file, line, severity: category.severity, category: category.category, description: `Project data-flow analysis traced attacker-controlled input through ${path.join(" → ")} into ${sink}.`, evidence: JSON.stringify({ source, source_origins: [source], source_file: sourceFile, propagation_path: path, sink, security_boundary: category.category === "XSS" ? "untrusted data to browser DOM" : "untrusted input to privileged operation", analysis: "typescript-project-ast", function: fnName, ssa_versions: ssaVersions, proof_obligations: ["source is externally controllable", "each propagation edge is statically resolved", "sink argument receives the tainted value", "context-specific mitigation is absent"] }), recommendation: "Constrain untrusted data at the trust boundary and use a sink-specific safe API." });
  };
  // Local CFG/SSA-style pass with object-property aliases, plus calls into imported/exported project functions.
  for (const [file, sf] of sourceFiles) {
    const imported = importBindings.get(file) ?? new Map();
    const scanScope = (root: ts.Node, scopeName: string) => {
      const taint = new Map<string, { origins: string[]; version: number }>();
      const objectAliases = new Map<string, string>(); let version = 0;
      const canonical = (path: string): string => {
        const dot = path.indexOf("."); const root = dot < 0 ? path : path.slice(0, dot);
        const mapped = objectAliases.get(root); return mapped ? mapped + (dot < 0 ? "" : path.slice(dot)) : path;
      };
      const alias = (target: string, expression: string, line: number) => {
        const origins = [...taint.entries()].filter(([key]) => expression === key || expression.includes(key) || expression.startsWith(`${key}.`)).flatMap(([, value]) => value.origins);
        if (isSourceText(expression)) origins.push(`source:${expression}#L${line}`);
        const callMatch = expression.match(/^([A-Za-z_$][\w$]*)\s*\(/);
        if (callMatch) {
          const resolved = imported.get(callMatch[1]);
          const local = fnByKey.has(`${file}::${callMatch[1]}`) ? `${file}::${callMatch[1]}` : undefined;
          const summary = summaries.get(resolved ?? local ?? "");
          if (summary?.returnsSource) origins.push(`source:${resolved ?? local}#return`);
          if (summary?.returnParams.size) {
            const args = expression.slice(expression.indexOf("(") + 1, expression.lastIndexOf(")"));
            for (const [key, value] of taint) if (args.includes(key)) origins.push(...value.origins);
          }
        }
        if (origins.length) taint.set(canonical(target), { origins: [...new Set(origins)], version: ++version });
      };
      const walk = (node: ts.Node) => {
        if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
          const rhs = node.initializer.getText();
          if (ts.isIdentifier(node.initializer)) objectAliases.set(node.name.text, canonical(rhs));
          alias(node.name.text, rhs, lineOf(node, sf));
        }
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          const target = canonical(node.left.getText()); alias(target, node.right.getText(), lineOf(node, sf));
          // Heap/object alias: propagate a tainted property write to the receiver's field path.
          if (ts.isPropertyAccessExpression(node.left)) alias(node.left.getText(), node.right.getText(), lineOf(node, sf));
        }
        if (ts.isIfStatement(node)) {
          const guard = node.expression.getText();
          // Context-aware sanitizer facts are scoped to the guarded branch only.
          const guarded = /(?:allowlist|allowed\w*|\.includes\(|\.has\(|\.test\()/.test(guard);
          if (guarded) {
            const before = new Map(taint);
            walk(node.thenStatement);
            const terminates = ts.isThrowStatement(node.thenStatement) || ts.isReturnStatement(node.thenStatement) || (ts.isBlock(node.thenStatement) && node.thenStatement.statements.some(s => ts.isThrowStatement(s) || ts.isReturnStatement(s)));
            if (terminates && /^\s*!/.test(guard)) {
              const variable = guard.match(/(?:includes|contains|has|test)\s*\(\s*([A-Za-z_$][\w$]*)/i)?.[1];
              if (variable) taint.delete(variable);
            } else if (!terminates) for (const [k, v] of before) if (!taint.has(k)) taint.set(k, v);
          } else { walk(node.thenStatement); if (node.elseStatement) walk(node.elseStatement); }
          return;
        }
        if (ts.isCallExpression(node)) {
          const calleeText = node.expression.getText(); const directSink = sinkCategory(node.getText());
          if (directSink && node.arguments.length) {
            const argNode = node.arguments[0]; const arg = argNode.getText();
            const canonicalArg = canonical(arg);
            const literalOnly = ts.isStringLiteral(argNode) || ts.isNoSubstitutionTemplateLiteral(argNode);
            const tainted = literalOnly ? [] : [...taint.entries()].filter(([k]) => canonicalArg === k || new RegExp(`\\b${k.split(".").map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\.")}\\b`).test(canonicalArg));
            const source = isSourceText(arg) ? `source:${arg}#L${lineOf(node, sf)}` : tainted.flatMap(([, v]) => v.origins)[0];
            const mitigated = hasSanitizer(node.parent.getText(), directSink.category);
            if (source && !mitigated) addFinding(file, lineOf(node, sf), directSink, source, node.getText(), [...new Set(tainted.flatMap(([, v]) => v.origins).concat(source))], scopeName, tainted.map(([key, value]) => `${key}#v${value.version}`));
          }
          // Resolve imported/local call to a project function and apply its sink summary.
          const localName = ts.isIdentifier(node.expression) ? node.expression.text : ts.isPropertyAccessExpression(node.expression) ? node.expression.name.text : "";
          const targetKey = imported.get(localName) ?? (fnByKey.has(`${file}::${localName}`) ? `${file}::${localName}` : "");
          const summary = targetKey ? summaries.get(targetKey) : undefined;
          const targetFn = targetKey ? fnByKey.get(targetKey) : undefined;
          if (summary && targetFn) for (const [paramIndex, sinks] of summary.sinkParams) {
            const arg = node.arguments[paramIndex]; if (!arg) continue;
            const argText = arg.getText(); const canonicalArg = canonical(argText); const literalOnly = ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg); const tainted = literalOnly ? [] : [...taint.entries()].filter(([k]) => canonicalArg === k || new RegExp(`\\b${k.split(".").map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\.")}\\b`).test(canonicalArg));
            const source = isSourceText(argText) ? `source:${argText}#L${lineOf(node, sf)}` : tainted.flatMap(([, v]) => v.origins)[0];
            if (!source) continue;
            for (const sink of sinks) addFinding(targetFn.file, sink.line, sink, source, sink.sink, [...new Set(tainted.flatMap(([, v]) => v.origins).concat(source, `${file}:${lineOf(node, sf)} calls ${targetFn.name}`))], targetFn.name, tainted.map(([key, value]) => `${key}#v${value.version}`), file);
          }
        }
        node.forEachChild(walk);
      }; walk(root);
    };
    scanScope(sf, "<module>");
    for (const fn of functions.filter(x => x.file === file)) if (fn.node.body) scanScope(fn.node.body, fn.name);
  }
  const dedup = new Map<string, AuditFinding>(); for (const f of findings) dedup.set(`${f.file}:${f.line}:${f.category}:${f.evidence}`, f);
  return { findings: [...dedup.values()], module_graph, flow_graphs: flows, summary_iterations: summaryIterations, summary_fixed_point_reached: !summariesChanged };
}

function analyzePythonAstFiles(files: Record<string, string>): { findings: AuditFinding[]; status: string } {
  const entries = Object.entries(files).filter(([f]) => /\.py$/i.test(f));
  if (!entries.length) return { findings: [], status: "not_applicable" };
  const payload = Object.fromEntries(entries);
  const candidates = process.platform === "win32" ? ["python", "py"] : ["python3", "python"];
  for (const command of candidates) {
    const parsed = spawnSync(command, ["-c", PY_AST], { input: JSON.stringify(payload), encoding: "utf8", timeout: Math.min(60000, 5000 + entries.length * 50), maxBuffer: 16 * 1024 * 1024, windowsHide: true });
    if (parsed.error || parsed.status !== 0 || !parsed.stdout.trim()) continue;
    try {
      const astFiles = JSON.parse(parsed.stdout); const findings: AuditFinding[] = [];
      for (const [file, ast] of Object.entries(astFiles) as Array<[string, any]>) {
        if (!Array.isArray(ast.functions)) continue;
        for (const fn of ast.functions) {
          const tainted = new Map<string, string>();
          for (const a of fn.assignments ?? []) {
            if (isSourceText(a.expr)) tainted.set(a.target, `source:${a.expr}#L${a.line}`);
            else for (const [name, origin] of tainted) if (new RegExp(`\\b${name}\\b`).test(a.expr)) tainted.set(a.target, origin);
          }
          for (const guard of fn.guards ?? []) {
            if (!guard.terminating) continue;
            const test = String(guard.test);
            const variable = test.match(/(?:includes|contains|has)\s*\(\s*([A-Za-z_]\w*)/i)?.[1] ?? test.match(/([A-Za-z_]\w*)\s+not\s+in\s+/i)?.[1];
            if (variable) tainted.delete(variable);
          }
          for (const call of fn.calls ?? []) {
            const kind = sinkCategory(call.name + "("); if (!kind) continue;
            const arg = (call.args ?? []).join(" ");
            if (kind.category === "COMMAND_INJECTION" && call.keywords?.shell === "False") continue;
            const origin = isSourceText(arg) ? `source:${arg}#L${call.line}` : [...tainted.entries()].find(([name]) => new RegExp(`\\b${name}\\b`).test(arg))?.[1];
            if (!origin || hasSanitizer(arg, kind.category)) continue;
            findings.push({ id: `python-ast-${kind.category.toLowerCase()}-${file}-${call.line}`, file, line: call.line, severity: kind.severity, category: kind.category, description: `Python AST data-flow analysis traced ${origin} into ${call.name}.`, evidence: JSON.stringify({ source_origins: [origin], source_file: file, propagation_path: [origin, call.name], sink: call.name, analysis: "python-stdlib-ast", function: fn.name, security_boundary: "untrusted Python input to privileged operation" }), recommendation: "Use parameterized APIs, safe process invocation, and strict input validation." });
          }
        }
      }
      return { findings, status: "stdlib_ast" };
    } catch { return { findings: [], status: "parse_failed" }; }
  }
  return { findings: [], status: "unavailable" };
}

function analyzeJavaAst(files: Record<string, string>): { findings: AuditFinding[]; status: string } {
  const javaFiles = Object.entries(files).filter(([f]) => /\.java$/i.test(f));
  if (!javaFiles.length) return { findings: [], status: "not_applicable" };
  const temp = mkdtempSync(join(tmpdir(), "leo-javac-"));
  try {
    const helper = join(__dirname, "java-parser", "LeoJavaAst.java");
    const compile = spawnSync("javac", ["-d", temp, helper], { encoding: "utf8", timeout: 20000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
    if (compile.error || compile.status !== 0) return { findings: [], status: "unavailable" };
    const inputPaths: string[] = [];
    for (const [file, source] of javaFiles) {
      const safeName = file.replace(/[^a-zA-Z0-9_.-]/g, "_");
      const dest = join(temp, `${inputPaths.length}_${safeName}`);
      writeFileSync(dest, source, { encoding: "utf8", mode: 0o600 }); inputPaths.push(dest);
    }
    const run = spawnSync("java", ["-cp", temp, "LeoJavaAst", ...inputPaths], { encoding: "utf8", timeout: 30000, windowsHide: true, maxBuffer: 8 * 1024 * 1024 });
    if (run.error || run.status !== 0 || !run.stdout.trim()) return { findings: [], status: "parse_failed" };
    const parsed = JSON.parse(run.stdout);
    const findings: AuditFinding[] = [];
    for (const fileInfo of parsed.files ?? []) {
      const matched = javaFiles.find(([file]) => fileInfo.file.endsWith(basename(file)));
      if (!matched) continue;
      const file = matched[0];
      for (const method of fileInfo.methods ?? []) {
        const tainted = new Map<string, string>();
        for (const assignment of method.assignments ?? []) {
          const expr = String(assignment.expr ?? "");
          if (/\b(?:getParameter|getHeader|getQueryString|getInputStream|nextLine|readLine)\s*\(|\bargs\s*\[/i.test(expr)) tainted.set(assignment.target, `source:${expr}#L${assignment.line}`);
          else for (const [name, origin] of tainted) if (new RegExp(`\\b${name}\\b`).test(expr)) tainted.set(assignment.target, origin);
        }
        for (const call of method.calls ?? []) {
          const name = String(call.name ?? ""); const args = (call.args ?? []).join(" ");
          const kind = sinkCategory(name + "(");
          if (!kind) continue;
          const origin = /\b(?:getParameter|getHeader|getQueryString|getInputStream|nextLine|readLine)\s*\(|\bargs\s*\[/i.test(args)
            ? `source:${args}#L${call.line}`
            : [...tainted.entries()].find(([v]) => new RegExp(`\\b${v}\\b`).test(args))?.[1];
          if (!origin || hasSanitizer(args, kind.category)) continue;
          findings.push({ id: `java-ast-${kind.category.toLowerCase()}-${file}-${call.line}`, file, line: call.line, severity: kind.severity, category: kind.category, description: `Java compiler AST traced ${origin} into ${name}.`, evidence: JSON.stringify({ source_origins: [origin], source_file: file, propagation_path: [origin, `${file}:${method.name}`, name], sink: name, analysis: "javac-tree-api", function: method.name, security_boundary: "untrusted Java input to privileged operation" }), recommendation: "Use parameterized database APIs, fixed command invocations, and context-appropriate output encoding." });
        }
      }
    }
    return { findings, status: "javac_tree_api" };
  } catch { return { findings: [], status: "parse_failed" }; }
  finally { try { rmSync(temp, { recursive: true, force: true }); } catch { /* best effort cleanup */ } }
}

function languageOf(file: string): string {
  return /\.(?:tsx?|jsx?|mjs|cjs)$/i.test(file) ? "typescript-javascript" : /\.py$/i.test(file) ? "python" : /\.java$/i.test(file) ? "java" : "unknown";
}

function buildUnifiedCallGraph(files: Record<string, string>): ProjectAnalysisResult["call_graph"] {
  const declarations = new Map<string, Array<{ file: string; name: string; language: string }>>();
  const calls: ProjectAnalysisResult["call_graph"] = [];
  const addDecl = (name: string, file: string) => {
    const key = name.split(".").pop()!;
    const current = declarations.get(key) ?? [];
    if (!current.some(item => item.file === file && item.name === name)) declarations.set(key, [...current, { file, name, language: languageOf(file) }]);
  };
  // Index declarations across the complete project before resolving any call sites.
  for (const [file, source] of Object.entries(files)) {
    const lang = languageOf(file);
    if (lang === "typescript-javascript") {
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
      const visit = (n: ts.Node) => {
        if ((ts.isFunctionDeclaration(n) && n.name) || (ts.isMethodDeclaration(n) && n.name)) addDecl(n.name!.getText(sf), file);
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) addDecl(n.name.text, file);
        n.forEachChild(visit);
      }; visit(sf);
    } else if (lang === "python") {
      for (const m of source.matchAll(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm)) addDecl(m[1], file);
    } else if (lang === "java") {
      const re = /\b(?:public|private|protected|static|final|synchronized|native|abstract|\s)+[\w<>\[\],.?]+\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{/g;
      for (const m of source.matchAll(re)) addDecl(m[1], file);
    }
  }
  for (const [file, source] of Object.entries(files)) {
    const lang = languageOf(file);
    if (lang === "typescript-javascript") {
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, /\.tsx$/i.test(file) ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
      const visit = (n: ts.Node) => {
        if ((ts.isFunctionDeclaration(n) && n.name) || (ts.isMethodDeclaration(n) && n.name)) addDecl(n.name!.getText(sf), file);
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) addDecl(n.name.text, file);
        n.forEachChild(visit);
      }; visit(sf);
      const callsIn = (n: ts.Node, owner: string) => {
        if (ts.isCallExpression(n)) {
          const callee = n.expression.getText(sf).split(".").pop()!;
          if (/^[A-Za-z_$][\w$]*$/.test(callee)) {
            const matches = declarations.get(callee) ?? [];
            calls.push({ caller: `${file}::${owner}`, callee: matches.length === 1 ? `${matches[0].file}::${matches[0].name}` : callee, file, line: lineOf(n, sf), language: lang, resolution: matches.length === 1 ? "resolved" : "name_only", confidence: matches.length === 1 ? "high" : "low" });
          }
        }
        n.forEachChild(child => callsIn(child, owner));
      };
      const scan = (n: ts.Node, owner: string) => {
        if (ts.isFunctionDeclaration(n) && n.name) { callsIn(n, n.name.text); return; }
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) { callsIn(n.initializer, n.name.text); return; }
        if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) { callsIn(n, `<callback@${lineOf(n, sf)}>`); return; }
        n.forEachChild(child => scan(child, owner));
      }; scan(sf, "<module>");
    } else {
      const patterns = lang === "python" ? [/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm] : lang === "java" ? /\b(?:public|private|protected|static|final|synchronized|native|abstract|\s)+[\w<>\[\],.?]+\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{/g : null;
      if (patterns) {
        const re = patterns instanceof RegExp ? patterns : patterns[0]; let m: RegExpExecArray | null;
        while ((m = re.exec(source))) addDecl(m[1], file);
        const callRe = /\b([A-Za-z_]\w*)\s*\(/g;
        while ((m = callRe.exec(source))) {
          const name = m[1]; if (["if", "for", "while", "switch", "catch", "def", "class", "return", "new", "super", "this"].includes(name)) continue;
          const line = source.slice(0, m.index).split("\n").length;
          calls.push({ caller: `${file}::<unknown>`, callee: name, file, line, language: lang, resolution: "name_only", confidence: "low" });
        }
      }
    }
  }
  return calls;
}

function assessPathFeasibility(conditions: string[]): { status: "no_contradiction_detected" | "contradiction_detected" | "unknown"; contradictions: string[]; method: string } {
  const normalized = conditions.map(x => x.replace(/[()]/g, "").replace(/\s+/g, " ").trim());
  const facts = new Map<string, boolean>(); const contradictions: string[] = [];
  for (const condition of normalized) {
    const m = condition.match(/^(!?)([A-Za-z_$][\w$]*)\s*(===|==|!==|!=)\s*(true|false|null|undefined|0|1|["'][^"']*["'])$/);
    if (!m) continue;
    const [, neg, variable, operator, literal] = m;
    const equality = operator === "===" || operator === "==";
    const truth = (literal === "true" || literal === "1") === equality;
    const value = neg ? !truth : truth;
    const previous = facts.get(variable);
    if (previous !== undefined && previous !== value) contradictions.push(`Conflicting constraints for ${variable}: ${conditions.join(" AND ")}`);
    else facts.set(variable, value);
  }
  if (conditions.some(x => /\bfalse\b/.test(x))) contradictions.push("An enclosing condition is statically false");
  return { status: contradictions.length ? "contradiction_detected" : conditions.length ? "no_contradiction_detected" : "unknown", contradictions: [...new Set(contradictions)], method: "bounded syntactic contradiction checks; not SMT solving" };
}

function enrichFindingEvidence(findings: AuditFinding[], files: Record<string, string>): void {
  for (const finding of findings) {
    let evidence: any = {};
    try { evidence = JSON.parse(finding.evidence ?? "{}"); } catch { evidence = { raw_evidence: finding.evidence }; }
    const sourceFile = typeof evidence.source_file === "string" && files[evidence.source_file] ? evidence.source_file : finding.file;
    const source = files[sourceFile] ?? "";
    const sinkSource = files[finding.file] ?? "";
    const pathConditions: string[] = [];
    if (/\.(?:ts|tsx|js|jsx|mjs|cjs)$/i.test(finding.file)) {
      const sf = ts.createSourceFile(finding.file, sinkSource, ts.ScriptTarget.Latest, true);
      const visit = (node: ts.Node) => {
        if (ts.isIfStatement(node)) {
          const start = lineOf(node, sf); const end = sf.getLineAndCharacterOfPosition(node.end).line + 1;
          if (finding.line >= start && finding.line <= end) pathConditions.push(node.expression.getText(sf));
        }
        node.forEachChild(visit);
      }; visit(sf);
    } else {
      const lines = sinkSource.split("\n");
      for (let i = Math.max(0, finding.line - 12); i < Math.min(lines.length, finding.line - 1); i++) {
        const line = lines[i];
        if (/^\s*(?:if|elif|else|try|except|catch|finally)\b/.test(line)) pathConditions.push(`L${i + 1}: ${line.trim()}`);
      }
    }
    evidence.path_conditions = [...new Set(pathConditions)];
    evidence.path_feasibility = assessPathFeasibility(evidence.path_conditions);
    evidence.confidence_notes = [
      "Static evidence is a candidate proof, not a runtime exploit demonstration.",
      ...(pathConditions.length ? [] : ["No enclosing path condition was recovered for this sink location."]),
      ...(evidence.path_feasibility?.status === "contradiction_detected" ? ["Recovered path conditions contain a syntactic contradiction; reachability is doubtful and requires review."] : []),
      ...(evidence.source_origins?.length ? [] : ["Attacker-controlled source origin is not fully established."])
    ];
    evidence.analysis_uncertainty = {
      path_sensitivity: pathConditions.length ? "partial_enclosing_conditions" : "not_established",
      dynamic_dispatch: "not_fully_resolved",
      runtime_reachability: "not_executed",
      alias_precision: "bounded_static_model",
      path_feasibility: evidence.path_feasibility?.status ?? "unknown"
    };
    finding.evidence = JSON.stringify(evidence);
  }
}

function buildExploitabilityGraphs(findings: AuditFinding[]): ProjectAnalysisResult["exploitability_graphs"] {
  return findings.map(f => {
    let ev: any = {}; try { ev = JSON.parse(f.evidence ?? "{}"); } catch { /* keep empty */ }
    const nodes: ProjectAnalysisResult["exploitability_graphs"][number]["nodes"] = [];
    const edges: ProjectAnalysisResult["exploitability_graphs"][number]["edges"] = [];
    const add = (id: string, kind: string, label: string, file?: string, line?: number) => nodes.push({ id, kind, label, file, line });
    const source = String(ev.source ?? ev.source_origins?.[0] ?? "source unresolved");
    add("source", "source", source, ev.source_file ?? f.file);
    let previous = "source";
    for (const [i, step] of (ev.propagation_path ?? []).entries()) {
      const id = `prop-${i}`; add(id, "propagation", String(step), f.file); edges.push({ from: previous, to: id, relation: "data_flow_candidate" }); previous = id;
    }
    add("boundary", "security_boundary", String(ev.security_boundary ?? "boundary not established"));
    edges.push({ from: previous, to: "boundary", relation: "crosses_or_may_cross" });
    add("sink", "sink", String(ev.sink ?? f.description), f.file, f.line);
    edges.push({ from: "boundary", to: "sink", relation: "reaches_candidate_sink" });
    return { finding_id: f.id, nodes, edges, proof_obligations: Array.isArray(ev.proof_obligations) ? ev.proof_obligations : ["Confirm source controllability", "Confirm each propagation edge", "Confirm runtime reachability", "Confirm sink argument semantics", "Review applicable mitigations"], uncertainty: Array.isArray(ev.confidence_notes) ? ev.confidence_notes : ["Static candidate; runtime reachability not demonstrated"] };
  });
}

function generateCounterexamples(findings: AuditFinding[]): ProjectAnalysisResult["counterexamples"] {
  const templates: Record<string, { input: string; observation: string }> = {
    COMMAND_INJECTION: { input: "; leo-counterexample-<id>", observation: "A process boundary or shell interpretation occurs with attacker-controlled metacharacters." },
    SQL_INJECTION: { input: "' OR '1'='1' --", observation: "The query structure changes rather than treating the value as a bound parameter." },
    XSS: { input: "<img src=x onerror=alert(1)>", observation: "The value is interpreted as executable markup in the browser context." },
    CODE_INJECTION: { input: "__LEO_COUNTEREXAMPLE__", observation: "The value is evaluated as code rather than inert data." },
    INSECURE_DESERIALIZATION: { input: "malformed or attacker-controlled serialized object", observation: "Deserialization instantiates or executes attacker-controlled object behavior." }
  };
  return findings.map(f => {
    const t = templates[f.category] ?? { input: "boundary-specific adversarial value", observation: "The value crosses the identified trust boundary and changes sink behavior." };
    return { finding_id: f.id, status: "generated_not_executed", challenge: `Challenge ${f.category}: attempt to falsify the claimed source-to-sink path with a boundary-specific adversarial value.`, candidate_input: t.input.replace("<id>", "<unique-marker>"), expected_observation: t.observation, limitations: ["This is a test hypothesis, not a confirmed exploit payload.", "Leo has not executed the candidate against the target application.", "Authentication, routing, framework semantics and environmental preconditions may prevent reachability."] };
  });
}

export function analyzeProject(files: Record<string, string>): ProjectAnalysisResult {
  const tsResult = analyzeTypeScriptProject(files);
  const pythonResult = analyzePythonAstFiles(files);
  const pythonFindings = pythonResult.findings;
  const javaResult = analyzeJavaAst(files);
  const javaStatus = javaResult.status;
  const pythonStatus = pythonResult.status;
  const findings = [...tsResult.findings, ...pythonFindings, ...javaResult.findings];
  const contextHeapAnalysis = analyzeContextsAndHeap(files, 2);
  enrichFindingEvidence(findings, files);
  return {
    findings,
    module_graph: tsResult.module_graph,
    flow_graphs: tsResult.flow_graphs,
    parser_status: { typescript: "typescript_compiler_api", python: pythonStatus, java: javaStatus },
    call_graph: buildUnifiedCallGraph(files),
    exploitability_graphs: buildExploitabilityGraphs(findings),
    counterexamples: generateCounterexamples(findings),
    context_heap_analysis: contextHeapAnalysis,
    analysis_metadata: { summary_iterations: tsResult.summary_iterations, summary_fixed_point_reached: tsResult.summary_fixed_point_reached, context_sensitivity: "bounded k=2 call-string contexts for local resolved call edges; dynamic dispatch remains unresolved", path_solver: "optional Z3 SMT-LIB with bounded internal contradiction fallback; unsupported paths remain unknown", heap_abstraction: "allocation-site and direct-field-sensitive heap approximation; no general points-to or escape analysis" },
    limitations: [
      "TypeScript interprocedural summaries use a bounded fixed-point propagation over local and relative-import call targets; they are not full k-context-sensitive summaries, and polymorphic, dynamic and higher-order dispatch can remain unresolved.",
      "Path conditions use Z3 when installed and expressions are in the supported subset; otherwise a bounded contradiction checker returns unknown. This is not full symbolic execution or general arithmetic range analysis.",
      "The unified multi-language call graph combines compiler-AST TypeScript nodes with lower-confidence name-based Python and Java edges; name-only edges are hypotheses, not resolved calls.",
      "Heap modelling uses allocation-site and direct named-field approximations; arbitrary pointers, prototypes, reflection, container contents and escape analysis are not modeled.",
      "Exploitability graphs serialize candidate evidence and proof obligations. They do not constitute formal proofs or demonstrate runtime reachability.",
      "Counterexamples are generated challenge inputs only unless an operator explicitly invokes the Docker/Podman sandbox API. Sandboxed execution is still not proof of production exploitability.",
      "Python uses stdlib ast and currently has local-function taint propagation; Java uses javac Tree API but taint propagation remains intraprocedural."
    ]
  };
}
