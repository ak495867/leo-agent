import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildSnapshot } from '../dist/core/snapshot.js';
import { applyPatchSet } from '../dist/core/patcher.js';
import { SessionLogger } from '../dist/utils/logger.js';
import { callAgent } from '../dist/api/openrouter.js';
import { loadConfig, saveConfig } from '../dist/utils/config.js';
import { createSnapshotBatches } from '../dist/analysis/batching.js';
import { runTaintHeuristics } from '../dist/analysis/taint.js';
import { deduplicateFindings } from '../dist/analysis/deduplicate.js';
import { scanDependencies } from '../dist/analysis/osv.js';
import { runRuleRegression } from '../dist/analysis/regression.js';

async function tempDir(prefix) { return fs.mkdtemp(path.join(os.tmpdir(), prefix)); }

test('snapshot includes C, C++, headers, Bash and existing languages', async (t) => {
  const dir = await tempDir('leo-snapshot-'); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  for (const [name, body] of [['a.c', 'int a;'], ['b.cpp', 'int b;'], ['c.h', 'int c;'], ['d.sh', 'echo d'], ['e.py', 'print(1)'], ['package-lock.json', '{\"packages\":{}}']]) await fs.writeFile(path.join(dir, name), body);
  const snapshot = await buildSnapshot(dir);
  assert.equal(snapshot.file_count, 6);
  assert.ok(snapshot.files['a.c']); assert.ok(snapshot.files['b.cpp']); assert.ok(snapshot.files['c.h']); assert.ok(snapshot.files['d.sh']); assert.ok(snapshot.files['package-lock.json']);
});

test('multiple patches preserve the pristine per-session backup and reject traversal', async (t) => {
  const dir = await tempDir('leo-patch-'); t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const root = path.join(dir, 'project'); const session = path.join(dir, 'session');
  await fs.mkdir(root); await fs.mkdir(session); await fs.writeFile(path.join(root, 'app.py'), 'print("original")');
  const logger = new SessionLogger(session);
  const applied = await applyPatchSet({ patches: [
    { id: '1', file: 'app.py', original_block: 'print("original")', patched_block: 'print("first")', status: 'READY', commit_message: 'first' },
    { id: '2', file: 'app.py', original_block: 'print("first")', patched_block: 'print("second")', status: 'READY', commit_message: 'second' },
    { id: '3', file: '../outside.py', original_block: 'x', patched_block: 'y', status: 'READY', commit_message: 'escape' },
  ] }, root, logger, session);
  assert.equal(applied, 2);
  assert.equal(await fs.readFile(path.join(root, 'app.py'), 'utf8'), 'print("second")');
  const backup = path.join(session, 'backups', Buffer.from('app.py').toString('hex') + '.bak');
  assert.equal(await fs.readFile(backup, 'utf8'), 'print("original")');
});

test('oversized model request is rejected instead of truncated', async () => {
  await assert.rejects(() => callAgent('system', 'x'.repeat(330_000), 'model', 'key'), /exceeds Leo.s 80,000-token safety budget/);
});

test('new config defaults to no automatic patch application and is private on POSIX', async (t) => {
  const home = await tempDir('leo-config-'); t.after(() => fs.rm(home, { recursive: true, force: true }));
  const oldHome = process.env.HOME; process.env.HOME = home;
  t.after(() => { if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome; });
  await saveConfig({ openrouter_api_key: 'test', default_model: 'test/model', scan_depth: 'deep', created_at: new Date().toISOString() });
  const config = await loadConfig();
  assert.equal(config.auto_apply_patches, false);
  if (process.platform !== 'win32') assert.equal((await fs.stat(path.join(home, '.leo', 'config.json'))).mode & 0o777, 0o600);
});


test('multi-batch partitioning is deterministic, complete, and file-safe', async () => {
  const snapshot = { root: '/tmp/project', files: { 'b.py': 'b'.repeat(900), 'a.py': 'a'.repeat(900), 'c.py': 'c'.repeat(900) }, directory_tree: {}, file_count: 3, skipped_files: [], total_bytes: 2700, snapshot_at: new Date().toISOString() };
  const batches = createSnapshotBatches(snapshot, 1024);
  assert.equal(batches.length, 3);
  assert.deepEqual(batches.map(b => Object.keys(b.files).flat()), [['a.py'], ['b.py'], ['c.py']]);
  assert.deepEqual(createSnapshotBatches(snapshot, 1024).map(b => b.id), batches.map(b => b.id));
});

test('taint engine detects vulnerable command flow and avoids parameterized SQL control', () => {
  const vulnerable = runTaintHeuristics({ 'v.py': 'value = request.args.get("x")\nos.system(value)\n' });
  assert.ok(vulnerable.findings.some(f => f.category === 'COMMAND_INJECTION'));
  const safe = runTaintHeuristics({ 'safe.js': 'const id = req.query.id;\ndb.query("SELECT * FROM t WHERE id = ?", [id]);\n' });
  assert.equal(safe.findings.length, 0);
});

test('finding deduplication collapses same file/line/category candidates', () => {
  const f = { id: 'a', severity: 'HIGH', file: 'src/a.py', line: 4, category: 'SQL_INJECTION', description: 'SQL injection', evidence: 'query(x)' };
  const report = deduplicateFindings([{ findings: [f] }, { findings: [{ ...f, id: 'b', description: ' SQL   injection ' }] }]);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].id.length, 20);
});

test('OSV dependency audit reports advisory matches and exposes query count', async (t) => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const payload = JSON.parse(init.body);
    assert.equal(payload.queries[0].package.ecosystem, 'npm');
    return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-test', summary: 'test advisory', aliases: ['CVE-2026-0001'] }] }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  t.after(() => { globalThis.fetch = oldFetch; });
  const result = await scanDependencies({ 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/example': { version: '1.2.3' } } }) });
  assert.equal(result.status, 'complete');
  assert.equal(result.queried, 1);
  assert.equal(result.findings[0].category, 'VULNERABLE_DEPENDENCY');
});

test('security rule regression suite measures TP/FP/TN/FN on safe and vulnerable fixtures', async () => {
  const cases = [
    { id: 'unsafe-shell', expected: 'vulnerable', file: 'unsafe.py', source: 'cmd = request.args.get("cmd")\nos.system(cmd)' },
    { id: 'parameterized-sql', expected: 'safe', file: 'safe.js', source: 'const id = req.query.id;\ndb.query("SELECT * FROM t WHERE id = ?", [id]);' },
    { id: 'plain-function', expected: 'safe', file: 'plain.py', source: 'def add(a, b):\n    return a + b' },
  ];
  const summary = runRuleRegression(cases);
  assert.equal(summary.tp, 1); assert.equal(summary.fp, 0); assert.equal(summary.tn, 2); assert.equal(summary.fn, 0);
  assert.equal(summary.precision, 1); assert.equal(summary.recall, 1);
});

test('taint analysis does not flag an unrelated sink or an explicitly guarded allowlist variable', () => {
  const unrelated = runTaintHeuristics({ 'u.py': 'value = request.args.get("name")\nos.system("fixed-command")\n' });
  assert.equal(unrelated.findings.length, 0);
  const guarded = runTaintHeuristics({ 'g.py': 'command = request.args.get("cmd")\nif command not in {"status", "version"}:\n    raise ValueError()\nsubprocess.run(["tool", command], shell=False)\n' });
  assert.equal(guarded.findings.length, 0);
});

test('independent verifier preserves explicit rejection and removes rejected candidates', async (t) => {
  const { verifyFindings } = await import('../dist/agents/verify.js');
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ records: [{ finding_id: 'f1', disposition: 'rejected', confidence: 0.97, rationale: 'The value is constant, not attacker controlled.', evidence_checked: ['line 3'] }] }) } }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  t.after(() => { globalThis.fetch = oldFetch; });
  const report = await verifyFindings({ findings: [{ id: 'f1', severity: 'HIGH', file: 'a.py', line: 1, category: 'COMMAND_INJECTION', description: 'Possible injection' }] }, { 'a.py': 'os.system("fixed")' }, { default_model: 'test/model', openrouter_api_key: 'test' });
  assert.equal(report.findings.length, 0);
  assert.equal(report.verification.records[0].disposition, 'rejected');
  assert.ok(report.rejected_findings.length > 0);
});

test('OSV lookup degrades explicitly when offline instead of claiming clean dependencies', async (t) => {
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('offline'); };
  t.after(() => { globalThis.fetch = oldFetch; });
  const result = await scanDependencies({ 'package-lock.json': JSON.stringify({ packages: { 'node_modules/example': { version: '1.2.3' } } }) });
  assert.equal(result.status, 'unavailable');
  assert.equal(result.queried, 1);
  assert.ok(result.errors.length > 0);
});


test('taint engine follows simple variable aliases to sinks', () => {
  const result = runTaintHeuristics({ 'alias.py': 'raw = request.args.get("cmd")\ncommand = raw\nos.system(command)\n' });
  assert.ok(result.findings.some(f => f.category === 'COMMAND_INJECTION'));
});

test('labeled evaluation reports TP/FP/TN/FN and excludes unlabelled findings', async () => {
  const { evaluateLabeledFindings } = await import('../dist/analysis/evaluate.js');
  const truth = [
    { id: 'vuln', file: 'a.py', expected: 'vulnerable', category: 'COMMAND_INJECTION', line: 10 },
    { id: 'safe', file: 'b.py', expected: 'safe' },
    { id: 'missed', file: 'c.py', expected: 'vulnerable', category: 'SQL_INJECTION', line: 5 },
  ];
  const findings = [
    { id: 'f1', file: 'a.py', line: 11, category: 'COMMAND_INJECTION', severity: 'HIGH', description: 'tainted shell command' },
    { id: 'f2', file: 'b.py', line: 2, category: 'SQL_INJECTION', severity: 'HIGH', description: 'false positive' },
    { id: 'f3', file: 'outside.py', line: 2, category: 'X', severity: 'LOW', description: 'unlabeled' },
  ];
  const result = evaluateLabeledFindings(truth, findings);
  assert.equal(result.tp, 1); assert.equal(result.fp, 1); assert.equal(result.tn, 0); assert.equal(result.fn, 1);
  assert.equal(result.unscored_findings.length, 1);
});


test('checked-in security fixtures cover vulnerable and safe examples', async () => {
  const root = path.resolve('fixtures/security');
  const cases = [
    { id: 'cmd', expected: 'vulnerable', file: 'command-injection.py', source: await fs.readFile(path.join(root, 'vulnerable/command-injection.py'), 'utf8') },
    { id: 'sql', expected: 'vulnerable', file: 'sql-injection.js', source: await fs.readFile(path.join(root, 'vulnerable/sql-injection.js'), 'utf8') },
    { id: 'sql-safe', expected: 'safe', file: 'parameterized-query.js', source: await fs.readFile(path.join(root, 'safe/parameterized-query.js'), 'utf8') },
    { id: 'cmd-safe', expected: 'safe', file: 'fixed-command.py', source: await fs.readFile(path.join(root, 'safe/fixed-command.py'), 'utf8') },
  ];
  const result = runRuleRegression(cases);
  assert.equal(result.tp, 2); assert.equal(result.fp, 0); assert.equal(result.tn, 2); assert.equal(result.fn, 0);
});

test('cross-batch correlation accepts only chains grounded in known files and existing findings', async (t) => {
  const { correlateBatches } = await import('../dist/agents/correlate.js');
  const { findingFingerprint } = await import('../dist/analysis/deduplicate.js');
  const finding1 = { id: 'f1', file: 'a.py', line: 1, category: 'X', severity: 'LOW', description: 'one' };
  const finding2 = { id: 'f2', file: 'b.py', line: 2, category: 'Y', severity: 'LOW', description: 'two' };
  const id1 = findingFingerprint(finding1); const id2 = findingFingerprint(finding2);
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({
    findings: [],
    cross_file_chains: [
      { title: 'valid chain', files: ['a.py', 'b.py'], explanation: 'Two findings connect.', finding_ids: [id1, id2] },
      { title: 'unknown path', files: ['a.py', '../outside.py'], explanation: 'bad', finding_ids: [id1, id2] },
      { title: 'invented finding', files: ['a.py', 'b.py'], explanation: 'bad', finding_ids: [id1, 'fake'] }
    ]
  }) } }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  t.after(() => { globalThis.fetch = oldFetch; });
  const result = await correlateBatches([
    { findings: [finding1] },
    { findings: [finding2] }
  ], { default_model: 'test/model', openrouter_api_key: 'test' }, ['a.py', 'b.py']);
  assert.equal(result.report.findings.length, 2);
  assert.equal(result.chains.length, 1);
  assert.equal(result.chains[0].title, 'valid chain');
});

test('TypeScript AST taint engine follows attacker-controlled data through interprocedural calls', async () => {
  const source = `function runCommand(command: string) {\n  exec(command);\n}\napp.get('/run', (req, res) => {\n  const input = req.query.command;\n  runCommand(input);\n});`;
  const result = runTaintHeuristics({ 'src/server.ts': source });
  const finding = result.findings.find(f => f.category === 'COMMAND_INJECTION');
  assert.ok(finding, 'expected a command injection finding');
  assert.match(finding.description, /exec\(command\)/);
  assert.match(finding.evidence, /typescript-compiler-ast/);
  assert.match(finding.evidence, /source:req\.query\.command#L5/);
});

test('TypeScript AST taint engine follows tainted function returns', async () => {
  const source = `function getCommand(req: any) { return req.query.command; }\nconst command = getCommand(req);\nexec(command);`;
  const result = runTaintHeuristics({ 'src/server.ts': source });
  const finding = result.findings.find(f => f.category === 'COMMAND_INJECTION' && f.line === 3);
  assert.ok(finding);
  assert.match(finding.evidence, /source:req\.query\.command#L1/);
});

test('TypeScript AST control-flow analysis respects rejecting allowlist guards', async () => {
  const source = `app.get('/run', (req, res) => {\n  const command = req.query.command;\n  if (!allowedCommands.includes(command)) { throw new Error('invalid'); }\n  exec(command);\n});`;
  const result = runTaintHeuristics({ 'src/server.ts': source });
  assert.equal(result.findings.filter(f => f.category === 'COMMAND_INJECTION').length, 0);
});

test('TypeScript AST detects tainted DOM HTML assignments and ignores malformed syntax', async () => {
  const unsafe = `app.get('/profile', (req, res) => {\n  const name = req.query.name;\n  document.body.innerHTML = name;\n});`;
  const result = runTaintHeuristics({ 'src/profile.ts': unsafe, 'broken.ts': 'const = {' });
  assert.ok(result.findings.some(f => f.category === 'XSS'));
  assert.equal(result.findings.some(f => f.file === 'broken.ts'), false);
});

test('independent verifier receives source-side evidence and structured proof obligations', async (t) => {
  const { verifyFindings } = await import('../dist/agents/verify.js');
  const oldFetch = globalThis.fetch;
  let payload;
  globalThis.fetch = async (_url, init) => {
    payload = JSON.parse(init.body).messages?.[1]?.content;
    return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ records: [{ finding_id: 'ast-1', disposition: 'needs_review', confidence: 0.6, rationale: 'Needs runtime context.', evidence_checked: ['source', 'sink'], attacker_controlled_source: 'req.query.command', propagation_path: ['req.query.command', 'command', 'exec(command)'], security_boundary: 'HTTP request to shell', exploitable_sink: 'exec(command)', mitigations_reviewed: ['allowlist'] }] }) } }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  t.after(() => { globalThis.fetch = oldFetch; });
  const evidence = JSON.stringify({ source_origins: ['source:req.query.command#L2'], sink: 'exec(command)', analysis: 'typescript-compiler-ast' });
  const report = await verifyFindings({ findings: [{ id: 'ast-1', severity: 'HIGH', file: 'a.ts', line: 4, category: 'COMMAND_INJECTION', description: 'tainted command', evidence }] }, { 'a.ts': 'app.get("/", (req) => {\n const command = req.query.command;\n doSomething(command);\n exec(command);\n});' }, { default_model: 'test/model', openrouter_api_key: 'test' });
  assert.equal(report.verification.records[0].disposition, 'needs_review');
  const decoded = JSON.parse(payload);
  assert.match(decoded.findings[0].source_excerpts[0].excerpt, /req\.query\.command/);
  assert.match(decoded.findings[0].source_excerpt, /exec\(command\)/);
});


test('project analysis resolves relative TypeScript imports and follows taint into exported helper sinks', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({
    'src/server.ts': `import { run } from './runner';\napp.get('/run', (req, res) => { const input = req.query.command; run(input); });`,
    'src/runner.ts': `export function run(command: string) { const alias = command; exec(alias); }`
  });
  assert.ok(result.module_graph.some(m => m.file === 'src/server.ts' && m.imports.includes('src/runner.ts')));
  assert.ok(result.findings.some(f => f.file === 'src/runner.ts' && f.category === 'COMMAND_INJECTION'));
});

test('project CFG contains branch nodes and explicit phi merge nodes', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'src/flow.ts': `function f(x: string) { let y = x; if (x) { y = 'safe'; } else { y = x; } exec(y); }` });
  const graph = result.flow_graphs.find(g => g.function === 'f');
  assert.ok(graph);
  assert.ok(graph.nodes.some(n => n.kind === 'branch'));
  assert.ok(graph.nodes.some(n => n.kind === 'phi_merge'));
});

test('project analysis follows direct object-field aliases in TypeScript', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'src/heap.ts': `app.get('/', (req) => { const object = {}; const alias = object; alias.command = req.query.command; exec(object.command); });` });
  assert.ok(result.findings.some(f => f.category === 'COMMAND_INJECTION'));
});

test('Python standard-library AST adapter detects request-to-shell flow', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'app.py': `def run(request):\n    command = request.args.get('cmd')\n    os.system(command)\n` });
  assert.ok(result.findings.some(f => f.file === 'app.py' && f.category === 'COMMAND_INJECTION'));
  assert.equal(result.parser_status.python, 'stdlib_ast');
});

test('javac Tree API adapter detects request-to-process execution when JDK is available', async (t) => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'App.java': `class App { void run(Request req) throws Exception { String command = req.getParameter("cmd"); Runtime.getRuntime().exec(command); } }` });
  if (result.parser_status.java === 'unavailable') return t.skip('JDK compiler is not installed');
  assert.equal(result.parser_status.java, 'javac_tree_api');
  assert.ok(result.findings.some(f => f.file === 'App.java' && f.category === 'COMMAND_INJECTION'));
});

test('independent verifier receives source excerpts from a different project file', async (t) => {
  const { verifyFindings } = await import('../dist/agents/verify.js');
  const oldFetch = globalThis.fetch; let payload;
  globalThis.fetch = async (_url, init) => {
    payload = JSON.parse(init.body).messages?.[1]?.content;
    return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ records: [{ finding_id: 'cross-1', disposition: 'needs_review', confidence: 0.7, rationale: 'Cross-file flow needs context.', evidence_checked: ['caller source', 'callee sink'] }] }) } }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  t.after(() => { globalThis.fetch = oldFetch; });
  const files = { 'src/caller.ts': `app.get('/', (req) => {\n const input = req.query.command;\n run(input);\n});`, 'src/runner.ts': `export function run(command: string) {\n exec(command);\n}` };
  const evidence = JSON.stringify({ source_origins: ['source:req.query.command#L2'], source_file: 'src/caller.ts', propagation_path: ['req.query.command', 'run(command)', 'exec(command)'], sink: 'exec(command)', analysis: 'typescript-project-ast' });
  await verifyFindings({ findings: [{ id: 'cross-1', severity: 'HIGH', file: 'src/runner.ts', line: 2, category: 'COMMAND_INJECTION', description: 'Cross-file command injection', evidence }] }, files, { default_model: 'test/model', openrouter_api_key: 'test' });
  const decoded = JSON.parse(payload);
  assert.match(decoded.findings[0].source_excerpts[0].excerpt, /req\.query\.command/);
  assert.match(decoded.findings[0].source_excerpt, /exec\(command\)/);
  assert.equal(decoded.findings[0].source_file, 'src/caller.ts');
});

test('0.5 evidence graph includes source, propagation, boundary, sink and proof obligations', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'src/server.ts': `app.get('/', (req) => { const command = req.query.command; exec(command); });` });
  const finding = result.findings.find(f => f.category === 'COMMAND_INJECTION');
  assert.ok(finding);
  assert.ok(result.exploitability_graphs?.some(g => g.finding_id === finding.id && g.nodes.some(n => n.kind === 'source') && g.nodes.some(n => n.kind === 'sink')));
  assert.ok(result.exploitability_graphs.find(g => g.finding_id === finding.id).proof_obligations.length >= 3);
});

test('0.5 generates counterexample challenges without claiming execution', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'src/server.ts': `app.get('/', (req) => { const command = req.query.command; exec(command); });` });
  const finding = result.findings.find(f => f.category === 'COMMAND_INJECTION');
  const challenge = result.counterexamples?.find(c => c.finding_id === finding.id);
  assert.equal(challenge.status, 'generated_not_executed');
  assert.match(challenge.candidate_input, /leo-counterexample/);
  assert.ok(challenge.limitations.some(x => /not executed/i.test(x)));
});

test('0.5 annotates recovered path conditions and explicit uncertainty', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'src/server.ts': `function run(req) { const command = req.query.command; if (req.user.isAdmin) { exec(command); } }` });
  const finding = result.findings.find(f => f.category === 'COMMAND_INJECTION');
  assert.ok(finding);
  const evidence = JSON.parse(finding.evidence);
  assert.ok(evidence.path_conditions.some(x => /isAdmin/.test(x)));
  assert.equal(evidence.analysis_uncertainty.runtime_reachability, 'not_executed');
});

test('0.5 emits a unified cross-language call graph with confidence labels', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({ 'src/a.ts': `export function execute(x) { return helper(x); }`, 'src/b.py': `def helper(x):\n    return x\n` });
  assert.ok(Array.isArray(result.call_graph));
  assert.ok(result.call_graph.some(edge => edge.language === 'typescript-javascript'));
  assert.ok(result.call_graph.every(edge => ['high', 'low'].includes(edge.confidence)));
});

test('0.5 resolves imported TypeScript callback call sites in the unified graph', async () => {
  const { runProjectAnalysis } = await import('../dist/analysis/taint.js');
  const result = runProjectAnalysis({
    'src/server.ts': `import { run } from './runner';\napp.get('/', (req) => { run(req.query.command); });`,
    'src/runner.ts': `export function run(command) { return command; }`
  });
  assert.ok(result.call_graph.some(edge => edge.file === 'src/server.ts' && edge.callee === 'src/runner.ts::run' && edge.resolution === 'resolved'));
});

test('0.6 fixed-point summaries propagate taint through multiple imported helper layers', () => {
  const result = runTaintHeuristics({
    'src/sink.ts': 'import { exec } from "node:child_process";\nexport function dangerous(value: string) { exec(value); }\n',
    'src/middle.ts': 'import { dangerous } from "./sink";\nexport function forward(value: string) { dangerous(value); }\n',
    'src/main.ts': 'import { forward } from "./middle";\nconst command = req.query.command;\nforward(command);\n'
  });
  assert.ok(result.findings.some(f => f.category === 'COMMAND_INJECTION'), 'expected transitive source-to-sink finding');
  assert.ok(result.project_analysis.analysis_metadata.summary_iterations >= 1);
});

test('0.6 records syntactic contradictions in recovered path conditions', () => {
  const result = runTaintHeuristics({
    'contradiction.ts': 'function run(value: string) {\n  const input = req.query.input;\n  if (value === true) {\n    if (value === false) {\n      exec(input);\n    }\n  }\n}\n'
  });
  const finding = result.project_analysis.findings.find(f => f.category === 'COMMAND_INJECTION');
  assert.ok(finding, 'expected candidate finding for the nested sink');
  const evidence = JSON.parse(finding.evidence ?? '{}');
  assert.equal(evidence.path_feasibility.status, 'contradiction_detected');
});

test('1.0 engine builds bounded call-string contexts and allocation-site heap facts', async () => {
  const { analyzeContextsAndHeap } = await import('../dist/analysis/engine-v1.js');
  const result = analyzeContextsAndHeap({
    'app.ts': `function leaf(x: string) { return x; }\nfunction middle(x: string) { return leaf(x); }\nfunction main(input: string) { const obj = new Box(); obj.value = input; return middle(input); }`,
  }, 2);
  assert.ok(result.call_edges.some(e => e.callee.endsWith('::leaf')));
  assert.ok(result.contexts.some(c => c.call_string.length <= 2));
  assert.ok(result.heap_facts.some(h => h.field === 'value' && h.variable === 'obj'));
  assert.equal(result.truncated_contexts, 0);
});

test('1.0 path solver detects contradictory conditions and preserves unknown', async () => {
  const { solvePathConditions } = await import('../dist/analysis/engine-v1.js');
  const contradiction = solvePathConditions([
    { expression: 'isAdmin', polarity: true, file: 'a.ts', line: 1 },
    { expression: 'isAdmin', polarity: false, file: 'a.ts', line: 2 },
  ]);
  assert.equal(contradiction.status, 'unsat');
  const conflictingValues = solvePathConditions([
    { expression: 'count === 1', polarity: true, file: 'a.ts', line: 4 },
    { expression: 'count === 2', polarity: true, file: 'a.ts', line: 5 },
  ]);
  assert.equal(conflictingValues.status, 'unsat');
  const unsupported = solvePathConditions([{ expression: 'user.role in allowedRoles', polarity: true, file: 'a.ts', line: 3 }]);
  assert.equal(unsupported.status, 'unknown');
});

test('1.0 sandbox rejects path traversal before attempting execution', async () => {
  const { runCounterexampleInSandbox } = await import('../dist/analysis/engine-v1.js');
  const result = runCounterexampleInSandbox({ files: { '../escape.js': 'process.exit(0)' }, image: 'node:22-alpine', command: ['node', 'escape.js'] });
  assert.equal(result.status, 'rejected');
  assert.match(result.reason, /Unsafe sandbox path/);
  assert.ok(result.isolation.includes('network disabled'));
});

test('1.0 benchmark report clearly scopes metrics to its labeled corpus', async () => {
  const { buildBenchmarkReport } = await import('../dist/analysis/engine-v1.js');
  const report = buildBenchmarkReport('fixture-set', { tp: 2, fp: 1, tn: 3, fn: 0, precision: 2 / 3, recall: 1, f1: 0.8 }, 6, 'abc123');
  assert.equal(report.schema_version, '1.0');
  assert.equal(report.detector_version, '1.0.0');
  assert.equal(report.corpus_sha256, 'abc123');
  assert.equal(report.cases, 6);
  assert.ok(report.limitations.some(x => x.includes('unseen repositories')));
});

test('1.0 project report exposes context heap and path-check metadata', async () => {
  const { analyzeProject } = await import('../dist/analysis/project-analysis.js');
  const result = analyzeProject({ 'app.ts': `function inner(x: string) { return x; }\nfunction outer(x: string) { if (x === "ok") { return inner(x); } return "no"; }` });
  assert.ok(result.context_heap_analysis);
  assert.ok(Array.isArray(result.context_heap_analysis.call_edges));
  assert.ok(Array.isArray(result.context_heap_analysis.path_checks));
  assert.match(result.analysis_metadata.context_sensitivity, /k=2/);
});
