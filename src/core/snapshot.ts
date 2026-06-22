import { promises as fs } from "node:fs";
import path from "node:path";
import { sync as globSync } from "glob";
import { buildTree } from "../utils/tree.js";

export interface CodebaseSnapshot {
  root: string;
  files: Record<string, string>; // relative path → content
  directory_tree: object; // built by buildTree()
  file_count: number;
  snapshot_at: string;
}

/**
 * Build a snapshot of the current project:
 *   - Glob source files (ts,tsx,js,jsx,py,go,rs,java,rb,php,cs)
 *   - Exclude common ignore patterns (node_modules, .git, dist, build)
 *   - Read each file (skip >100KB to avoid large generated assets)
 *   - Return the snapshot object.
 */
export async function buildSnapshot(projectRoot: string): Promise<CodebaseSnapshot> {
  const pattern = "**/*.{ts,tsx,js,jsx,py,go,rs,java,rb,php,cs}";
  const ignore = [
    "node_modules/**",
    ".git/**",
    "dist/**",
    "build/**",
    "*.min.js",
    "*.bundle.js"
  ];

  const files = globSync(pattern, { cwd: projectRoot, ignore, nodir: true, absolute: false });

  const fileContents: Record<string, string> = {};
  for (const rel of files) {
    const abs = path.join(projectRoot, rel);
    const stats = await fs.stat(abs);
    if (stats.size > 100_000) continue; // skip large/minified files
    const content = await fs.readFile(abs, "utf-8");
    fileContents[rel] = content;
  }

  return {
    root: projectRoot,
    files: fileContents,
    directory_tree: buildTree(Object.keys(fileContents)),
    file_count: Object.keys(fileContents).length,
    snapshot_at: new Date().toISOString()
  };
}
