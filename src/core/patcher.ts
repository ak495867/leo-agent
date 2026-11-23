import path from "node:path";
import { promises as fs } from "node:fs";
import { randomUUID } from "node:crypto";
import { SessionLogger } from "../utils/logger.js";

export async function applyPatchSet(
  patchSet: { patches: Array<{ id: string; file: string; original_block: string; patched_block: string; status: "READY" | "DEFERRED"; commit_message: string }> },
  projectRoot: string, logger: SessionLogger, sessionDir: string
): Promise<number> {
  let applied = 0;
  const root = await fs.realpath(projectRoot);
  const backupDir = path.join(sessionDir, "backups");
  await fs.mkdir(backupDir, { recursive: true, mode: 0o700 });
  const backedUp = new Set<string>();

  for (const patch of patchSet.patches) {
    if (patch.status !== "READY") { await logger.write(`Patch ${patch.id} skipped (status: ${patch.status})`); continue; }
    if (!patch.file || path.isAbsolute(patch.file) || patch.file.split(/[\\/]/).includes("..")) {
      await logger.write(`Rejected patch ${patch.id}: unsafe target path ${patch.file}`); continue;
    }
    const target = path.resolve(root, patch.file);
    if (!target.startsWith(root + path.sep)) { await logger.write(`Rejected patch ${patch.id}: target escapes project root`); continue; }
    let realTarget: string;
    try { realTarget = await fs.realpath(target); } catch (e) { await logger.write(`Patch ${patch.id}: target unavailable: ${(e as Error).message}`); continue; }
    if (!realTarget.startsWith(root + path.sep)) { await logger.write(`Rejected patch ${patch.id}: symlink target escapes project root`); continue; }
    let current: string;
    try { current = await fs.readFile(realTarget, "utf8"); } catch (e) { await logger.write(`Patch ${patch.id}: read failed: ${(e as Error).message}`); continue; }
    if (!patch.original_block || !current.includes(patch.original_block)) { await logger.write(`Patch ${patch.id}: original block missing or empty; refusing unsafe replacement`); continue; }

    // Save the first pristine version only once per file per session.
    const backupName = Buffer.from(path.relative(root, realTarget)).toString("hex") + ".bak";
    const backupPath = path.join(backupDir, backupName);
    try {
      if (!backedUp.has(realTarget)) {
        try { await fs.access(backupPath); } catch { await fs.writeFile(backupPath, current, { encoding: "utf8", flag: "wx", mode: 0o600 }); }
        backedUp.add(realTarget);
      }
      const updated = current.replace(patch.original_block, patch.patched_block);
      const temp = `${realTarget}.${randomUUID()}.leo-tmp`;
      await fs.writeFile(temp, updated, { encoding: "utf8", mode: (await fs.stat(realTarget)).mode });
      await fs.rename(temp, realTarget);
      await logger.write(`Patched ${patch.file}: ${patch.commit_message} (${patch.id})`);
      applied++;
    } catch (e) { await logger.write(`Patch ${patch.id} failed: ${(e as Error).message}`); }
  }
  return applied;
}
