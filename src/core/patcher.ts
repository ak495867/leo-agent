import path from "node:path";
import { promises as fs } from "node:fs";
import { SessionLogger } from "../utils/logger.js";

/**
 * Apply a PatchSet safely.
 *
 * For each patch whose `status` is "READY":
 *   1️⃣ Write a backup copy `<filename>.leo-backup` containing the original file.
 *   2️⃣ Verify that the original block exists in the current file.
 *   3️⃣ Replace the original block with the patched block.
 *   4️⃣ Log success / failure via the provided SessionLogger.
 *
 * Patches with `status: "DEFERRED"` are skipped (they require human review).
 *
 * @param patchSet   The PatchSet returned by the Patch agent.
 * @param projectRoot Absolute path to the project root (where Leo was invoked).
 * @param logger     Instance of SessionLogger for incremental log output.
 */
export async function applyPatchSet(
  patchSet: { patches: Array<{
    id: string;
    file: string;
    original_block: string;
    patched_block: string;
    status: "READY" | "DEFERRED";
    commit_message: string;
  }>},
  projectRoot: string,
  logger: SessionLogger
): Promise<void> {
  for (const patch of patchSet.patches) {
    if (patch.status !== "READY") {
      await logger.write(
        `⚠️ Patch ${patch.id} skipped (status: ${patch.status})`
      );
      continue;
    }

    const absoluteFile = path.resolve(projectRoot, patch.file);

    // 1️⃣ Read the current file contents
    let originalContent: string;
    try {
      originalContent = await fs.readFile(absoluteFile, "utf-8");
    } catch (e) {
      await logger.write(
        `❌ Failed to read target file for patch ${patch.id}: ${(e as Error).message}`
      );
      continue;
    }

    // 2️⃣ Verify the original block is present
    if (!originalContent.includes(patch.original_block)) {
      await logger.write(
        `❌ Original block not found for patch ${patch.id} in ${patch.file}. Skipping.`
      );
      continue;
    }

    // 3️⃣ Write a backup before mutating
    const backupPath = `${absoluteFile}.leo-backup`;
    try {
      await fs.writeFile(backupPath, originalContent, "utf-8");
    } catch (e) {
      await logger.write(
        `❌ Could not write backup for ${patch.file}: ${(e as Error).message}`
      );
      continue;
    }

    // 4️⃣ Perform the replacement
    const patchedContent = originalContent.replace(
      patch.original_block,
      patch.patched_block
    );

    try {
      await fs.writeFile(absoluteFile, patchedContent, "utf-8");
      await logger.write(
        `✅ Patched ${patch.file} — ${patch.commit_message} (patch ${patch.id})`
      );
    } catch (e) {
      await logger.write(
        `❌ Failed to write patched file for ${patch.file}: ${(e as Error).message}`
      );
      // Attempt to restore from backup if write failed
      try {
        await fs.writeFile(absoluteFile, originalContent, "utf-8");
        await logger.write(`🔁 Restored original ${patch.file} from backup`);
      } catch (_) {
        // swallow – we already logged the failure
      }
    }
  }
}
