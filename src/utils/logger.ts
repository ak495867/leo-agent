import { promises as fs } from "node:fs";
import path from "node:path";

export class SessionLogger {
  private logPath: string;
  private buffer: string[] = [];

  constructor(sessionDir: string) {
    this.logPath = path.join(sessionDir, "log.txt");
  }

  async write(line: string) {
    const timestamp = new Date().toISOString();
    this.buffer.push(`${timestamp}\t${line}`);
  }

  async flush() {
    if (this.buffer.length === 0) return;
    await fs.mkdir(path.dirname(this.logPath), { recursive: true, mode: 0o700 });
    await fs.appendFile(this.logPath, this.buffer.join("\n") + "\n", { encoding: "utf-8", mode: 0o600 });
    try { await fs.chmod(this.logPath, 0o600); } catch { /* Windows ACLs apply. */ }
    this.buffer = [];
  }
}
