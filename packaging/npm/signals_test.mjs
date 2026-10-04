// The npm launcher when the command is stopped: it ends by the same signal (or the shell's code for it), never
// with 0, so a script or a CI step doesn't go on as if the command had finished. Run by packaging/test.sh where
// the packages are installed (Linux: it reads /proc):
//   node signals_test.mjs node_modules/rowfence/bin/rowfence.js
// Plain JavaScript, typed with JSDoc and checked strictly (packaging/npm/tsconfig.json).
import { spawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { constants } from "node:os";

const launcher = process.argv[2];
if (!launcher) throw new Error("usage: node signals_test.mjs path/to/rowfence.js");
/** @param {number} ms @returns {Promise<void>} */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The process started by pid (the Python under the launcher), once it is there. @param {number} pid */
async function childOf(pid) {
  for (let tries = 0; tries < 100; tries++) {
    for (const d of readdirSync("/proc")) {
      if (!/^\d+$/.test(d)) continue;
      try {
        const stat = readFileSync(`/proc/${d}/stat`, "utf8");
        if (Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]) === pid) return Number(d);
      } catch {
        // gone meanwhile
      }
    }
    await sleep(100);
  }
  throw new Error("the launcher started no process");
}

/** `rowfence lsp` (it waits for its input), stopped by `signal` sent to the launcher or to the Python under it:
 *  how the launcher ended. @param {NodeJS.Signals} signal @param {"launcher" | "python"} to */
async function stopped(signal, to) {
  const p = spawn(process.execPath, [launcher, "lsp"], { detached: true, stdio: ["pipe", "ignore", "ignore"] });
  if (p.pid === undefined) throw new Error("the launcher didn't start");
  /** @type {Promise<{code: number | null, signal: NodeJS.Signals | null}>} */
  const done = new Promise((r) => p.on("exit", (code, sig) => r({ code, signal: sig })));
  const python = await childOf(p.pid);
  await sleep(1000);                                  // Python has started, and waits for a message
  process.kill(to === "launcher" ? p.pid : python, signal);
  const end = await Promise.race([done, sleep(10000).then(() => null)]);
  try { process.kill(-p.pid, "SIGKILL"); } catch { /* both gone */ }
  return end;
}

let fails = 0;
for (const [signal, to] of /** @type {[NodeJS.Signals, "launcher" | "python"][]} */ ([
  ["SIGTERM", "launcher"], ["SIGTERM", "python"], ["SIGINT", "launcher"], ["SIGHUP", "launcher"], ["SIGKILL", "python"],
])) {
  const end = await stopped(signal, to);
  const ok = end !== null && (end.signal === signal || end.code === 128 + constants.signals[signal]);
  console.log(`${ok ? "ok   " : "FAIL "} ${signal} to the ${to}: the launcher ends by it (${JSON.stringify(end)})`);
  if (!ok) fails += 1;
}
process.exit(fails ? 1 : 0);
