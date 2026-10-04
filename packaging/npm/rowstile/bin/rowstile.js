#!/usr/bin/env node
// rowstile for npm: runs the command (Python, standard library only, in ../command) on the Python that came
// with it, from the package for this platform (@rowstile/cli-<platform>-<arch>, -musl on a Linux with musl), so
// a TypeScript app needs no Python. ROWSTILE_PYTHON names another; without either, a python3 of 3.11 or later
// on PATH.
// Plain JavaScript, typed with JSDoc and checked strictly (packaging/npm/tsconfig.json).
"use strict";
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PLATFORMS = ["linux-x64", "linux-arm64", "linux-x64-musl", "linux-arm64-musl", "darwin-x64", "darwin-arm64",
  "win32-x64"];
const command = path.join(__dirname, "..", "command", "cli", "rowstile_cli.py");

/** Whether this Linux's C library is musl (Alpine) and not glibc: Node's report names glibc's version when
 *  that is what Node runs on. @returns {boolean} */
function musl() {
  if (process.platform !== "linux") return false;
  try {
    const report = /** @type {{excludeNetwork?: boolean, getReport(): object}} */ (process.report);
    report.excludeNetwork = true;                     // the report's network part can take seconds
    const header = /** @type {{header?: {glibcVersionRuntime?: string}}} */ (report.getReport()).header;
    return !header?.glibcVersionRuntime;
  } catch {
    return fs.existsSync("/etc/alpine-release");
  }
}

// the package for this machine first; on Linux the other C library's after it, for an npm that installed that
// one (an npm that doesn't read a package's libc installs both)
const base = `${process.platform}-${process.arch}`;
const keys = process.platform !== "linux" ? [base] : musl() ? [`${base}-musl`, base] : [base, `${base}-musl`];
const key = keys[0];

/** @returns {string | null} */
function bundled() {
  for (const k of keys) {
    if (!PLATFORMS.includes(k)) continue;
    try {
      const manifest = require.resolve(`@rowstile/cli-${k}/package.json`);
      const exe = path.join(path.dirname(manifest), JSON.parse(fs.readFileSync(manifest, "utf8")).rowstilePython);
      if (!fs.existsSync(exe)) continue;
      if (process.platform !== "win32") {
        try { fs.accessSync(exe, fs.constants.X_OK); } catch { fs.chmodSync(exe, 0o755); }
        // the other C library's Python, when it is the only one here, can't start: say so below, not ENOENT
        if (k !== key && spawnSync(exe, ["-c", "pass"]).status !== 0) continue;
      }
      return exe;
    } catch {
      // not installed
    }
  }
  return null;
}

/** @returns {string | null} */
function onPath() {
  for (const name of process.platform === "win32" ? ["python", "py"] : ["python3", "python"]) {
    const r = spawnSync(name, ["-c", "import sys; print(sys.version_info >= (3, 11))"], { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim() === "True") return name;
  }
  return null;
}

const python = process.env.ROWSTILE_PYTHON || process.env.ROWFENCE_PYTHON || bundled() || onPath();   // ROWFENCE_PYTHON: the name before the rename
if (!python) {
  console.error(`rowstile: no Python to run on. The package for this platform (@rowstile/cli-${key}) isn't installed` +
    (PLATFORMS.includes(key) ? " (optional dependencies turned off?)" : `, and there is none for ${key}`) +
    "; install Python 3.11 or later, or set ROWSTILE_PYTHON");
  process.exit(1);
}
// -E -s: the bundled Python ignores PYTHON* variables and user site-packages; -X utf8: one encoding everywhere
const child = spawn(python, ["-E", "-s", "-X", "utf8", command, ...process.argv.slice(2)], { stdio: "inherit" });
// A signal sent to this process is passed on to the command. From a terminal, Ctrl-C and a hang-up reach the
// command by themselves (it is in this process's group): passing those on would give it each one twice.
const SIGNALS = /** @type {NodeJS.Signals[]} */ (["SIGINT", "SIGTERM", "SIGHUP"]);
for (const signal of SIGNALS) {
  process.on(signal, () => {
    if (signal === "SIGTERM" || !process.stdin.isTTY) child.kill(signal);
  });
}
child.on("error", (e) => {
  console.error(`rowstile: could not run ${python}: ${e.message}` +
    (process.env.ROWSTILE_PYTHON ? "" : "; install Python 3.11 or later, or set ROWSTILE_PYTHON"));
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (!signal) process.exit(code ?? 1);
  // The command was stopped by a signal: this process ends the same way, never with 0. Its own listeners
  // would take the signal, so they go first; where the signal doesn't end it, the shell's code for it.
  for (const s of SIGNALS) process.removeAllListeners(s);
  process.kill(process.pid, signal);
  setTimeout(() => process.exit(128 + (os.constants.signals[signal] ?? 1)), 200);
});
