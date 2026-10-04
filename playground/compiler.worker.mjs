// The compiler in a worker: Pyodide starts beside PGlite (on the page) instead of after it, and compiling a
// large policy doesn't stop the page while someone types. The page sends {id, method, args}; the answer is
// {id, result} or {id, error}.
import { compiler } from "./core.mjs";

/** @typedef {import("./core.mjs").Compiler} Compiler */
/** @typedef {{id: number, method: keyof typeof methods, args: any[]}} Call  (args: the method's, as the page sent them) */

/** @type {Compiler | null} */
let engine = null;

/** The compiler, once start() has loaded it. */
function loaded() {
  if (!engine) throw new Error("the compiler hasn't started");
  return engine;
}

const methods = {
  /** @param {string} pyodideUrl @param {Record<string, string>} files */
  async start(pyodideUrl, files) {
    /** @type {typeof import("pyodide")} */
    const { loadPyodide } = await import(`${pyodideUrl}pyodide.mjs`);
    engine = compiler(await loadPyodide({ indexURL: pyodideUrl }), files);
    return true;
  },
  /** @param {string} policy @param {string} tests */
  compile: (policy, tests) => loaded().compile(policy, tests),
  /** @param {string} code */
  help: (code) => loaded().help(code),
};

self.onmessage = async (/** @type {MessageEvent<Call>} */ { data: { id, method, args } }) => {
  try {
    const run = /** @type {(...args: unknown[]) => unknown} */ (methods[method]);
    self.postMessage({ id, result: await run(...args) });
  } catch (e) {
    self.postMessage({ id, error: e instanceof Error ? e.message : String(e) });
  }
};
