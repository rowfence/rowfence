// Starts the rowfence language server (`rowfence lsp`) for .authz files. Everything else is in the server.
// Plain JavaScript, typed with JSDoc and checked strictly (editor/tsconfig.json).
const vscode = require("vscode");
const { LanguageClient } = require("vscode-languageclient/node");

/** @type {import("vscode-languageclient/node").LanguageClient | undefined} */
let client;

/** @param {import("vscode").ExtensionContext} context */
function activate(context) {
  const [command = "rowfence", ...args] = vscode.workspace.getConfiguration("rowfence").get("command", ["rowfence", "lsp"]);
  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;     // where rowfence.toml is looked for
  // On Windows an npm install makes `rowfence.cmd`, which only a shell starts. The shell is given one line:
  // what holds a space is quoted.
  const windows = process.platform === "win32";
  const word = (/** @type {string} */ s) => (windows && /\s/.test(s) && !s.startsWith('"') ? `"${s}"` : s);
  const started = new LanguageClient("rowfence", "rowfence",
    { command: word(command), args: args.map(word), options: { cwd, shell: windows } },
    { documentSelector: [{ language: "authz" }] });
  client = started;
  started.start();
  context.subscriptions.push({ dispose: () => started.stop() });
}

function deactivate() {
  return client ? client.stop() : undefined;
}

module.exports = { activate, deactivate };
