// Builds the playground into playground/dist/: the page, its scripts, and bundle.json (the compiler's files and
// the examples, read from the repository so they are the tested ones). Serve dist/ from any static host.
//   node playground/build.mjs
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..");
/** @param {string[]} parts */
const read = (...parts) => readFileSync(join(REPO, ...parts), "utf8");

/** @typedef {{name: string, source: string, data: string, policy: string, tests: string, as: string, ask: string}} Example */

/** The fenced block of a markdown file whose info string is `lang name` (name: "" for the first unnamed one).
 *  @param {string} markdown @param {string} lang @param {string} name @returns {string} */
function block(markdown, lang, name) {
  for (const m of markdown.matchAll(/```(\w+)[ \t]*([^\n]*)\n([\s\S]*?)```/g)) {
    if (m[1] === lang && m[2].trim() === name) return m[3];
  }
  throw new Error(`no \`\`\`${lang} ${name} block`);
}

/** The compiler (core/authzlib) and the examples, as the page loads them.
 *  @returns {{compiler: Record<string, string>, examples: Example[]}} */
export function bundle() {
  /** @type {Record<string, string>} */
  const compiler = {};
  for (const f of readdirSync(join(REPO, "core", "authzlib")).sort()) {
    if (f.endsWith(".py")) compiler[f] = read("core", "authzlib", f);
  }
  const guide = read("docs", "getting-started.md");
  const docsPolicy = read("core", "example", "docs.authz");
  const examples = [
    {
      name: "Getting started: projects and notes",
      source: "docs/getting-started.md",
      data: block(guide, "sql", ""),
      policy: block(guide, "authz", "db/policy.authz"),
      tests: block(guide, "authz", "db/tests/first.authz"),
      as: "user:1",
      ask: "SELECT n.id, n.body, p.name AS project\nFROM app.notes n JOIN app.projects p ON p.id = n.project_id",
    },
    {
      name: "Folders and files: inheritance, teams, denies",
      source: "core/example/docs.authz",
      data: read("core", "example", "app_schema.sql"),
      policy: docsPolicy.split("\ntest\n")[0] + "\n",       // its test section needs the scenario's shares
      tests: read("core", "example", "docs.test.authz"),
      as: "user:1",
      ask: "SELECT f.id, f.name, f.folder_id FROM app.files f ORDER BY f.id",
    },
    {
      name: "Cookbook: one small app per pattern",
      source: "docs/cookbook.md",
      // its tests bring their own rows; these few are for asking as someone
      data: read("docs", "cookbook", "schema.sql") + "\n-- a few rows to ask about (the tests bring their own)\n" +
        "INSERT INTO cb.users VALUES (1, 'Ann'), (2, 'Bo');\n" +
        "INSERT INTO cb.notes (owner_id, body) VALUES (1, 'Ann''s note'), (2, 'Bo''s note');\n",
      policy: read("docs", "cookbook", "policy.authz"),
      tests: readdirSync(join(REPO, "docs", "cookbook", "tests")).sort()
        .map((f) => read("docs", "cookbook", "tests", f)).join("\n"),
      as: "user:1",
      ask: "SELECT id, body FROM cb.notes",
    },
  ];
  return { compiler, examples };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const dist = join(HERE, "dist");
  mkdirSync(dist, { recursive: true });
  for (const f of ["index.html", "core.mjs", "playground.mjs", "compiler.worker.mjs"]) copyFileSync(join(HERE, f), join(dist, f));
  writeFileSync(join(dist, "bundle.json"), JSON.stringify(bundle()));
  console.log(`wrote ${dist}`);
}
