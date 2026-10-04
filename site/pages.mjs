// The site's pages: which Markdown in the repository, at which address. The files stay where they are, written
// for GitHub and editors (links relative to the file); siteLink() turns each link into the site's: a page's address,
// or the file on GitHub. A link to a file that isn't in the repository fails the build.
// Plain JavaScript, typed with JSDoc and checked strictly (site/tsconfig.json).
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const GITHUB = "https://github.com/rowfence/rowfence";
const BRANCH = "main";

const errorPages = readdirSync(join(REPO, "docs", "errors")).filter((f) => /^AZ\d+\.md$/.test(f)).sort();

/** Repository path -> address in the site (the page's path, with .md). @type {Record<string, string>} */
export const PAGES = {
  "site/index.md": "index.md",
  "docs/installing.md": "installing.md",
  "docs/getting-started.md": "getting-started.md",
  "docs/cookbook.md": "cookbook.md",
  "docs/troubleshooting.md": "troubleshooting.md",
  "docs/operations.md": "operations.md",
  "docs/managed-postgres.md": "managed-postgres.md",
  "docs/signed-urls.md": "signed-urls.md",
  "docs/threat-model.md": "threat-model.md",
  "SECURITY.md": "security.md",
  "CHANGELOG.md": "changelog.md",
  "docs/reference/language.md": "reference/language.md",
  "docs/reference/app-code.md": "reference/app-code.md",
  "docs/reference/identity.md": "reference/identity.md",
  "docs/reference/governance.md": "reference/governance.md",
  "docs/reference/tools.md": "reference/tools.md",
  "docs/reference/migrations.md": "reference/migrations.md",
  "docs/reference/review.md": "reference/review.md",
  "docs/reference/guarantees.md": "reference/guarantees.md",
  "docs/reference/limits.md": "reference/limits.md",
  "core/README.md": "development.md",
  "core/CONTEXT.md": "words.md",
  "editor/README.md": "editor.md",
  "core/bench/README.md": "benchmark.md",
  "docs/stacks/README.md": "stacks/index.md",
  "docs/stacks/fastapi.md": "stacks/fastapi.md",
  "docs/stacks/nextjs.md": "stacks/nextjs.md",
  "docs/stacks/node.md": "stacks/node.md",
  "docs/stacks/python.md": "stacks/python.md",
  "docs/stacks/sql.md": "stacks/sql.md",
  "sdk/python/README.md": "sdk/python.md",
  "sdk/typescript/README.md": "sdk/typescript.md",
  "integrations/README.md": "sdk/conformance.md",
  "examples/README.md": "examples/index.md",
  "examples/filemanager/README.md": "examples/filemanager.md",
  "examples/messenger/README.md": "examples/messenger.md",
  "site/problems/refused.md": "problems/refused.md",
  "site/problems/not-found.md": "problems/not-found.md",
  "docs/errors/README.md": "errors/index.md",
  ...Object.fromEntries(errorPages.map((f) => [`docs/errors/${f}`, `errors/${f}`])),
};

/** Titles for pages whose first heading says something else on the site. @type {Record<string, string>} */
export const TITLES = { "development.md": "Working on rowfence", "words.md": "Words" };

/** A page's URL: "/reference", "/stacks/". @param {string} address */
export function url(address) {
  return "/" + address.replace(/(^|\/)index\.md$/, "$1").replace(/\.md$/, "");
}

/** Where a link written in `source` (a repository path) goes on the site: a page's URL, or GitHub.
 *  @param {string} source @param {string} href @returns {string} */
export function siteLink(source, href) {
  if (/^([a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return href;       // elsewhere, mailto:, or on the same page
  const cut = href.indexOf("#");
  const path = cut < 0 ? href : href.slice(0, cut);
  const hash = cut < 0 ? "" : href.slice(cut);
  const target = posix.normalize(path.startsWith("/") ? path.slice(1) : posix.join(posix.dirname(source), decodeURI(path)))
    .replace(/\/$/, "");
  if (target.startsWith("..") || !existsSync(join(REPO, target))) {
    throw new Error(`${source}: the link ${href} points to ${target}, which isn't in the repository`);
  }
  const dir = statSync(join(REPO, target)).isDirectory();
  const page = PAGES[target] ?? (dir ? PAGES[posix.join(target, "README.md")] : undefined);
  if (page) return url(page) + hash;
  if (target === ".") return GITHUB;
  return `${GITHUB}/${dir ? "tree" : "blob"}/${BRANCH}/${target}${hash}`;
}

/** Every other Markdown file in the repository, and the folders of what's installed or built: not pages. */
export function notPages() {
  const skip = new Set(["node_modules", ".git", "dist", ".venv", ".vitepress", ".next", "out", ".cache"]);
  const found = [...skip].map((d) => `**/${d}/**`);
  (function walk(/** @type {string} */ rel) {
    for (const e of readdirSync(join(REPO, rel), { withFileTypes: true })) {
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(p); }
      else if (e.name.endsWith(".md") && !(p in PAGES)) found.push(p);
    }
  })("");
  return found;
}

/** The error pages' sidebar: the sections of docs/errors/README.md, each code with its title. */
/** @typedef {{text: string, link: string}} Item */
/** @typedef {{text: string, collapsed: boolean, items: Item[]}} Group */
/** @returns {Group[]} */
export function errorSidebar() {
  /** @type {Group[]} */
  const groups = [];
  for (const line of readFileSync(join(REPO, "docs", "errors", "README.md"), "utf8").split("\n")) {
    const h = line.match(/^## (.+)/);
    const item = line.match(/^- \[(AZ\d+)\]\(AZ\d+\.md\): (.+)/);
    if (h) groups.push({ text: h[1], collapsed: true, items: [] });
    else if (item) groups.at(-1)?.items.push({ text: `${item[1]} ${item[2]}`, link: `/errors/${item[1]}` });
  }
  return groups;
}
