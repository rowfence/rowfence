// Builds the docs site into site/dist/: the pages (VitePress), the playground at /playground/, each page's
// Markdown beside it (/getting-started.md, its links pointing to the others'), llms.txt with its links pointing
// there, and llms-full.txt. Any static host serves dist/. Plain JavaScript, typed with JSDoc and checked strictly
// (site/tsconfig.json).
//   cd site && npm ci && node build.mjs          (PYTHON=... if python3 isn't the one)
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vitepress";
import { PAGES, REPO, siteLink } from "./pages.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = join(HERE, "dist");

/** @param {string} cmd @param {string[]} args */
function run(cmd, ...args) {
  const r = spawnSync(cmd, args, { cwd: REPO, stdio: "inherit" });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed`);
}

/** A file's Markdown links, for readers of the Markdown itself: a page's .md copy, or GitHub.
 *  @param {string} source @param {string} text */
function markdownLinks(source, text) {
  return text.replace(/\]\(([^)\s]+)\)/g, (_, /** @type {string} */ href) => {
    const link = siteLink(source, href);
    const cut = link.indexOf("#");
    const path = cut < 0 ? link : link.slice(0, cut);
    if (!path.startsWith("/")) return `](${link})`;
    const page = path.endsWith("/") ? `${path}index.md` : `${path}.md`;
    return `](${page}${cut < 0 ? "" : link.slice(cut)})`;
  });
}

await build(HERE);

run(process.execPath, "playground/build.mjs");
cpSync(join(REPO, "playground", "dist"), join(DIST, "playground"), { recursive: true });

for (const [source, address] of Object.entries(PAGES)) {
  mkdirSync(dirname(join(DIST, address)), { recursive: true });
  writeFileSync(join(DIST, address), markdownLinks(source, readFileSync(join(REPO, source), "utf8")));
}
writeFileSync(join(DIST, "llms.txt"), markdownLinks("llms.txt", readFileSync(join(REPO, "llms.txt"), "utf8")));
run(process.env.PYTHON || "python3", "docs/llms_full.py", join(DIST, "llms-full.txt"));
console.log(`wrote ${DIST}`);
