// Builds the docs site into site/dist/: the pages (VitePress), the playground at /playground/, each page's
// Markdown beside it (/getting-started.md, its links pointing to the others'), llms.txt with its links pointing
// there, llms-full.txt, and the blog's feed (/blog/feed.xml) once there is a post. Any static host serves dist/. Plain JavaScript, typed with JSDoc and checked strictly
// (site/tsconfig.json).
//   cd site && npm ci && node build.mjs          (PYTHON=... if python3 isn't the one)
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build, createMarkdownRenderer } from "vitepress";
import { FEED, LANGUAGES, feed, forFeed, postBody } from "./blog.mjs";
import { ORIGIN, PAGES, POSTS, REPO, siteLink, url } from "./pages.mjs";

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

/** A file's text once it is whole. VitePress ends its sitemap's stream without waiting for it, so the file is
 *  finished a moment after build() returns.
 *  @param {string} file @param {string} end */
async function written(file, end) {
  for (let tries = 0; tries < 100; tries++) {
    if (existsSync(file)) {
      const text = readFileSync(file, "utf8");
      if (text.includes(end)) return text;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`${file} wasn't written`);
}

await build(HERE);

// for search engines: the sitemap VitePress wrote must hold every page, and robots.txt names it (the site's source
// folder is the repository's root, so there is no public/ folder to put the file in)
const sitemap = await written(join(DIST, "sitemap.xml"), "</urlset>");
const unlisted = Object.values(PAGES).map((address) => ORIGIN + url(address)).filter((u) => !sitemap.includes(`<loc>${u}</loc>`));
if (unlisted.length) throw new Error(`sitemap.xml doesn't list ${unlisted.join(", ")}`);
// the mark and the card for shared links, at the site's root (no public/ folder: see above)
for (const f of ["mark.svg", "card.png"]) cpSync(join(HERE, "assets", f), join(DIST, f));
writeFileSync(join(DIST, "robots.txt"), `User-agent: *\nAllow: /\n\nSitemap: ${ORIGIN}/sitemap.xml\n`);

// the blog's feed: each post whole, as HTML, its links to the site's pages by their full address
if (POSTS.length) {
  const md = await createMarkdownRenderer(REPO, { languages: LANGUAGES });
  /** @type {Map<string, string>} */
  const html = new Map();
  for (const post of POSTS) {
    const body = postBody(readFileSync(join(REPO, post.source), "utf8")).replace(/\]\(([^)\s]+)\)/g, (_, /** @type {string} */ href) => {
      const link = siteLink(post.source, href);
      return `](${link.startsWith("/") ? ORIGIN + link : link})`;
    });
    // the renderer is the build's own, with the config's rules: they ask which file the text is from
    html.set(post.slug, forFeed(md.render(body, { path: join(REPO, post.source) })));
  }
  mkdirSync(dirname(join(DIST, FEED)), { recursive: true });
  writeFileSync(join(DIST, FEED), feed(POSTS, (post) => html.get(post.slug) ?? ""));
}

run(process.execPath, "playground/build.mjs");
cpSync(join(REPO, "playground", "dist"), join(DIST, "playground"), { recursive: true });

for (const [source, address] of Object.entries(PAGES)) {
  mkdirSync(dirname(join(DIST, address)), { recursive: true });
  writeFileSync(join(DIST, address), markdownLinks(source, readFileSync(join(REPO, source), "utf8")));
}
writeFileSync(join(DIST, "llms.txt"), markdownLinks("llms.txt", readFileSync(join(REPO, "llms.txt"), "utf8")));
run(process.env.PYTHON || "python3", "docs/llms_full.py", join(DIST, "llms-full.txt"));
console.log(`wrote ${DIST}`);
