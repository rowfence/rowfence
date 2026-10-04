// The docs site. The pages are the repository's Markdown, where it is (pages.mjs says which, and where each goes).
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import sql from "shiki/langs/sql.mjs";
import type { Plugin } from "vite";
import { defineConfig } from "vitepress";
import { GITHUB, PAGES, REPO, TITLES, errorSidebar, notPages, siteLink } from "../pages.mjs";

// ```authz blocks: the editor's grammar (SQL inside { } too, so Shiki's SQL is loaded with it)
const authz = JSON.parse(readFileSync(join(REPO, "editor", "syntaxes", "authz.tmLanguage.json"), "utf8"));

// The pages are outside site/, and so is Vite's root (the repository), where there is no Vue: the pages' imports of
// it are resolved from here, and the server bundle leaves Vue out (it imports it at run time, from site/.vitepress)
const SITE = join(REPO, "site");
const vueFromSite: Plugin = {
  name: "rowstile:vue-from-site",
  enforce: "pre",
  async resolveId(id, importer, options) {
    if (!/^(vue|@vue\/[^/]+)(\/|$)/.test(id) || !importer) return null;
    if (options?.ssr) return { id, external: true };
    if (importer.replaceAll("\\", "/").startsWith(SITE.replaceAll("\\", "/") + "/")) return null;
    return this.resolve(id, join(SITE, "index.md"), { ...options, skipSelf: true });
  },
};

const guide = [
  { text: "Installing", link: "/installing" },
  { text: "Getting started", link: "/getting-started" },
  { text: "Cookbook", link: "/cookbook" },
  { text: "Troubleshooting", link: "/troubleshooting" },
  { text: "Running rowstile", link: "/operations" },
  { text: "Managed Postgres: Neon, Supabase", link: "/managed-postgres" },
  { text: "Files in S3-compatible storage", link: "/signed-urls" },
  { text: "Threat model", link: "/threat-model" },
  { text: "Reporting a vulnerability", link: "/security" },
  { text: "Changelog", link: "/changelog" },
];
const stacks = [
  { text: "Pick yours", link: "/stacks/" },
  { text: "FastAPI, SQLAlchemy, Alembic", link: "/stacks/fastapi" },
  { text: "Next.js, Prisma", link: "/stacks/nextjs" },
  { text: "Node: pg, postgres.js, Drizzle", link: "/stacks/node" },
  { text: "Python", link: "/stacks/python" },
  { text: "Any other stack: SQL", link: "/stacks/sql" },
];
const sdks = [
  { text: "Python SDK", link: "/sdk/python" },
  { text: "TypeScript SDK", link: "/sdk/typescript" },
  { text: "Conformance suites", link: "/sdk/conformance" },
];
const reference = [
  { text: "The policy language", link: "/reference/language" },
  { text: "Using it from app code", link: "/reference/app-code" },
  { text: "Identity", link: "/reference/identity" },
  { text: "Governance", link: "/reference/governance" },
  { text: "Tools", link: "/reference/tools" },
  { text: "Migrations", link: "/reference/migrations" },
  { text: "Reviewing a change", link: "/reference/review" },
  { text: "How it works", link: "/reference/guarantees" },
  { text: "Speed and limits", link: "/reference/limits" },
  { text: "Error codes", link: "/errors/" },
  { text: "Words", link: "/words" },
  { text: "Editor", link: "/editor" },
  { text: "Scale benchmark", link: "/benchmark" },
  { text: "Working on rowstile", link: "/development" },
];
const examples = [
  { text: "Examples", link: "/examples/" },
  { text: "File manager", link: "/examples/filemanager" },
  { text: "Messenger", link: "/examples/messenger" },
];

export default defineConfig({
  title: "rowstile",
  description: "Access rules for Postgres: a policy file compiled into row-level security",
  srcDir: "..",
  srcExclude: notPages(),
  rewrites: PAGES,
  outDir: "./dist",
  cacheDir: "./.vitepress/cache",
  cleanUrls: true,
  vite: { plugins: [vueFromSite] },
  markdown: {
    languages: [...sql, { ...authz, name: "authz", embeddedLangs: ["sql"] }],
    config(md) {
      // indented code blocks (the docs use them for commands) get the fenced blocks' box, which scrolls
      md.core.ruler.push("indented_as_fenced", (state) => {
        for (const t of state.tokens) if (t.type === "code_block") Object.assign(t, { type: "fence", info: "", markup: "```" });
      });
      // before VitePress's own link handling: links are relative to the source file, not the page's address
      const linkOpen = md.renderer.rules.link_open!;
      md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
        const href = tokens[idx].attrGet("href");
        const source = relative(REPO, env.realPath ?? env.path).replaceAll("\\", "/");
        if (href) tokens[idx].attrSet("href", siteLink(source, href));
        return linkOpen(tokens, idx, options, env, self);
      };
    },
  },
  transformPageData(page) {
    const title = TITLES[page.relativePath];
    if (title) page.title = title;
  },
  themeConfig: {
    nav: [
      { text: "Guide", link: "/getting-started" },
      { text: "Reference", link: "/reference/language" },
      { text: "Stacks", link: "/stacks/" },
      { text: "Errors", link: "/errors/" },
      { text: "Playground", link: "/playground/", target: "_self" },
    ],
    sidebar: {
      "/errors/": [{ text: "Error codes", link: "/errors/" }, ...errorSidebar()],
      "/": [
        { text: "Guide", items: guide },
        { text: "Stacks", items: stacks },
        { text: "SDKs", items: sdks },
        { text: "Reference", items: reference },
        { text: "Examples", items: examples },
      ],
    },
    outline: [2, 3],
    search: { provider: "local" },
    socialLinks: [{ icon: "github", link: GITHUB }],
  },
});
