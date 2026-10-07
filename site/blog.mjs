// The blog's feed (Atom, /blog/feed.xml): what a feed reader and Planet PostgreSQL read. The posts themselves are
// pages like the others (pages.mjs: POSTS, readPost). Plain JavaScript, typed with JSDoc and checked strictly
// (site/tsconfig.json).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import sql from "shiki/langs/sql.mjs";
import { ORIGIN, REPO, url } from "./pages.mjs";

/** @typedef {import("./pages.mjs").Post} Post */

/** The feed's address in the site, and its title. */
export const FEED = "blog/feed.xml";
export const FEED_TITLE = "rowstile blog";

// ```authz blocks: the editor's grammar (SQL inside { } too, so Shiki's SQL is loaded with it)
const authz = JSON.parse(readFileSync(join(REPO, "editor", "syntaxes", "authz.tmLanguage.json"), "utf8"));
/** The languages the pages' code blocks are in, beyond Shiki's own.
 *  @type {NonNullable<import("vitepress").MarkdownOptions["languages"]>} */
export const LANGUAGES = [...sql, { ...authz, name: "authz", embeddedLangs: ["sql"] }];

/** Text inside XML. @param {string} text */
function xml(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** A post's Markdown without its title and its byline (a feed's entry has both as fields). @param {string} text */
export function postBody(text) {
  const blocks = text.replace(/\r\n/g, "\n").split(/\n{2,}/);
  let skipped = 0;
  while (blocks.length && skipped < 2) {
    if (blocks[0].trim()) skipped++;
    blocks.shift();
  }
  return blocks.join("\n\n");
}

/** A page's HTML as a feed reader should get it: without the page's own controls (the headings' anchors, the
 *  code blocks' copy button and language label) and without what only the site's stylesheet reads (the
 *  highlighter's spans, classes). Code stays as <pre><code>. @param {string} html */
export function forFeed(html) {
  return html
    .replace(/<a class="header-anchor"[^>]*>.*?<\/a>/g, "")
    .replace(/<button[^>]*class="copy"[^>]*><\/button>/g, "")
    .replace(/<span class="lang">[^<]*<\/span>/g, "")
    .replace(/<\/?span[^>]*>/g, "")
    .replace(/ (?:class|style|tabindex|v-pre)="[^"]*"/g, "")
    .replace(/ +(<\/h[1-6]>)/g, "$1")
    .trim();
}

/** The blog's Atom feed: every post, newest first, whole. An entry's id is its address, which never changes.
 *  @param {Post[]} posts @param {(post: Post) => string} html each post's body as HTML @returns {string} */
export function feed(posts, html) {
  const at = (/** @type {string} */ date) => `${date}T00:00:00Z`;
  const blog = ORIGIN + "/blog/";
  const entries = posts.map((p) => {
    const link = ORIGIN + url(p.address);
    return [
      "  <entry>",
      `    <title>${xml(p.title)}</title>`,
      `    <link rel="alternate" type="text/html" href="${xml(link)}"/>`,
      `    <id>${xml(link)}</id>`,
      `    <published>${at(p.date)}</published>`,
      `    <updated>${at(p.date)}</updated>`,
      `    <author><name>${xml(p.author)}</name></author>`,
      `    <summary>${xml(p.summary)}</summary>`,
      `    <content type="html">${xml(html(p))}</content>`,
      "  </entry>",
    ].join("\n");
  });
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<feed xmlns="http://www.w3.org/2005/Atom">',
    `  <title>${xml(FEED_TITLE)}</title>`,
    "  <subtitle>Authorization inside your Postgres: how it works, how it is checked, what was measured</subtitle>",
    `  <link rel="self" type="application/atom+xml" href="${ORIGIN}/${FEED}"/>`,
    `  <link rel="alternate" type="text/html" href="${blog}"/>`,
    `  <id>${blog}</id>`,
    `  <updated>${at(posts[0]?.date ?? "1970-01-01")}</updated>`,
    ...entries,
    "</feed>",
    "",
  ].join("\n");
}
