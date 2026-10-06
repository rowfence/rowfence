# Changelog

What changed in each release, newest first. An alpha (`0.1.0-alpha.1`) is for trying a version early: it may
still change before that version is released. Before 1.0, a minor release (0.2.0) may change the policy
language, the `authz.*` functions, the SDKs and the file formats: what to do about it is under **Upgrading**.
Each release upgrades from the one before it. How releases are numbered and made: [RELEASING.md](RELEASING.md).

## Unreleased

### Added

- Each release publishes the MCP server's entry (`rowstile mcp`) to the official MCP registry, as
  `io.github.rowstile/rowstile`, so clients that find servers there can add it by name. The entry names the
  npm package.

### Changed

- The VS Code extension (0.1.1) has an icon, keywords and a link to its page on rowstile.dev. Nothing in
  what it does changes.

### Fixed

- `rowstile indexes` and `rowstile dev` named indexes as missing on tables whose name has capital letters
  (`"TeamMember"`, as Prisma writes them): the table was looked up by its name unquoted, and never found.
- `@rowstile/prisma`: `findUniqueOrThrow` and `findFirstOrThrow` on a row that isn't there, or that the user
  can't see, threw Prisma's own error, which `route()` answered with a 500. They throw `NotFound` (404), as
  an update or a delete of such a row does.
- On Windows, in a project whose path is so long that the Python inside the npm package can't be loaded,
  `npx rowstile` stopped with a Python traceback ("DLL load failed ... The filename or extension is too
  long"). It now runs on a Python 3.11 or later from `PATH`, and without one says what is wrong in a line.
- `rowstile[psycopg]` installed a psycopg that can't be imported where the system has no libpq (Windows):
  the extra asks for `psycopg[binary]`.
- The FastAPI page didn't say that Alembic needs a sync driver (the policy's revision fails on asyncpg with
  "cannot insert multiple commands into a prepared statement"), that the owner must hold the app role, or
  what to do with a development database `rowstile dev` pushed to. It says all three.
- The Next.js and Node pages' install lines asked for the alpha of the command only, so the SDK packages
  came at an older alpha than the command. Every line asks for `@next` while only alphas are published.

## 0.1.0 (alpha)

**rowfence is now rowstile**, and 0.1.0-alpha.2 is its first release under the new name (0.1.0-alpha.1 was
published as rowfence, and those packages stay at that version). Another product, a proxy for DuckDB, was
already called Rowfence, so the project takes a name of its own. The command is `rowstile`, the packages are
`rowstile` on PyPI and npm and `@rowstile/*`, the image is `ghcr.io/rowstile/rowstile`, the docs are at
https://rowstile.dev, and the repository is github.com/rowstile/rowstile. The policy language, the `authz`
schema, the `authz.*` functions, `.authz` files and the AZ error codes keep their names; **Upgrading** below
says what to change.

The first release, as an alpha: for trying rowstile early. Anything in it may still change before 0.1.0
([what a 0.x release promises](docs/reference/limits.md#what-a-0x-release-promises)). It holds:

- **The policy language** (`.authz`): types read from the app's tables, relations from their columns and link
  tables, permissions built with `and`, `or` and `not` and inherited down trees, rules for each table and
  command, column rules and masked columns, conditions in SQL, custom roles, shares that expire or carry
  conditions, scopes, invariants and tests.
- **The `rowstile` command**: compiles a policy into views, trigger-maintained inheritance tables, row-level
  security policies and `authz.*` functions, applied as the tables' owner, with no extension and no superuser.
  Each change to the policy is a migration for Alembic, Prisma, Drizzle Kit, plain SQL, goose, dbmate or
  Flyway. Beside it: `init`, `dev`, `test` (with coverage), `prove`, `review`, `diff`, `why`, `fmt`, `lint`,
  `indexes`, `plans`, `bench`, `graph`, the generated clients, Studio, the language server and an MCP server
  for coding agents.
- **What apps call** (`authz.*`): signing in (`act_as`, API keys, JWTs), checks and lists (`can`, `list`,
  `perms_of`), sharing, who has access and why, the audit trail and change feed, access requests, break-glass,
  access reviews and view-as.
- **The SDKs**: Python (FastAPI, SQLAlchemy, psycopg, asyncpg, Alembic, pytest) and TypeScript (pg,
  postgres.js, Prisma, Drizzle, Next.js, React, Vitest).
- **The review for pull requests**: a GitHub action and a GitLab CI template that comment what a policy change
  does to access.
- **Editors**: VS Code, Zed, and a Tree-sitter grammar for Helix and Neovim.

PostgreSQL 16, 17 and 18. Installed with npm (the command with its own Python), pip or the Docker image:
[Installing](docs/installing.md).

What changed since 0.1.0-alpha.3:

### Changed

- `@rowstile/prisma`: a Prisma extension added to the client `authz()` returns is placed before `authz()`,
  which stays the last one. Your query hooks then see the errors `authz()` makes (`Refused`, `NotFound`) where
  they saw Prisma's `P2025`.

### Fixed

- `@rowstile/prisma`: the client `authz()` was made from is refused inside your own query extensions too. In a
  hook added after `authz()` it was let through, and Prisma could then answer the `findUnique` calls that
  several requests made on it in one tick with one query, signed in as the first caller: a request could be
  given a row its user may not see. An app that only uses the client `authz()` returns was not affected.
- `@rowstile/prisma`: a query hook of yours runs once for a `findUnique` or a `findUniqueOrThrow`. One added
  before `authz()` ran twice; one added after it was not called at all, so a filter it added was skipped.
- On Windows, three commands ended in a Python traceback when two paths were on different drives. `rowstile
  review` now works from a `subst` drive or a folder reached through a junction (it stopped with test files
  named in `rowstile.toml`, and with `--annotations`); for a policy on another drive than the one it runs on,
  it reviews the whole policy as new, as for any file outside the repository. `rowstile migrate --dir` with a
  folder on another drive wrote the migration and the lock file, then stopped: it now finishes. Studio shows
  such a policy's path as it is.
- `rowstile migrate` no longer adds a line to `.gitattributes` for a migrations folder or a lock file outside
  `rowstile.toml`'s folder: such a line (`../migrations/*_authz_*`) matches nothing.
- On Windows, the command's output is UTF-8 when it goes into a file or a pipe (CI, `rowstile review --markdown
  > comment.md`, `rowstile graph > policy.mmd`), as it already was in a terminal. Python wrote it in the
  system's code page: a character that page lacks (an arrow, a name or a text in another script, in a
  condition) stopped `review`, `prove` and the others with `UnicodeEncodeError`, and the files written were not
  UTF-8.
- `rowstile review` finds, at the base, a test file whose name has an accent or another non-ASCII character (it
  read the base as having no such file, so its checks showed as added), and reads a base file that isn't UTF-8
  with the bytes it can't read replaced (on Linux and macOS it stopped with a traceback).
- `rowstile review` says when a test file of the pull request doesn't parse, with the mistake. It compared the
  policies without any test file then, and said "no change to what the tests claim". A check that changed is
  shown on its own file's line (`tests/docs.authz line 12`), no longer on a line counted from the policy's top.
- `rowstile explain-rule --row` shows a row that isn't JSON as it arrived. Windows PowerShell 5 and cmd take
  the double quotes out of `'{"project_id": 1}'`, and the message was JSON's own ("Expecting property name
  enclosed in double quotes"): it now says the shell took them, and how to write the row there.
- `rowstile review` flags a relation that is newly shared once. It said so once for each kind of subject the
  relation may be shared with (`viewer : user, team#member, org#member shared`: three times, word for word).

What changed since 0.1.0-alpha.2:

### Added

- The VS Code extension is on the VS Code Marketplace too, as `rowstile.rowstile` (a preview, like on Open VSX).
- The Python SDK copies the migrated test database for each pytest-xdist worker, as `@rowstile/vitest` does
  for Vitest's: `rowstile.testing.database_per_worker(url)` returns the copy's URL (and the app role's), so
  tests that write don't meet each other. It needs no driver of the app's.
- `authz.list_links(type, id)` lists the share links on an object (an id, the relation, who made it, when,
  until when) and `authz.revoke_link(type, id, link)` turns one off by that id, so an app no longer keeps a
  table of its own to do it. For people who can share the object, or may make such links. The generated
  clients have them as `list_links` and `revoke_link` (`listLinks`, `revokeLink`).
- The Python SDK's queries by permission take the policy's names: `rowstile.sqlalchemy.Queries[ObjectType,
  Permission]()`, with the generated client's two types, has `ids`, `can`, `can_sync`, `perms_of` and
  `perms_of_sync`, and a misspelled type or permission no longer type-checks. The functions that take any
  string stay.

### Changed

- Reads plan faster in policies with tiers that inherit. With `can edit = manage or editor or parent.edit` and
  `can view = edit or viewer or parent.view`, the view of `view` looked up `parent.view`, `parent.edit` and
  `parent.manage`, and each did the same one type up, so what Postgres planned for a read grew with the number
  of ways down through the tiers. It now looks up `parent.view` alone, which includes the others. Five types
  in a chain with three tiers: from 85 views and 13 ms of planning for each read to 20 views and 1.9 ms; seven
  types with four tiers: from 519 views and 179 ms to 36 and 6.7 ms. Who holds what doesn't change, and no
  policy has to.

### Upgrading

- The next `rowstile migrate` (or `apply`) replaces the views of permissions that name others of their type:
  a migration with no change to the policy.

What changed since 0.1.0-alpha.1:

### Added

- The docs site, at https://rowstile.dev: the guides, the reference, the error codes and the playground,
  as of the latest release.
- The VS Code extension is published on Open VSX, as a preview, by the release workflow whenever its own
  version is new (VSCodium, Cursor, Gitpod and other editors install from there).

### Changed

- The name: rowfence is rowstile (above). What it writes says rowstile: the hints of the errors the runtime
  raises (`rowstile help AZ709`), `rowstile graph`'s first line, the generated clients, the compiled SQL, and
  the comments that mark its own RLS policies and masked views in the database (`'rowstile'`,
  `'rowstile masked view'`). The SDKs still read the code from the hints of a database applied by rowfence.
  The problem bodies the SDKs write have their `type` at rowstile.dev (`https://rowstile.dev/problems/refused`).
- The Zed extension carries the licence in its own folder, as Zed's registry asks, and when `rowstile` isn't
  on the PATH it points to the Installing page (the install lines it showed get the placeholder while only an
  alpha is published).
- The compiler's script in the repository is `core/compile_policy.py` (it was `authzc.py`).

### Upgrading

- Install `rowstile` in place of `rowfence`: `pip install --pre rowstile` (or `rowstile[fastapi]`, ...), `npm i
  rowstile@next` and `@rowstile/*` in place of `@rowfence/*`; in Python, `import rowstile` in place of
  `import rowfence`.
- Rename `rowfence.toml` to `rowstile.toml`. Until then the command reads `rowfence.toml` and says so. The npm
  launcher reads `ROWFENCE_PYTHON` when `ROWSTILE_PYTHON` isn't set. The GitLab review template's variables
  are `ROWSTILE_REVIEW_TOKEN`, `ROWSTILE_VERSION` and `ROWSTILE_PACKAGE`.
- The next migration (`rowstile migrate`) marks the RLS policies and masked views anew; until then the command
  still recognizes the marks rowfence wrote (`'rowfence'`, and `'authzc'` before them). The next
  `rowstile client` rewrites the clients' first line.

### Fixed

- The policies readers copy (the docs app, the cookbook, the example apps' policies and tests) are laid out as
  `rowstile fmt` writes them, so `rowstile fmt --check` in CI passes on a copy; only spacing changed.
- While only an alpha is published, a plain `pip install rowstile` finds nothing: `rowstile init` now tells a
  Python app to add `rowstile[...]>=` its own version (which lets pip and uv take a pre-release), and the stack
  pages, the Python SDK's README and `llms.txt` ask for the alpha (`--pre`, `rowstile@next`,
  `uv add --prerelease=allow`).
