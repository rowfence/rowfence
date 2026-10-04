# Changelog

What changed in each release, newest first. An alpha (`0.1.0-alpha.1`) is for trying a version early: it may
still change before that version is released. Before 1.0, a minor release (0.2.0) may change the policy
language, the `authz.*` functions, the SDKs and the file formats: what to do about it is under **Upgrading**.
Each release upgrades from the one before it. How releases are numbered and made: [RELEASING.md](RELEASING.md).

## Unreleased

### Changed

- The Zed extension carries the licence in its own folder, as Zed's registry asks, and when `rowfence` isn't
  on the PATH it points to the Installing page (the install lines it showed get the placeholder while only an
  alpha is published).

## 0.1.0 (alpha)

The first release, as an alpha: for trying rowfence early. Anything in it may still change before 0.1.0
([what a 0.x release promises](docs/reference/limits.md#what-a-0x-release-promises)). It holds:

- **The policy language** (`.authz`): types read from the app's tables, relations from their columns and link
  tables, permissions built with `and`, `or` and `not` and inherited down trees, rules for each table and
  command, column rules and masked columns, conditions in SQL, custom roles, shares that expire or carry
  conditions, scopes, invariants and tests.
- **The `rowfence` command**: compiles a policy into views, trigger-maintained inheritance tables, row-level
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
