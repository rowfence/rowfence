# Tools

| command | what |
|---|---|
| `rowstile init [--schema app] [--users app.users]` | a first policy drafted from your tables and foreign keys, a test file, `rowstile.toml`, and a note for coding agents in `AGENTS.md` (see below) |
| `rowstile dev [--once]` | on every save of the policy or its tests: check, show who gains and loses access, push, test, write the clients; a mistake stops it before applying. With `[migrations]`, it writes the migration once you stop editing. Studio runs beside it (`--no-studio`: not) |
| `rowstile studio [--port 4983] [--write]` | Studio, a local web page: the app's tables as anyone (the rows they can't see greyed; a masked column they may not read shown empty, marked `masked`, as they get it), why they hold a permission or not and what would grant it, the policy as a graph, the policy file's access diff on this data, shares and pending requests, and a test from "Ann should see this". Read-only unless `--write` (then shares and decisions are made as the person you view as); localhost only, with a token |
| `rowstile why --as user:42 folder 7 edit` | yes and why; or no, why not, and the smallest changes to the data that would grant it: each is tried in a savepoint and undone, and comes with what else it would grant |
| `rowstile migrate [p.authz] [--name N] [--check]` | the policy's changes since the lock file, as a migration for your tool (no database needed); `--check` exits 1 when a change has no migration (for CI) |
| `rowstile push [p.authz] [--development]` | a development database brought to the policy by the same migration (never production); `--development` marks a database that already has a policy as one, once |
| `rowstile review [--base main] [--markdown\|--json\|--annotations] [--db DSN]` | what the change since `--base` does: meaning, access (on a review database), risk, tests, deploy; the pull request comment with `--markdown` |
| `rowstile fmt [--check] [files]` | writes policies and test files one way; `--check` exits 1 when one isn't (for CI) |
| `rowstile apply [p.authz] [--force]` | apply it whole, with the files it includes (read from disk by the command), unless it is in force already (the same text and build, and what it made still there: row-level security on, its policies and triggers). `--force` applies in any case and computes every inheritance table again, which a plain apply keeps: what to run when `authz.verify()` says false |
| `rowstile check p.authz` | only report mistakes, as `file: line N: message [AZ201]`; exit 1 if there are any |
| `rowstile help AZ201` | what a mistake's code means, and the same mistake fixed ([error codes](../errors/README.md); `help errors` lists them) |
| `rowstile prove [p.authz] [--worlds N]` | every invariant in many small worlds, with no database: the smallest counterexample (exit 1), or that none was found. A data check (`authz.check_invariants()`) says the data keeps it; prove says whether the policy does |
| `rowstile test --coverage` | the tests, then the branches of each permission no passing check makes true, with their lines (`rowstile dev` shows how many on each save). The checks that count are the `can` ones (`user 1 can view folder 3`): a `cannot`, or a statement run `as` someone, covers nothing |
| `rowstile snapshot [--check]` | who holds what on this database's data, one sorted line per object and permission (`access.snapshot` beside the policy): on review data, commit it, and a pull request that changes access changes it; `--check` exits 1 when it is out of date |
| `rowstile indexes [--check]` | the lookups the policy makes into the app's tables that no index serves, why, and the line to add for your migration tool (rowstile doesn't add indexes to your tables: your ORM's diff would see them); `dev` warns at start |
| `rowstile plans [--as user:1]`, `rowstile bench` | each governed table read as someone, timed, with full scans and per-row subplans named; p50 and p95 of reads, lists, checks and updates (undone) as people in the data |
| `rowstile diff p.authz [--users 1,2]` | who gains and loses what (see [Governance](governance.md)); changes nothing |
| `rowstile lint` | what `authz.lint()` finds, the worst first; exit 1 on an error or a warning |
| `rowstile test [tests.authz ...]` | the current policy's tests, these named tests, and the invariants; exit 1 if any fails |
| `rowstile can\|explain\|perms\|list --as user:42 ...`, `rowstile who ...` | ask the database as someone |
| `rowstile explain-rule --as user:42 app.files insert --row '{...}'` | why a write is (or would be) refused |
| `rowstile sql --as user:42 "SELECT ..."` | a statement as the app role, signed in as someone; rolled back |
| `rowstile lsp` | the language server: errors while typing, hover, go to definition, references, outline, completion |
| `rowstile mcp` | the MCP server, for coding agents (see below) |
| `rowstile graph [p.authz]`, `rowstile client py\|ts [p.authz]` | diagram and typed helpers |
| `rowstile reapply [--force]`, `rowstile remove --yes` | the policy in force again, after an upgrade (`--force`: and every inheritance table computed again); to take the policy out |
| `core/compile_policy.py p.authz` | without a database: the SQL to apply with psql (one transaction) |
| `core/compile_policy.py p.authz --check` | only report mistakes, as `file: line N: message` |
| `core/compile_policy.py p.authz --tests [tests.authz ...]` | the tests and invariants as SQL (run after applying) |
| `core/compile_policy.py p.authz --diff [--users 1,2]` | who gains and loses what (see [Governance](governance.md)) |
| `core/compile_policy.py p.authz --graph` | a Mermaid diagram of types, relations and permissions |
| `core/compile_policy.py p.authz --client ts\|py` | typed client helpers |
| [`editor/`](../../editor/README.md) | the VS Code and Zed extensions: highlighting (SQL inside `{ }` too) and the language server; a Tree-sitter grammar for Helix and Neovim; other editors start `rowstile lsp` themselves |

`rowstile <command> --help` prints that command's own lines, and `rowstile --help` all of them.

Commands without a policy file read `rowstile.toml`, found in the current folder or a folder above it:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:DATABASE_URL"          # a DSN or URL, or env:NAME
[clients]
py = "backend/app/authz_client.py"     # written by rowstile dev (and rowstile client) on every change
[migrations]
tool = "alembic"                       # alembic, prisma, drizzle, sql, goose, dbmate or flyway
dir  = "alembic/versions"              # where the tool keeps them (each tool has a default)
```

The database is `--db` (before or after the command), else `rowstile.toml`'s, else `DATABASE_URL`, else the
`PG*` variables (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGOPTIONS`, `PGSSLMODE`,
`PGSSLROOTCERT`, `PGCHANNELBINDING`; not a password file or a service file). Those variables, and the one `database = "env:NAME"`
names, may be in `.env.local` or `.env` beside `rowstile.toml` (in the current folder while there is none), where
Next.js, Prisma and many others keep them: the environment comes first, then `.env.local`, then `.env`, and
`rowstile dev` says when the database came from a file. Nothing else in those files is read, a file that
is a link out of the folder isn't read at all, and with `--db` neither is: the command line named the database. Values are as dotenv writes them: quotes, `#` comments,
`export`, and `${NAME}` filled in. A URL's `?sslmode=`, `?host=`, `?port=` and the like are read; TLS is used when
the server has it, required with `sslmode=require`, and the server's certificate checked with `verify-ca` and
`verify-full`. Over TLS the password exchange is bound to the server's certificate when the server offers it
(`channel_binding=prefer`, the default, as in libpq; `require` refuses a server that doesn't, `disable` never
does), so a connection string from Neon's dashboard works as it is. Client certificates are refused, not ignored. The files `rowstile.toml` names to be read (the policy, the tests, the lock) are in its folder or
below; a setting it doesn't know, or one of the wrong type, is an error.
[Getting started](../getting-started.md) goes through all of it; [the cookbook](../cookbook.md) has tested patterns and
[troubleshooting](../troubleshooting.md) what people run into.

Your stack, step by step: [stacks](../stacks/README.md) (FastAPI, Next.js, other Node and Python apps, and the SQL any other
language sends). To try rowstile with nothing installed, [the playground](../../playground/README.md) runs the compiler and a real Postgres in
the browser (Pyodide and PGlite).

## Coding agents: `AGENTS.md`

`rowstile init` leaves a note for the coding agents that work in the app, in `AGENTS.md` at the project's
root: where the policy and its tests are, the loop after an edit (`check`, `push` on the development
database, `test`, or `dev`), that production takes migrations, that the app connects as the app role and
signs each transaction in, and where the rest is ([llms.txt](../../llms.txt)). Without it an agent sees a
route with no permission check and adds one.

The note sits between `<!-- rowstile:begin -->` and `<!-- rowstile:end -->`. An `AGENTS.md` that is there
keeps its text and gets the section at its end; one that has the markers is left as it is, so the section
is yours to edit, and `init` run again changes nothing. Delete the section if you don't want it.

## Coding agents: `rowstile mcp`

`rowstile mcp` is a Model Context Protocol server (stdin and stdout) with the command's own tools: `check`,
`prove`, `review`, `test`, `why`, `lint`, and `push` to a development database. Each call runs the command
once, in the folder the agent started it in, so `rowstile.toml` names the policy and the database. `check`
also returns the mistake's file and line. A finding (a mistake, a failing test, a counterexample) is an
answer with `ok: false`; a call that couldn't run (no policy file, no database) is an error. An agent is given
the command to start it, in its own settings for MCP servers:

```json
{"command": "rowstile", "args": ["mcp"]}
```

Each release publishes the server's entry to the official MCP registry, as `io.github.rowstile/rowstile`, for
clients that find servers there. The entry names the npm package, which brings its own Python.

`push` is the only tool that changes anything, and it is marked so; production takes migrations.
