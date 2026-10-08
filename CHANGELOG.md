# Changelog

What changed in each release, newest first. An alpha (`0.1.0-alpha.1`) is for trying a version early: it may
still change before that version is released. Before 1.0, a minor release (0.2.0) may change the policy
language, the `authz.*` functions, the SDKs and the file formats: what to do about it is under **Upgrading**.
Each release upgrades from the one before it. How releases are numbered and made: [RELEASING.md](RELEASING.md).

## Unreleased

### Added

- Two starters, as template repositories: [FastAPI, SQLAlchemy and
  Alembic](https://github.com/rowstile/starter-fastapi) and [Next.js and
  Prisma](https://github.com/rowstile/starter-nextjs-prisma). Each is a small app where documents are shared
  with people and teams and no route checks a permission, with its policy, its tests, the review in CI, and
  an open pull request that shows the review's comment. The stack pages link them.
- The command reads `.env.local` and `.env` beside `rowstile.toml` (in the current folder while there is
  none) for where the database is: `DATABASE_URL`, the `PG*` variables, and the variable `database =
  "env:NAME"` names. The environment comes first, then `.env.local`, then `.env`; `rowstile dev` says when the
  database came from a file, and so does a connection that fails. Nothing else in those files is read, a
  file that is a link out of the folder isn't read, and with `--db` neither is. A Next.js or Prisma app
  keeps its URLs there: `npx rowstile init` and `npx rowstile dev` failed for want of them. (#96)
- `rowstile <command> --help` prints that command's lines of the usage and where the database comes from,
  where it printed the whole usage. `rowstile init --help` says which schema `init` reads when none is
  named: `public`.

### Changed

- `rowstile prove` finds a counterexample that needs several conditions at once in fewer worlds: at each
  size it tries, besides worlds drawn row by row, worlds where every condition holds on every row or on none,
  as the review's refactor check does. One that needs `{b1 and b2}` on one object and `{b1}` on another was
  found at the 191st world, and missed with `--worlds 200`; it is found at the 12th. Over 1,200 random
  policies, of 952 invariants that can be broken, it missed 1 with 400 worlds where it missed 4, and 4 with
  200 where it missed 12, for about a sixth more time. The worlds it tries include those, so `--worlds 80`
  counts more than 80.
- A migration run on a database that already holds what it brings says so: "this database already holds
  what this migration brings (it ran here before, or rowstile dev or push took the database there): don't
  run it, tell your migration tool it is applied [AZ607]", with the Prisma and the Alembic command in the
  hint. That is what a development database `rowstile dev` pushed to answers to `prisma migrate deploy` or
  `alembic upgrade head`; it said "this migration changes the policy the migration before it left".
  Migrations written before keep their words.
- A refusal's `table`, `command` and `code` say the same thing whichever rule refused (the 403's fields:
  <https://rowstile.dev/problems/refused>). An update or delete that `expect` explains names the table as
  the policy does, with its schema, as a refused insert always did: `public.Note` for a Prisma model `Note`,
  where it said `Note` (so does the 404 for a hidden row: `public.Note 2 not found`). A column's rule gives
  the table and `update` through Prisma too, which drops the error's fields. And `code` is the database's
  own: AZ705 for a share by someone who may not share, where every refusal said AZ709. In the TypeScript
  SDK `db.$authz.tableName("Note")` gives the policy's name for a table; in the Python SDK `answer()` returns
  that name as a third value, and `verdict()` takes it (`named`).
- `authz.lint()` names a table the policy reads for a relation when the app role may read every row of it
  (a note, like the one for a type's table without rules): who is in which team is readable.
- AZ602, a key of another type, says which: "public.User.id is integer, not bigint: write its type after
  the key, (id integer)". It said "e.g. (id uuid)".
- `rowstile init` drafts a user's own row as the reference says to write it, a relation: `self : user = id`
  and `can edit = self`, where it wrote `{id = authz.uid()}`. And a link table's relation leaves the type's
  name out however the table is spelled: `TeamMember` gives `member`, as `team_members` does.
- While only alphas are published, each release moves npm's `latest` to the alpha it publishes: a plain
  `npm i rowstile` gets the newest, and a package's page on npmjs.com shows it. `next` names it too, as
  before. From the first final release on, `latest` is a release's only.

### Fixed

- `rowstile prove` and the review's refactor check could read the column values of a world they had
  already left, kept under its address once another world took it: an invariant found broken that the
  world doesn't break (prove stopped on an internal check), or a world's answer missed. And a world where
  every condition holds could make `{archived}` and `{not archived}` hold on the same row: a corner now
  chooses each row's column values, and the conditions are read from them as in any other world.
- `rowstile prove` and the review's refactor check read a condition as a fact about the row only where it
  means the same whatever the column's type. Text in order (`{name < 'b'}`, which follows the database's
  collation), text Postgres reads as the column's number or boolean (`{size = '10'}`, `{done = 't'}`, `{kind
  in ('y')}`) and an order against `authz.uid()` are now left to the database, as a subquery is: a world may
  have any row pass them. They compared text by its characters, `'t'` with a boolean as text, and the ids a
  relation's column holds with a number as text: `{owner_id < 10}` was false for owner 2. Conditions made up
  at random are now asked of Postgres too, on the same rows, and must get the same answer.
- **Rows under a governed table.** Rowstile checks a rule on a column (`update owner_id : share`) with a
  row trigger, and forgets a row's shares when its key changes with another. Three kinds of rows escaped
  them. An app with neither partitions nor tables that inherit was not affected.
  - *A partition made after the policy was last applied* (by a job that makes next month's, say): the rule
    on a column was not checked on its rows, so someone who may update a row could change a column the
    policy keeps for others. The trigger asked whether row-level security applies to the partition, where
    rowstile turns it on at the next apply; it now asks of the table, and the rule holds on a partition
    from the moment it is made.
  - *A table that inherits from a governed one* (`CREATE TABLE ... INHERITS`): Postgres runs a table's row
    triggers for its own rows and its partitions', not for the rows stored there. No rule on a column was
    checked on them, a key change kept their shares, and the audit had no line for a relationship column
    changed there. Applying now gives each such table its table's row triggers, and `authz.lint()` reports
    one made since the last apply.
  - *A row an update puts in another partition*: Postgres runs no `AFTER UPDATE` row trigger for it. A key
    change kept its shares, so a row that took the old key later started with them, and the audit missed
    its changed relationship columns. A partitioned table now forgets the shares of every key an update
    leaves without a row, and audits the rows it moves.

  And `rowstile apply` applies when a partition, or a table that inherits, was made since the last apply:
  it answered `unchanged` and left it as it was, though `authz.lint()` said to apply again.
  **Upgrading**: apply the policy again (`rowstile apply`, or the next migration). The limits page says
  what stays a limit.
- A rule on a column whose permission involves a service (a principal type other than `user`: `update
  owner_id : bot`, or a permission a bot's relation feeds) could be passed by nobody: every update of that
  column through the app role failed with Postgres's "permission denied for schema authz_int", for the
  service the rule names as for those it refuses. The trigger that checks the rule runs as the app role
  and named the signed-in service, which is not the app role's to name; the rule is now behind a function
  made once, as the refusals' are. Nothing was let through that the policy doesn't allow. (#108)
- `rowstile apply` also applies when someone was given a privilege on rowstile's own schemas since the last
  apply. `authz.lint()` said "the next apply takes it back", and `apply` answered `unchanged`: only `rowstile
  reapply` took it back.
- With a capital letter in a governed table's name, as Prisma names tables (`"Folder"`), `rowstile push`,
  `apply` and `dev` applied the whole policy every time: `apply` never answered `unchanged`, and `dev` did
  all the work again at each save. The command looked for what the policy made under the tables' unquoted
  names, and found nothing. (#95)
- The Next.js page says which Prisma to install, where `instrumentation.ts` goes when `app/` is inside
  `src/`, how a route handler shares (`db.$authz.share`), and has the development database's step in the
  migration commands. The stack pages and troubleshooting no longer say that `rowstile migrate --check`
  tells what a database holds: it compares the policy with the lock file. (#99)
- `rowstile review`: "2 checks changed what they expect". It said "what it expects" of several.
- `rowstile review` no longer reads a test's new name as its checks removed. A test that went away, whose
  every check is in one that appeared, is said to be renamed, and its checks are compared under the new name:
  "1 test renamed. 2 checks changed what they expect", where it said "8 checks removed". The JSON has the
  names under `tests.renamed`.

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

What changed since 0.1.0-alpha.5:

### Added

- Tests can check a line as a key or a token limited to a scope would be: `with scope` after who the line is
  about, `user 3 with scope read cannot edit file 11`, `as user 3 with scope read, files refused {UPDATE
  ...}`. A scope the policy doesn't have is a mistake when the tests compile (AZ503). The editors' grammars
  know the words (the VS Code extension is 0.1.2).
- A recipe: [API keys limited to some permissions](docs/cookbook/api-keys-with-scopes.md), which those
  tests make possible. The cookbook has nineteen.
- `rowstile init` leaves a note for the coding agents that work in the app, in `AGENTS.md`: where the policy
  and its tests are, the loop after an edit, that production takes migrations, that the app connects as the
  app role and signs each transaction in. Without it an agent sees a route with no permission check and adds
  one. The note sits between two markers: an `AGENTS.md` that is there keeps its text and gets the section at
  its end, and one that has the markers is left as it is.
- Each `@rowstile/*` package has a page of its own on npm: what that package is for, its install line,
  code from the tested Next.js app, and links to its stack's page. All eight showed the SDK's one
  README.
- `authz.lint()` warns of a rule for a command the app role has no privilege for on the table (`update :
  manage` on a table it may not `UPDATE`): the rule never applies, and the statement fails with Postgres's
  own "permission denied for table", which reads like the policy refusing. It says what to grant. A privilege
  on one column is enough; `nobody` asks for none.
- A page per alternative, each with examples in both and a section on when the other is the better
  choice: [OpenFGA](docs/compare/openfga.md), [SpiceDB](docs/compare/spicedb.md),
  [ZenStack](docs/compare/zenstack.md), [row-level security by hand](docs/compare/hand-written-rls.md) and
  [checks in app code](docs/compare/app-code.md).
- A blog, with an Atom feed (`/blog/feed.xml`). Its first article:
  [Why a recursive row-level security policy is slow, and what fixes
  it](docs/blog/2026-10-07-recursive-row-level-security.md), with the experiment to run it again.

### Changed

- A refused write reads the same wherever it is said. An UPDATE or DELETE that changed nothing (the
  SDKs' `expect`, Prisma's and SQLAlchemy's writes of a row the user may not change, the generated
  clients) is `permission denied: user 3 may not update row 7 of app.notes`, like the database's own
  `user 3 may not insert this row into app.notes`. It was `may not update app.notes 7`, without who. Who
  is asked of the database, in the same transaction. A key of several columns is written as the database
  writes it, `(1,2)`, in `Refused`, in `NotFound` and in its `id` (Python wrote `(1, 2)`, TypeScript
  `("1","2")`). Generated clients: write yours again (`rowstile client py`).
- `authz.lint()` notes a relation named like a type only when that type signs in (`user : user = owner_id`:
  alone in a rule, `user` reads like any user). A relation named like another type, as `rowstile init` drafts
  and getting started writes (`project : project = project_id`), is only ever followed (`project.edit`) and
  gets no note.

- `rowstile sql --as` says what a statement that returns no rows did, in the server's words (`UPDATE 0, as
  user:2; rolled back`): "done" read as allowed when the rules had let it change nothing.
- A policy's Alembic revision stops in one line when Alembic is connected with asyncpg (which takes one
  statement at a time), naming the sync driver to give it, instead of the driver's error with the whole
  script in it.
- `rowstile init`'s draft writes an insert rule with the relation (`insert : project.edit and author`), not
  its column again (`{author_id = authz.uid()}`), and for folders inside folders lets a row with nothing
  above it be made, in the maker's own name (`insert : owner and (parent.edit or {parent_id is null})`):
  with "inside one you edit" alone, nobody could make the first one through the app.
- The coverage line of `rowstile dev` and `rowstile test --coverage` names the checks that count: "7
  branches no "can" check reaches". A statement run `as` someone passes and covers nothing.
- The FastAPI page's install line is `uv add "rowstile[...]>=0.1.0a0"`: it takes rowstile's pre-release and
  no other package's, where `--prerelease=allow` also brought betas of the app's own dependencies.
- The cookbook's folders recipe lets anyone start a top-level folder of their own
  (`insert : owner and (parent.edit or {parent_id is null})`): with `parent.edit and owner` nobody could make
  the first folder through the app.

### Fixed

- `rowstile review` says "1 user gains" (it said "1 user gain"), and names the difference that makes a
  change no refactor as its risks name theirs: "differs for user 1 on note 1" (it said "for 1 on 1").
- `rowstile why` (and Studio) tries a row in a link table for a relation with a `where`, with the values
  the condition asks (`add user 4 to app.project_members for project 1, with role = 'admin'`), or the
  change to the row that is there already (`set role = 'admin' on user 4's row of ...`). It ended with "no
  single change to shares or links grants it" where one row would. A condition that is more than columns
  with values isn't tried, and a note names the relation left out.
- `authz.lint()` no longer warns about a column a relation reads on a table whose rule is `update : nobody`,
  and the rule it suggests for such a column names `share` only where the type has it (`nobody` otherwise:
  the suggestion didn't compile on a type without `share`).
- `rowstile init` names the policy's app role in what it prints and in the first test file (it said
  `app_user` whatever `--role` was), doesn't ask to add `rowstile` to a project that has it, finds FastAPI
  and SQLAlchemy when they come through rowstile's own extras, and in a Prisma project shows the app's
  client on a URL of its own (`ROWSTILE_APP_URL`), not on Prisma's `DATABASE_URL`, which is the owner's.
- With no `--db`, no `database` in `rowstile.toml` and no variable, a failed connection says that no database
  was named and how to name one (on Windows it said `host=/var/run/postgresql is a Unix socket`).
- `rowstile dev`: an error after the policy went in (the tests' switch to the app role refused, AZ618) ends
  with "the policy is applied; its tests didn't run", not "nothing applied". AZ618's hint says who may run
  the grant when the owner didn't make the app role.
- The Next.js page shows the migration that makes the app role and its grants, Prisma's configuration on the
  owner's URL, and what to do on a development database that `rowstile dev` pushed to before
  `prisma migrate deploy` (AZ607: `prisma migrate resolve --applied`); `rowstile help AZ607`, the
  migration's own hint and the troubleshooting page say the same for each tool.
- A test line `as user X sees N {UPDATE ...}` is refused when the tests are compiled, saying that `sees`
  counts a SELECT's rows and that a write which must change no row is `refused` (it was a bare "syntax
  error" when the tests ran).
- `rowstile dev`'s access line reads "2 user(s) gain permission comment on 1 project" (it said "on 1 of
  project").
- `rowstile help` for a code the runtime raises (AZ701 to AZ713) ends with its own code, not AZ709's.
- The FastAPI page shows the imports its code uses; getting started says the draft is replaced, not edited,
  and what its Python example needs; the language page says how a condition names a column with capital
  letters.

What changed since 0.1.0-alpha.4:

### Added

- The cookbook is eighteen recipes, each a page with its own tables, policy and tests and a link that opens
  it in the playground: tenants, roles, teams inside teams, folders that inherit, sharing and links, access
  on request, a masked column, archive and trash, bots, blocking ([the cookbook](docs/cookbook.md)).
- Two pages: [rowstile and the alternatives](docs/comparison.md), and
  [how rowstile is checked](docs/how-it-is-checked.md).
- The packages say what they are on npm, PyPI and ghcr.io (keywords, links, labels), and the site has a
  sitemap, a description per page and a card for shared links.
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
- The getting-started guide began in a clone of the repository: it now begins with the installed command
  and any Postgres, and keeps the clone as the other way. It says that the `SET ROLE` session of step 6 is
  a trusted one, where a forgotten sign-in gives no rows and not the error an app's connection gets.
- The Next.js and Node pages' install lines asked for the alpha of the command only, so the SDK packages
  came at an older alpha than the command. Every line asks for `@next` while only alphas are published.

What changed since 0.1.0-alpha.3:

### Changed

- `@rowstile/prisma` (security advisory
  [GHSA-6g93-673q-c29f](https://github.com/rowstile/rowstile/security/advisories/GHSA-6g93-673q-c29f)): a
  Prisma extension added to the client `authz()` returns is placed before `authz()`,
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
