# Changelog

What changed in each release, newest first. An alpha (`0.1.0-alpha.1`) is for trying a version early: it may
still change before that version is released. Before 1.0, a minor release (0.2.0) may change the policy
language, the `authz.*` functions, the SDKs and the file formats: what to do about it is under **Upgrading**.
Each release upgrades from the one before it. How releases are numbered and made: [RELEASING.md](RELEASING.md).

## Unreleased

### Added

- A Managed Postgres page: the setup on any service (the app role made with SQL and given to the owner), then
  Neon and Supabase as tried with both conformance suites: which connection for what, their poolers,
  passwords, test databases, Node's TLS on Supabase, and Supabase's search path, which stops the first apply
  (AZ612) until the applying connection sets `search_path=public`.
- "On managed Postgres" in Running rowfence: what the owner of a managed database has to do (give itself the
  app role, make the app role with SQL), and Neon as tried with both conformance suites: its connection
  string, its pooler, strong passwords, test databases. The limits page says what a read through the rules
  costs: in proportion to what the reader holds directly, about a millisecond per thousand folders.
- `this.column` in a condition is the row the condition is about, wherever rowfence places it (views, rules,
  triggers, inheritance): `{exists (select 1 from app.memberships m where m.project_id = this.id)}`. Inside a
  subquery a bare name is the subquery's table's column when it has one by that name (`m.project_id = id`
  compared `m.id`): applying warns when a condition names a column of its row that it reads from another
  table, and says to write `this.<column>`. A caveat has no row: `this` there is refused (AZ112).
- `nobody`, beside `signed_in` and `anyone`: a condition that never holds (`update id : nobody`).
- `rowfence review` reads a base written in the language before this version as that version meant it, and
  says so, naming each old form: the pull request that upgrades rowfence and rewrites its policy gets a
  review, and Meaning says whether the rewrite grants the same.
- `roles : user from org` says whose custom roles count on an object: only those owned by
  what its `org` relation links it to, now (AZ211 if that relation can't name an owner). `authz.share`
  refuses another owner's role, an assignment of one grants nothing, and an object moved to another org
  stops honouring the first org's roles; `authz.create_role` refuses an owner of another type. Without
  `from`, any role for the type counts wherever it is given, as before: the language page says an app must
  then offer only the owner's roles.
- The Python SDK is typed, and ships `py.typed`: type checkers read its types. New names for them:
  `rowfence.Who` (whoever a transaction acts for), `rowfence.Id`, `rowfence.Problem`, and in
  `rowfence.testing` the fixtures' types (`AsUser`, `AssertRefused`, `AssertNotFound`).
  `rowfence.act_as_args()` gives `authz.act_as`'s two arguments.
- The generated Python client (`rowfence client`, `py`) is typed: it passes `mypy --strict` and ty. Its
  connection is a small `Connection` Protocol (psycopg's and psycopg2's fit), and each method returns what it
  says: `str`, `int`, a list of strings, or rows as `dict[str, object]`. Regenerate it after upgrading. Its
  `Id` takes a `uuid.UUID` too.
- `npm i rowfence` works on a Linux with musl (Alpine): two more packages, `@rowfence/cli-linux-x64-musl` and
  `@rowfence/cli-linux-arm64-musl`, and the launcher picks the one for the machine's C library. With only the
  other library's package there, it says there is no Python to run on (it failed with `ENOENT`).
- `authz.lint()` notes each table the app role may read that the policy doesn't name, in the schemas of the
  policy's tables (a table of password hashes or sessions with no rules: until now only a type's table
  without rules was said). A note, not a warning: a lookup table is meant to be read in full.
- `@rowfence/next`: `authzRoutes({ maxStreams })` limits the event streams open at once (1000 unless said):
  one more answers 503. Each open stream holds a subscriber, and the route answers whoever asks.
- `authz.lint()` warns about a table whose select rule makes every read slow to plan: its permissions name
  others more than once on the way, and Postgres writes each one out again each time (the limits page says
  how to write it instead). A policy of nine permissions took 1.9 s to plan a read of seven rows. A permission
  named twice in one `and` or `or` is now written once.
- `authz.lint()` reports a policy on a governed table that rowfence didn't make (one left from before, or made
  by a migration) when it applies to the app role: an error for a permissive one, which Postgres joins to the
  rules with OR, so it lets through what they refuse; a note for a restrictive one. Applying shows the error.
- `authz.break_glass`, `authz.start_review` and `authz.roles_of` take the id as a number too, like `authz.can`:
  `authz.break_glass('folder', 6, 'viewer', 'INC-7 outage')`, as the reference writes it, was "function does
  not exist".

- The docs site has an Installing page (npm, pip, the image; alphas and release candidates; from the
  repository) and this changelog.

### Changed

- The review action for GitHub (`review-ci/github`) sets up Python with `actions/setup-python` 7, which runs on
  Node 24: a self-hosted runner needs version 2.327.1 or newer. GitHub's own runners have it.
- `rowfence prove` and the review's refactor check read a simple condition (`{archived}`, `{kind = 'group'}`,
  `{parent_id is null}`, `{size > 10}`, `{owner_id = authz.uid()}`) as what it says about the row's columns:
  `{archived}` and `{not archived}` are each other's opposite (but for NULL), two spellings of one condition
  are the same, and a counterexample shows the columns it needs. Any other condition is still a set of rows
  of its own.
- The editors (VS Code, Zed, Helix, Neovim) read the language as it is now: `app role`, `anyone`, `nobody`,
  and `roles` in permissions.
- `rowfence push` stays refused (AZ610) after `rowfence remove` on a database that took migrations or a plain
  apply, until someone marks it with `rowfence push --development`. Removing the policy made the database one
  push would change. A database already marked stays marked.
- `rowfence fmt` keeps a file's line endings: a file with CRLF (a Windows checkout) is written back with CRLF.
  It was rewritten with LF.
- `rowfence apply --force` and the new `rowfence reapply --force` compute every inheritance table again. A
  plain apply keeps the tables whose definition didn't change, so after rows were written with the triggers
  off (a bulk load, a restore with `--disable-triggers`) and `authz.verify()` said false, nothing brought them
  back short of removing the policy.
- The preview (`rowfence diff`, the review's Access, `rowfence dev`'s access line) asks as every service and
  other principal too, named `service:7`. A change that reached only a service said "nobody gains or loses
  anything".
- Versions may be alphas: `0.1.0-alpha.1` (PyPI's `0.1.0a1`), published like a release candidate (npm's
  `next`, a GitHub pre-release, never `latest`). The command places a version's alphas before its candidates
  when it refuses to put an older version's work over a newer one's (AZ616).
- `rowfence.toml` is checked: a setting rowfence doesn't know, or one of the wrong type, is an error that
  names it (`tests = "db/tests/*.authz"`, not a list, ran no named test and passed). The policy, the tests
  and the lock file it names must be in its folder or below, also through links.
- The command refuses arguments it doesn't take and options it doesn't know or gets twice (exit 2), where it
  ignored them; an unknown command is said before connecting.
- `@rowfence/vitest` works with Vitest 4 and Vitest 5 (its peer dependency says so): its matchers'
  types merged only with Vitest 4's. They now return `void | Promise<void>`, whichever Vitest it is.
- A new version of rowfence needs a migration only when it makes something differently: `rowfence migrate
  --check` no longer fails after an upgrade that changes nothing. The lock file now records a hash of the
  steps every migration runs.
- `rowfence.psycopg.transaction()` signs in with parameters, `SELECT authz.act_as(%s, %s)`, as the
  generated Python client does, rather than values written into the statement.
- Whoever signs in is a row of their type. An id the user table doesn't have (a user deleted since) is
  nobody: `authz.uid()` is NULL, as it already was for a user failing the type's `where`, so a leftover
  `owner_id` no longer grants. The same for services and other principals.
- `authz.check_invariants()` (and so `rowfence test`) asks as every principal, not only as users: a
  service that breaks an invariant is reported, as `service:3`. `rowfence prove` already did.
- Both SDKs: a plain id is always a user's. `"service:3"` given as who a transaction acts for was read as
  service 3; it is now the user whose id that is, so an id from outside (a username, an identity provider's
  subject such as `oauth2:1234`) can't sign in as another principal type. `Principal.parse()` (Python) and
  `parsePrincipal()` (TypeScript) read back what `str()` and `describe()` write.

### Upgrading

- The next migration (`rowfence migrate`) computes every inheritance table again: the functions that fill and
  check them changed. Where it can, it builds them beside the ones in use, then swaps them in (two
  migrations).
- Every policy: the app role's line is `app role app_user`, and a policy must have one (AZ111). `role
  app_user` is refused with the line to write (`role` is the word for custom roles), as is each form below.
  The review of the pull request that rewrites them says whether the policy still grants the same.
- `everyone` is `anyone` now (signed in or not, the word shares and tests use). `anyone` and `nobody` are
  words of the language: a relation or permission named either is refused (AZ107), as is one named `roles`.
- Custom roles are written where they give a permission. `roles : user, team#member grant view, edit` becomes
  `roles : user, team#member`, and `view` and `edit` each write `roles` where a role holder joins:
  `can view = (viewer or roles or parent.view) and {not archived}`. `roles` under `not` is refused (AZ210).
- Where `and` meets `or`, parentheses say which comes first: `a or b and c` is refused (AZ102), with the
  parentheses to add.
- A permission the runtime asks for by name, declared where it never asks, is refused (AZ307):
  `impersonate` on a type other than the user type, `manage_keys` on a type that doesn't sign in,
  `break_glass` on a type with no relation shared with a user, `manage_roles` on a type whose roles no roles
  line counts. `roles : ... from org` needs `can manage_roles` on the org's type, and roles without `from`
  need it on some type.
- Inside a condition, `this.` names the row: a subquery that calls its own table `this` takes another alias.
- Both SDKs: where the app passed `"service:3"` to act as a service, pass `("service", 3)` (Python) or
  `["service", 3]` (TypeScript).
- With the setting `jwt_audience`, tokens must name that audience (`aud`): one that names none is now refused.
- A permissive policy of your own on a table with rules, for the app role, is now an error from `authz.lint()`
  and a warning when applying: drop it, and say what it allowed in the policy file.
- A script that ran `rowfence remove` then `rowfence push` on a database set up by migrations: push with
  `--development`, once.

- Python SDK: `rowfence.refusal(exc)` answers `None` for a "permission denied" that isn't a policy's (a table
  the app role was never granted): FastAPI answers it as a server error, no longer a 403. And
  `rowfence.act_as_args(None)` and `act_as_sql(None)` now mean nobody: call them with no argument for whoever
  the code acts for.
- TypeScript SDK: `refusal(e)` and `translate(e)` answer `null` for a "permission denied" that isn't a
  policy's (a table the app role was never granted): `route()` lets it through as a server error, no longer
  a 403.
- An app that signed in as a new user before inserting their row (a sign-up) now inserts the row first:
  until it is there, they are nobody.
- Applying refuses a search path with a schema that roles other than the owner may create in (AZ612). A
  database upgraded from Postgres 14 or older still lets everyone create in `public`:
  `REVOKE CREATE ON SCHEMA public FROM PUBLIC`, or apply with a search path without `public`.
- An app whose login is a superuser or the policy's owner, switching to the app role with `SET ROLE`, now
  gets an error from `authz.connection_check()`, and the SDKs refuse to start on it: log in as a role in the
  app role instead.
- A policy that includes a file outside its own folder (`include "../shared/roles.authz"`) is refused
  (AZ108): move the file into the policy's folder, or the policy up to the folder they share.

### Fixed

- `@rowfence/prisma`: a client not extended with `authz()` is refused inside the extended client's
  `$transaction` callback too. There it passed, since the callback ran inside the extended call, and its
  `findUnique` calls could be answered together, as the first caller.
- On Windows, an included file, or a file `rowfence.toml` names, whose link leads to another drive is refused as
  outside the folder. The command stopped with a Python traceback.
- A condition that calls a function of the app's by a quoted name (`{app."banned"(this.id)}`,
  `{"app".banned(this.id)}`) or through an operator the app made (`{this.id =!= authz.uid()}`) reads with the
  policy's rights in row-level security too, as it does in the views and `authz.can`. Such a call was taken
  for a built-in on the row's columns, so row-level security ran it as the app role, under row-level
  security: the app could update a row `authz.can` refused.
- `authz.verify()`, the backfill (`apply`, `apply --force`, `reapply --force`) and the migration that builds an
  inheritance table beside the one in use work through the rows 10,000 at a time. They computed the whole
  table in one recursion, which Postgres keeps in memory whatever `work_mem` says: with a million folders (22
  million rows) `authz.verify()` took more than 2.4 GB, was killed by the kernel on a 6 GB machine, and
  Postgres restarted under the app. It now passes there in about two and a half minutes.
- The command connects with the connection string Neon's dashboard gives, `channel_binding=require` included:
  over TLS it binds the password exchange to the server's certificate when the server offers it, as libpq
  does (`channel_binding=prefer`, the default; `PGCHANNELBINDING`). It refused such a string.
- An owner that isn't a superuser only administers the app role it made (PostgreSQL 16 on), and `rowfence
  test`, `sql --as`, `explain-rule`, `plans` and `bench` failed with "permission denied to set role". They say
  what to run, `GRANT app_user TO app_owner` (AZ618), and a test that expects `refused` no longer passes on
  that error.
- The change feed (`changes()` in `@rowfence/pg`) tells its subscribers once when it begins to listen: a change
  made while its connection was being opened (a second, to a database far away) was notified to nobody, and
  a page that had just loaded stayed as it was.
- `authz.lint()` reports JIT for the app role once, as `performance`. It gave two lines, with two tests.
- `rowfence bench` times each statement alone, and its first line says what a statement that does nothing
  takes from where it runs. Far from the database every line read three or four round trips.
- `databasePerWorker` (`@rowfence/vitest`) says what holds the test database when it can't be copied, and what
  to use where the service keeps a connection of its own.
- `rowfence review` no longer says a permission "allows more than before", with an example, when it changed
  only in a condition it can't read (a subquery, a function): rewriting a subquery's `id` as `this.id` gave
  five such flags across two real changes. It says it can't compare them, names the conditions, and Meaning
  counts them. A project with no lock file (it applies its policy, no migrations) is told so in Deploy: every
  change read as the whole policy, locking every table and rebuilding every tree.
- Inheritance round a loop of several types compiles when one of them has a starting point: an org's owner
  edits its domains, their addresses, the settings that use them, and the orgs those settings belong to
  (`can edit = org.edit` on a domain, with nothing of its own). Each permission of the loop needed a starting
  point of its own (AZ303). A loop with none anywhere is still refused: it grants nothing.
- `rowfence init` on real apps' schemas (tried on nine: Cal.com, Documenso, GitLab, Mastodon, Chatwoot,
  Plausible, Mattermost, Lemmy, Pagila): every draft now compiles and applies (four did not). It takes
  `users` as the user table before `accounts` (Chatwoot's tenants), and no longer `members` (GitLab's link
  table); a foreign key declared twice is one relation (it made two, and a second `after` rule, AZ109); a
  loop of foreign keys with no owner anywhere is not inherited round, and its types say so; a membership
  table with an id of its own (what Rails, Ecto, Django and Prisma make) is a link when the pair is unique or
  it holds only a role and timestamps besides, so what it links is no longer everyone's; and a view names
  each parent once (`author or project.view`), so the draft is not the shape `rowfence lint` warns about.
- A typo in a relation's only use (`can edit = ownr`) names the typo's line (AZ203), not the relation as
  unused on its own line (AZ208). A character that doesn't print is shown escaped in AZ102 (`'\x01'`).
- `rowfence apply` (and a whole-policy migration run by the command) warns before it starts when the policy
  makes more objects than Postgres's lock table holds, and names the `max_locks_per_transaction` to set: GitLab's
  thousand tables stopped after two and a half minutes with "out of shared memory". The limits page says so,
  that reads through the rules run on one CPU, and its speed numbers come from `benchmark.sql` as it is now
  (a big move: 290 ms where it said 920); `benchmark.sql` measures nested teams and the audit trail's cost too.
  `regress.sh` fails when the big move gets twice as slow (it let it get four times slower). The editor
  README's Helix setup gives highlighting too (`[[grammar]]`, where the queries go).
- Behind a pooler: the operations page has a section on it (transaction mode works, statement mode can't,
  what may not outlive a transaction, migrations through it). The change feed (`changes()`) heard nothing
  through a pooler in transaction mode and said it was connected: it needs its own connection to Postgres, and
  the Next.js page's feed takes `ROWFENCE_FEED_URL` for it. Behind a pooler that keeps no prepared statements
  (Supavisor, `max_prepared_statements = 0`), asyncpg and psycopg need a setting each, now on the Python page.
  The conformance suites run through PgBouncer with `POOLER=pgbouncer`, every night.
- A condition that reads more than its row (a subquery, or a function) reads with the policy's rights
  wherever it is checked. In its own table's rules it ran as the app role and saw only the rows the user may
  see, so one permission gave two answers: in the messenger, a group's creator who had left kept reading the
  chat, though `authz.can` said no. The rules call a function rowfence makes for it, which runs as the
  owner; a condition on the row's own columns is still written in place. The docs no longer say a
  condition in a rule sees only what the user may, and applying no longer warns about it.
- A write whose rule inherits through a relation kept in shares (`shortcut : doc shared`, then
  `shortcut.view`) works: every such write failed with "permission denied for table shares", the owner's
  too. A write rule reads a link table it inherits through with the policy's rights too.
- A policy without an app role line applied its rules to PUBLIC and let every role in the database call
  `authz.act_as`, so any role could sign in as anyone. It is refused now (AZ111).
- The unnamed `test` section checks as the principal each line names: `service 1 can ...` checked user 1,
  and `bot 1` compiled with no `bot` type. It takes `anyone` too. A test that passed may fail now: it was
  checking someone else.
- `authz.lint()` no longer asks for an `after` rule on a row's own key for a relation from it to its own type
  (`self : user = id`): that is the row itself, not a parent it moves under.
- Studio's grid works on a table with a masked column (it failed with "permission denied for table"): it reads
  the table through its masked view. Viewed as someone, a masked column they may not read is shown as they
  get it: empty, and marked `masked`.
- Flyway runs rowfence's migrations: each comes with its script config file (`.sql.conf`,
  `placeholderReplacement=false`). The SQL holds `${`, which Flyway took for a placeholder and refused, the
  first migration included. For migrations written before: add the same file beside each.
- `rowfence why` names a change it couldn't try (a link table with another column that must be given) instead
  of answering that no change grants the permission. `rowfence indexes` no longer takes an index that starts
  with an expression, or one that isn't valid, as serving a lookup by its later columns.
- `authz.login_jwt` refuses a token that has no `aud` claim once the setting `jwt_audience` names an audience.
  It refused a token for another audience and accepted one for none, so a token the identity provider signed
  for another service, without an audience, signed in.
- `authz.explain_rule` answers for an update or a delete on a table with a masked column. It failed with
  `permission denied for table`, so the generated clients' `expect` and the SDKs raised the driver's error
  there instead of `NotFound` or `Refused`. It judges the row as the user may read it: a masked column is NULL
  unless its rule holds.
- Python SDK: `import rowfence.sqlalchemy` (and so `rowfence.fastapi`) works without `greenlet`. With
  SQLAlchemy 2.1, which installs it only when asked, the import failed after `pip install
  "rowfence[sqlalchemy]"`. The `fastapi` extra now asks for `sqlalchemy[asyncio]`.
- `rowfence init`'s line for FastAPI, and the SDK's README, no longer read `request.state`: that was a 500
  when the app's own middleware was added before `Rowfence(...)`. The README says when `request.state` is
  filled.
- The docs: the getting-started guide's `PATH` line named a folder that isn't there, and its policy is now
  laid out as `rowfence fmt` writes it; the reference says how shares are made (`shared by`, `shared if`,
  caveats and their arguments), how custom roles are created and shared (`manage_roles`, `role:<id>`), and
  where a change feed reader starts; what `authz.sync_members` writes; and no longer names
  `authz.test_policy`, which doesn't exist.
- The TypeScript SDK:
  - `permsOf` works over Drizzle (the ids went out as a list of parameters, and it failed every time).
  - `@rowfence/pg`: a connection that drops while a transaction holds it fails that transaction; it stopped
    the Node process. `changes(pool)` listens again after its connection drops and tells its subscribers
    once; it stayed silent for good.
  - A transaction given who it acts for (`transaction(fn, who)`, `begin(fn, who)`) runs the sign-in hooks
    too, so `@rowfence/next` keeps it out of caches like any other.
  - An update or delete that matched nothing though the user may change the row (a `where` with more than the
    key) is `NotFound`, not a `Refused` whose reason says yes. The Prisma extension and every `expect`.
  - A table named without its schema (a Prisma model without `@@schema`) is found on the search path when the
    SDK asks why a write was refused; it was a 500.
  - `inIds` takes a key with a length or a precision (`varchar(30)`); a key of one column given as an array
    is that value; a refused upsert names the update rule; `sqlstate()` no longer answers Node's `EPIPE`.
  - `authzRoutes`: the POST routes take `application/json` only, and `POST perms` takes a long list of ids
    (`usePerms` uses it past about 1500 characters of ids).
  - `@rowfence/react`: `<AuthzProvider user={id}>` makes every hook ask again when the signed-in user
    changes; the hooks also ask again when the event stream opens again after a gap.
  - `@rowfence/prisma` asks for Prisma 7 (its peer range said 6); the packages are published with a README
    and the licence.
- The generated clients (`rowfence client py`, `ts`): `expect` answers `NotFound` when the rule allows the
  write and the statement matched nothing for another reason (a `WHERE` with more than the key). It raised
  `Refused` with a reason that said yes.
- `@rowfence/prisma`: a Prisma client that wasn't extended with `authz()` is refused whenever it is used. Before,
  it was only refused until some client was extended; after that, concurrent `findUnique` calls on it were
  answered with one query, signed in as the first caller, so a caller could be given a row they may not see.
  Use the client `$extends(authz())` returns, and only that one.
- The Python SDK:
  - `None` given to `transaction(conn, None)` (psycopg, asyncpg) and to `act_as_sql(None)` is nobody, also
    inside `acting_as(...)`. It signed in as whoever the code acted for.
  - `Rowfence(app, engine)` checks the connection at start-up whether or not the app has a `lifespan`. With
    one, the check never ran.
  - `why_stale()` asks about each row of the flush that failed and answers for the one refused. It answered
    for the last row written, which the user might well be allowed to change.
  - `rowfence.psycopg.transaction()` and `rowfence.asyncpg.transaction()` inside a transaction already open
    (a savepoint) sign back in as whoever the transaction acted for before the block, or nobody. The block's
    user stayed signed in until the outer transaction ended.
  - With SQLAlchemy on psycopg, a user id that holds a `%` reaches `authz.act_as` as it is. `%s` in it became
    `$1`, and another `%` failed every transaction.
  - A table named without its schema (a model that names none) is found on the search path when the SDK asks
    why a write was refused. It raised "the policy has no rules for table notes", a 500 in FastAPI.
  - An UPDATE or DELETE that matched nothing though the user may change the row (a `WHERE` with more than
    the key) is `NotFound`, not a `Refused` whose reason says yes.
  - A composite key is written as Postgres writes a row, each field quoted.
  - `user(request)` may raise an `HTTPException` (it was a 500); a query nobody signed in for raises
    `NotSignedIn` from FastAPI's handler.
  - `rowfence.psycopg.expect()` takes the cursor too (its `rowcount`); `aexpect()` is the same on an async
    connection.
  - `assert_refused` and `assert_not_found` take async functions (awaited in an async test), and
    `assert_refused(fn, command=...)` fails when the refusal names no command.
  - The wheel and the sdist hold the licence.
- Editors: the Tree-sitter grammar (Zed, Helix, Neovim) reads a relation named like a word that starts a line
  (`role`, `type`, `test`, `scope`, `principal`, `include`, `caveat`, `rules`, `invariants`, `roles`), as the
  compiler does; it showed a parse error. On Windows the VS Code extension starts a `rowfence` installed with
  npm (a `.cmd`).
- A view or a function of the app's built on a masked view no longer stops `rowfence apply`, `push` or a
  migration: the masked view is replaced in place, and so are the views a migration changes (it dropped and
  made them again, which Postgres refuses while something depends on them). What can't be done in place (the
  masked view taken out of the policy, a column of the table renamed) is refused with what is built on it
  named (AZ617).
- The language server checks a file the policy includes as the part of the policy it is: opened by itself it
  showed "declare the user type" on its first line. A mistake that is fixed is cleared from the file it was
  on. Open files are found whatever way the editor spells their address (on Windows, VS Code's
  `file:///c%3A/...`): an unsaved include or policy was read from disk. A test file's outline is its tests;
  `is not null` in a condition is no longer called a deny.
- `rowfence why` says every other permission a way would give on the object (`share editor` for a view
  question also gives edit), and whom a column that changes hands takes it from; the way that gives the
  least comes first. Studio shows the same.
- `rowfence plans` names a scan that reads a big table and keeps little, which is what a missing index
  gives: it counted the rows kept, so it never said.
- `rowfence graph`: two things no longer share a node (`team` + `member_view` and `team_member` + `view`),
  and a relation shared with every signed-in service is drawn to that type. The ids changed: a node is
  `type__name`.
- The generated clients' `expect` reads what a driver hands back (a cursor's `rowcount`, pg's `rowCount`):
  given the cursor or the result itself, it took a refused update for a changed row.
- The reference no longer names `SELECT authz.client('py')`, a function that was never there.
- `rowfence init` drafts a policy that compiles and applies for schemas it tripped on: Prisma's names
  (`"User"`, `"authorId"`: a column in a `{condition}` gets its quotes), a column named like an SQL word or a
  word of the language, a link table or column named like a permission (`post_views`, `view_id`), a link
  through a unique column that isn't the key. What it can't write (a name with a space, a dash, a letter
  outside ASCII) is left out with a line saying why; the migration tool's own table is left out; a user table
  whose key it can't use is an error that says so.
- `rowfence init` finds Prisma's migrations folder when the schema is not in `prisma/` (`package.json`'s
  `prisma.schema`, `prisma.config.ts`).
- AZ613 names the condition that failed when it holds `authz.uid()`: it named another condition of the same
  statement.
- `rowfence fmt` leaves tests saying what they said: a `{` in a string of a test's statement made every line
  after it a continuation (the file no longer compiled), and the spaces and `--` inside a test's name were
  changed. The check that formatting changes nothing now covers the tests.
- `rowfence fmt` formats a policy with an `include` (it said "can't find" the file), and one with a relation
  named `role`, `type`, `scope` or `test`. A policy with a mistake gets the mistake's message.
- Studio serves its own three files and nothing else: on Windows a request path with backslashes named any
  file on the disk, and static files need no token. (A browser can't send such a path; another program on
  the machine could.)
- The named test Studio writes ("Make a test") runs: it copied the person's row with its key, which collided
  with the row it was copied from. Names are quoted; a row whose key has several columns is named, not copied.
- Studio loads Mermaid in one version, checked against its hash before it runs, in the page that holds the
  token. The graph is drawn again each time its tab is opened (under `rowfence dev` the policy changes). A
  token that isn't ASCII is a wrong token, not a traceback. The page can't be framed.
- The language server no longer exits when `rowfence.toml` names the database by a variable the editor's
  environment doesn't have (`database = "env:DATABASE_URL"`): it completes without table and column names.
- A database URL's options are read: `?sslmode=require` was dropped (the command connected without TLS),
  and `?host=`, `?port=` went to the default server. The command now does TLS: when the server has it
  (`prefer`, the default), or else refuses (`require`), with the certificate checked for `verify-ca` and
  `verify-full` (`sslrootcert`, `PGSSLMODE`, `PGSSLROOTCERT`). What it can't do (client certificates, channel
  binding) is an error. A managed Postgres that only takes TLS can be reached.
- Through the MCP server, a tool's argument can no longer be one of the command's options: `push` with
  `--development` as the policy marked a database as a development database, which is a person's to do.
  A line of JSON nested too deep no longer ends the server.
- `rowfence sql` shows an array of two dimensions as Postgres writes it (a traceback). A password that SCRAM
  prepares (a soft hyphen, compatibility characters) signs in. A connection that the server never answers
  times out. The command's `application_name` is `rowfence`. A connection string it can't read says what to write.
- `--db` is read wherever it is on the line. After the command it was ignored, or taken for the policy file:
  `rowfence remove --yes --db X` removed the policy of the default database, and the reference's own
  `rowfence review --base main --markdown --db "$URL"` failed.
- `rowfence client` no longer empties the client files `rowfence.toml` names when the policy has a mistake.
- A policy, test or included file that isn't UTF-8 is said (exit 2), where the command gave a traceback;
  `rowfence dev` says it and keeps watching.
- A server that ends the connection, or goes away: "lost the database" with the server's own message, exit
  2, where the command gave two tracebacks. Ctrl-C cancels the statement on the server.
- Two `rowfence apply` (or push, remove) at once: the second waits for the first, where one stopped with
  "deadlock detected".
- On a database with no policy, `rowfence who`, `can`, `sql` and the like say "no policy is applied" as the
  other commands do. A mistake in a test file always names the file. An expression nested too deep is a
  message, not a traceback.
- `rowfence review` flags widenings it called safe ("Risk: nothing flagged"): a `select` rule that allows
  more, a rule that is new on a table that had rules, a permission or rule that allows more through a
  relation that changed (another column, a `where` taken off a link table), and a type's `where` taken off.
  Each comes with an example, on its policy line.
- `rowfence review` no longer says "Meaning unchanged" for a change of text inside quotes
  (`{status = 'a  b'}`), nor for a widening behind a long run of conditions: the worlds it compares in now
  include the ones where every condition holds. When Risk finds an example, Meaning lists the change.
- `rowfence review` on a policy with a mistake says what `rowfence check` says (it gave a traceback), and
  names the base when the mistake is there. With a `--base` git doesn't know (a typo, a shallow checkout) it
  stops with exit 2, where it compared with an empty policy and reviewed everything as new.
- The review's comment lists the checks that flipped or were removed, and the flags, also when the meaning
  is unchanged; the text output lists them too. A flag in an included file is annotated on that file. The
  GitLab template finds its note on a merge request with more than 100 notes.
- A group that fails its type's `where` (`type team = app.teams where {not disbanded}`) no longer passes its
  members on to the group that holds it. Its members held nothing through it directly, but still everything
  the team above it gave: they could read and write rows the policy doesn't give them. `authz.can`, the
  rules and `authz.who` all follow.
- `authz.who` no longer lists an id that is no row of the user table (one a column, a link table or a share
  names with no foreign key), for a permission open to `anyone`.
- Applying a changed policy (or a migration) no longer deletes shares to every signed-in user (`user:*`, or
  any principal type's `*`): the sweep of shares on rows that no longer exist took `*` for a missing row.
  `TRUNCATE` of a type's table keeps them too. Shares deleted that way are in `authz.audit` (`unshare`,
  reason "applying the policy: the row was deleted"): share them again.
- In a policy test, an `allowed` or `refused` statement that starts with `WITH` or a comment is judged as the
  write it is: one that changes no row is refused (it passed as allowed). `sees N {...;}` and
  `given x = {...;}` take a final `;`.
- `rowfence test --coverage` counts the branches of a permission with a deny inside inheritance
  (`(owner or parent.view) and not hidden`): `owner` and `parent.view`, where it counted one branch and never
  reported them. `signed_in`, `anyone` and `nobody` are shown as the policy writes them.
- Applying again works when a view or a function of the app calls an `authz.*` function (`authz.can` in a
  view): the function is replaced in place, where Postgres refused to drop it. One the policy no longer
  makes with those arguments is refused, naming what uses it (AZ614).
- An older rowfence command no longer undoes a newer version's work: `apply`, `push` and `migrate` stop when
  the database or the lock file was last written by a newer version (AZ616), where they put the older
  functions back and wrote the step back as if it were an upgrade. `--downgrade` goes back on purpose.
- A migration that adds or removes an inheritance tree no longer deletes and rewrites the lock rows tree
  writes take. A write that waited on one went on without the lock, and two moves waiting together could
  make a loop.
- A migration run outside a transaction (`psql -f` without `-1`: each statement commits on its own) refuses
  before it changes anything (AZ615). It used to stop half way, and a change to inheritance left the database
  with the old trees dropped. Migrations written before this have no such check: run them with `psql -1`.
- `rowfence prove` checks the policy first, as `rowfence check` does: a policy it refuses gets its message, line
  and code, not a traceback. A number option that isn't one (`--worlds`, `--limit`, `--port`, `--people`,
  `--rounds`, `--studio-port`) is a usage error.
- `rowfence prove` and the review's refactor check no longer report what can't happen: `signed_in`,
  `anyone` and `nobody` mean the same on every row, a polymorphic column links a row to one object, and a
  rule's rows are those that pass the type's `where`.
- `authz.create_role()` stores the owner's id as every id is stored (`'01'` is `1`).
- Shares written straight into `authz.shares` (a seed script, an import) get canonical ids whatever the
  policy's keys: `'007'` is stored as `'7'`, an uppercase uuid in lowercase. Only policies with a composite
  key did this, so such a share on `'007'` granted access to row 7, stayed when row 7 was deleted, and gave
  access to the next row 7. Applying makes the ids already stored canonical (keeping one of two spellings of
  the same share).
- The partitions of a governed table, and tables that inherit from it, get row-level security when the
  policy is applied (on, with no rules of their own), so the app role reads and writes them only through
  the table. Read directly, a partition showed every row, whatever the policy said. `authz.lint()` reports
  a partition made since the last apply that the app role may use, or TRUNCATE.
- A custom role gives a permission where the permission writes `roles`, so the conditions and denies joined
  to it with `and` hold for role holders too. `grant` added the role outside them: with `can view = (viewer
  or parent.view) and {not archived}`, or `owner and {not archived}`, a role holder saw archived rows that no
  one else could.
- On Windows, a database address that is a Unix socket (`host=/var/run/postgresql`, the default when
  `PGHOST` isn't set) is refused with a message saying to use `host=localhost`, instead of a Python error.
- A build from source (a version ending in `-dev`) records a hash of its compiler, so `rowfence apply` no
  longer says `unchanged` for a database an earlier build applied.
- `authz.explain()`, the refusals and `authz.explain_rule()` explain only what the signed-in user can see. A
  user holding any permission on an object they couldn't see (such as `break_glass`) got it explained, with
  the hidden folders above it and their conditions' results; and the walk up from a visible object went on
  into hidden ones. A hidden object now reads as a missing one, and the walk stops at one: `parent is a
  folder you can't see`.
- Requests signing in with the same API key no longer wait for each other, and `authz.login_key()` works in a
  read-only transaction (a replica). Each login updated the key's `last_used_at`, locking its row until the
  transaction ended. It is now kept to the minute, never waiting, and not by read-only transactions.
- The audit trail's trigger no longer lets a delete through when a session sets `authz_int.trim_before`:
  the table's owner could empty the trail that way, without DDL and without a record. `authz.trim_audit()`
  disables the trigger for its own delete instead.
- `authz.share()` and `authz.create_link()` answer a caller who may share nothing on an object as for a missing
  one (`you cannot share file 12`, AZ705), before they look at the subject or the relation. They said `there is
  no user ...` or `the policy does not allow sharing ...` for a hidden object, so anyone could tell it exists.
- `authz.lint()` reports a governed table's primary key the app role may choose (`info`): an insert with a
  hidden row's id fails, which tells that it exists. The threat model now names primary and foreign keys
  beside unique constraints, and what to do about them.
- A `{condition}` Postgres refuses when the policy is applied (a column that isn't there, a syntax error, a
  function it can't find) is named with its line: `policy line 63: the condition {...} doesn't run: column
  "nme" does not exist [AZ613]`, with Postgres's hint. It gave Postgres's message alone. A condition
  containing a dollar-quote tag (`'$f$'`) is refused when compiled (AZ110): it ended the generated function.
- `authz.list()` refuses a page cursor that isn't an id of the type, or a negative page size, with SQLSTATE
  22023 and AZ710 (the SDKs answer 400). It failed with Postgres's own error and the generated query.
- Signing in (`authz.act_as`, `login_jwt`, `view_as`) stores the id as every other id is stored (`' 05'` is
  `5`, an uppercase uuid in lowercase), so the audit trail and `created_by` name the user as shares do. They
  recorded the id as the backend spelled it.
- `authz.explain(type, id, perm, user)` explains without the inspect check only the signed-in user's own
  access. A service (or another principal) whose id was a user's got that user's access explained on any
  object. Migrate and apply.
- Row-level security turned off on a table with rules is noticed: `rowfence apply` applies again (it said
  `unchanged`), `authz.lint()` reports an error (it said `info`, as for a table without rules), and
  `authz.connection_check()` an error. `rowfence apply` also applies again when a trigger it made on an app
  table is dropped or disabled.
- `authz.connection_check()` reports an error for a login that is a superuser or the policy's owner and
  switched to the app role with `SET ROLE`: `RESET ROLE` leaves row-level security, and who is signed in is
  believed without a signature. It looked only at the role after `SET ROLE`.
- An `include` stays in the policy's folder: a name with `..` out of it, an absolute path, a drive or a
  backslash is refused (AZ108), and a link leading out of the folder isn't followed. An include could read
  any file, and the error quoted its first line: in CI, a pull request could print the runner's environment
  in the review's log.
- Policy files are read as UTF-8 on every platform, and a byte-order mark at the start is ignored. On
  Windows, `authzc.py` read them in the locale's encoding and wrote its output in it too.
- An SQL comment (`--`) inside a `{condition}` ends at the end of its line. The lines of a condition were
  joined into one, so the comment swallowed the lines after it (and a `'` in it, as in `don't`, opened a
  string). `--` inside double quotes (`include "a--b.authz"`, a test's name) is no longer a comment.
- `or`, `and`, `not`, `if`, `where` and `grant` are refused as names (AZ107). A relation named `where` was
  joined to the line above it, with a confusing message.
- `update before : ...` is refused (AZ105): it was a plain `update` rule, checked after the change too. A
  column named `before` or `after` says when it is checked: `update after after : edit`.
- In the unnamed `test` section, a quoted id is unescaped (`'it''s'` is `it's`), as in named tests.
- `authz.can`, `authz.list` and `authz.perms` run a condition that names a function, operator or type without
  its schema (`{is_open(status)}`, an extension's operator in `public`), as the rules do: on the search path
  in effect when the policy was applied. They failed with `function ... does not exist`. Migrate and apply.
- `rules` for a table two types map to are refused (AZ401): they used the first type's permissions, and a
  rule naming the second's said the first had no such permission.
- A scope can't name a permission the compiler made (`folder.view__base`, AZ107).
- A deny whose permission has a deny of its own is refused with that reason (AZ306), not with one saying it
  doesn't inherit.
- With SQLAlchemy, an ORM update or delete of a class mapped to several tables (joined inheritance) no
  longer fails in rowfence's flush hook: it remembers the class's own table.
- Applying takes back every privilege on `authz`, `authz_gen`, `authz_int` and what is in them that the
  policy doesn't give, and says how many it took back. When the tables' owner had default privileges for
  the app role (`ALTER DEFAULT PRIVILEGES GRANT ... TO app_user`, a common migration setup), the app role got
  rowfence's own tables and administrators' functions: it could delete shares, read the session key, empty
  the audit trail with `authz.trim_audit()`, and make the next apply grant it any table. `authz.lint()`
  reports a privilege granted there since the last apply.
- The functions that evaluate the policy's own SQL run as the owner on the search path of the session that
  applied it. Applying now refuses a schema on that path that roles other than the owner may create in
  (AZ612): a function made there could take the place of a built-in one, and run as the owner. `"$user"` is
  no longer kept in that path when no such schema exists, and `authz.lint()` reports a schema opened to others
  since the last apply.
- The VS Code extension (`.vsix`) carries `vscode-languageclient`, which it starts the language server with:
  it was left out, so errors, hover and completion didn't start.
- Studio's graph: clicking a type or a permission no longer shows the word "null" for the parts it doesn't
  have.
- The language server on Windows reads the files VS Code names (`file:///c%3A/...`): it took them for
  `\c:\...`, a path that doesn't exist.
- `npx rowfence ...` no longer exits 0 when the command is stopped by SIGTERM, Ctrl-C or a hang-up: the
  launcher ends by the same signal, so a script or a CI step doesn't go on as if the command had finished.
  From a terminal it no longer sends Ctrl-C to the command a second time.
- The `rowfence` npm package and the platform packages carry the licence, and each platform package the
  licences of the libraries built into its Python (OpenSSL, SQLite, zlib and others), in `python/licenses/`.
- The Python inside each `@rowfence/cli-*` package is checked against its release's SHA-256 when the package
  is built, and what the release workflow runs is pinned (actions by commit, uv and vsce by version). A
  release that stopped half-way is finished by running it again; a patch to an older line is published as
  `release-X.Y`, not `latest`.
- The review for CI (`review-ci/github`) names `actions/setup-python` by commit.
- The command's image: the documented command has `-u "$(id -u):$(id -g)"`, so the migration and the lock
  file it writes are yours, not root's.
- The playground: two columns with one name each show their own value under "Ask as someone" (both showed
  the second's); a policy nested too deep says so (the page went on showing the last policy as compiling);
  an id with a colon is taken whole; a link that holds something else than a policy opens an example.

## 0.1.0 (release candidate)

`0.1.0-rc.1` was tagged on 2026-09-29 and never published: no package, image or release exists for it.

The first release: the policy language and its compiler, the `rowfence` command, the Python and TypeScript
SDKs, the review for pull requests (GitHub and GitLab), and the editor extensions (VS Code, Zed).
