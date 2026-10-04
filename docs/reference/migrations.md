# Deploying a policy: migrations

The compiler runs in the `rowfence` command, never in the database. A policy change is a
migration, written for the tool in `rowfence.toml`, reviewed and deployed with the app's
other migrations. The database needs nothing installed first: `plpgsql`, which every Postgres has, is
enough. `core/Dockerfile` builds a Postgres for development and tests: the stock image, with the command in it.

    rowfence migrate                          # the next migration, and db/policy.lock (no database needed)
    rowfence migrate --check                  # in CI: exit 1 if the policy has a change no migration has
    rowfence push                             # a development database, with the same migration
    rowfence diff                             # who gains and loses what; changes nothing
    rowfence test                             # the tests and invariants

| tool | what `rowfence migrate` writes |
|---|---|
| `alembic` | a revision after the current head, `<rev>_authz_<name>.py`, with its SQL beside it (`.sql`) |
| `prisma` | `prisma/migrations/<time>_authz_<name>/migration.sql` |
| `drizzle` | `drizzle/<n>_authz_<name>.sql` with statement breakpoints, its journal entry and snapshot |
| `sql` | `<n>_authz_<name>.sql` after numbered files (`0005_...`), else `<time>_authz_<name>.sql` |
| `goose`, `dbmate` | the same SQL, with each tool's markers |
| `flyway` | `V<time>__authz_<name>.sql`, and its script config file beside it (`.sql.conf`, `placeholderReplacement=false`: the SQL holds `${`, which Flyway would take for a placeholder) |

- **The lock file** (`db/policy.lock`, next to the policy; commit it) lists the policy's lines, then
  each function, view, trigger, policy and table the migrations made so far, with a hash of its SQL.
  So the next migration holds only what changed: a new permission is a new view and a few `CREATE OR
  REPLACE` of the functions that list permissions; unchanged inheritance tables are never touched. A view
  that changes is replaced in place (emptied first, then defined again), so what the app built on a masked
  view stays.
  The same policy always gives the same bytes. Lines that only moved need no migration.
- **Each migration checks where it starts**: the lock's hash is recorded in `authz.policy_versions`, and
  a migration applied out of order, twice, or to a database changed since with `push` or `apply` stops
  with a message naming both.
- **Each migration is one transaction**, your tool's. Plain SQL files run with
  `psql -1 -v ON_ERROR_STOP=1 -f <file>`. Run a statement at a time (`psql -f` alone), a migration refuses
  before it changes anything (`AZ615`).
- **Each migration starts with what changed**, as comments (`-- + type file: can comment = folder.view`).
  `migrate` also marks the lock and its migrations `linguist-generated` in `.gitattributes`, so reviews
  show them collapsed.
- **Inheritance that changes is built beside, then swapped in**: two migrations. The first fills the new
  inheritance table while the app runs (it only reads the app's tables); the second, a short
  transaction, swaps it in and does again what the app changed in between (rows written since the first
  one's snapshot, and the links the change feed records). A tree of several types, one whose conditions
  read other tables, one that takes links from shares, or one whose link tables the policy in force
  doesn't watch yet is rebuilt in one migration, under lock. `--one-phase` asks for one migration.
- **The first migration** is the whole policy, which also applies over a database that already has
  one (applied with `rowfence apply`).
- **Upgrading rowfence** is the next migration when the new version makes something differently:
  `rowfence migrate --check` says so, and `rowfence migrate` writes it. A new version that makes the same
  needs no migration. The other way round is refused: a command older than the version that last wrote the
  lock file or the database stops (`AZ616`), unless told `--downgrade`.
- **Development**: `rowfence push` (and `rowfence dev`, on every save) runs the migration from the policy
  in force to this one, directly; `rowfence apply` applies the whole policy again. Neither is for
  production, which takes migrations. Push only changes a development database: the first push to a
  database that never had a policy marks it as one; mark one your migrations set up with
  `rowfence push --development`, once. A database with a policy and no mark is refused (`AZ610`), and stays
  refused after `rowfence remove`: taking the policy out doesn't make a database a development one.

The version (semantic versioning; 1.0 will freeze the public surface) is the compiler's, in
`core/authzlib/__init__.py`; every package carries the same one (`packaging/version.py` sets them).

- **Who may apply**: whoever may change the tables' policies and triggers, which is their owner (or a
  superuser). The `{...}` conditions are SQL that runs with the rights of whoever applies the policy,
  so applying is as powerful as being that role.
- **Every applied policy is kept** in `authz.policy_versions`, with the rowfence version that applied
  it and the lock's hash (not readable by the app role).
- **Backups**: everything is an ordinary table, view, function or policy, so `pg_dump` keeps it all:
  shares, audit trail, change feed, policy history, and what the policy made.
- **Removing**: `rowfence remove --yes` drops everything the policy made and gives back the
  table-wide SELECT that masks replaced; shares and history stay, and row-level security stays on
  (with a warning), so nothing becomes readable by accident.
- **Nothing needs a superuser**: later grants on masked columns are reported by `authz.lint()`, not
  refused.
