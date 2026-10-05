# Speed and limits

## Speed

`core/bench/benchmark_results.txt` (`benchmark.sql`): 200,000 files, 10,000 folders, 2,000 users, nested
teams, 500 linked folders; the dev laptop, JIT off:

| median | ms |
|---|---|
| open one file, prepared statement | 1.1 |
| open a folder (20 files), prepared statement | 1.2 |
| `authz.can('file', id, 'edit')` | 0.3 |
| list every visible file (11k to 53k of 200k) | 32 |
| apply the policy, backfilling 10,000 folders | 940 |
| move a folder holding 3,441 subfolders (inside the tree) | 290 |

The scale benchmark (`core/bench/scale.sh --large`: a million files, 50,000 folders, writes arriving while 400
reads a second are served) moves the folder with the most below it, about 19,000 folders, into another root in
0.56 to 0.62 s; reads through the rules have a p95 of 3.2 ms beside the writes (`core/bench/README.md`).

At twenty times that (`scale.sh --full`: 20 million files, a million folders, 40,000 users; 22 and 15 million
rows of inheritance in a 6 GB database; the same laptop, 8 GB of shared buffers) the same workload has reads at
a p95 of 4.3 to 4.6 ms and tree writes at 28 to 38 ms. The folder with the most below it, 54,000, moves in 2 to
3.7 s. Applying takes three minutes there (the backfill), and `authz.verify()` two and a half.

**Turn JIT off for the app role** (`ALTER ROLE app_user SET jit = off`): with JIT on,
Postgres spends about a third of a second compiling each large read through RLS (the list
above takes 290 ms instead of 32). The audit trail and change feed add about 15 µs per changed row
(10,000 owner changes: 292 ms instead of 137 ms).

## Limits

- **One database.** Everything lives next to the data, so it scales with that
  Postgres. Across shards, run the same policy in each shard and keep an object's
  whole tree (and its groups) on one shard; cross-shard inheritance isn't supported.
- **Nested groups are expanded per query**, walking up from the user's own groups: with 20,000
  teams in chains ten deep, opening a folder given to the top of one takes 1.7 ms (1.5 ms with chains
  one deep) and `authz.can` 0.2 ms (`benchmark.sql`). A stored closure would only pay off for much
  deeper or wider nesting, and couldn't honour expiring shares.
- **A read costs what its reader holds.** A rule looks the object's ancestors up among the folders where the
  reader's permission starts (the ones they own, are shared, or reach through a team), and that set is worked
  out for each query: about a millisecond per thousand. With a million folders and everything in memory,
  opening a folder took 4.5 to 5 ms on the server for a member who held 4,000 folders directly, against the
  1.2 ms above for one who holds a hundred. Access through one membership of something big costs nothing of
  the kind: an org's admin, who reaches every folder, reads faster than any member in the benchmark.
- **Reads through the rules run on one CPU.** rowstile's functions aren't marked parallel safe: a session's
  signature is bound to its backend, which a parallel worker isn't. So Postgres never splits a read through
  the rules between workers: counting 200,000 files took 28 ms through them, 5.5 ms as the owner with two
  workers.
- **A big policy needs room in Postgres's lock table.** Applying it whole (or a first migration) takes a lock
  on each object it makes, in one transaction, and the table holds `max_locks_per_transaction` for each
  connection: 6,400 by default. GitLab's thousand tables, drafted by `rowstile init`, make about 45,000; applying
  stopped after two and a half minutes with "out of shared memory", and took 163 s with
  `max_locks_per_transaction = 1024`. `rowstile apply` warns before it starts and names the value to set (a
  restart; on managed Postgres, a parameter).
- **Identity providers**: `authz.sync_members` takes the member list; there is no SCIM
  endpoint. JWTs are HS256 only (no RS256/JWKS in plpgsql); for asymmetric tokens,
  verify in your backend and sign in from there ([Identity](identity.md)), or use an API key.
- **Writes cost more**: each closure table is maintained on every structural write,
  and structural writes to one type are serialized. Inheritance conditions that read
  other tables are re-evaluated for every row of the type when those tables change.
  A move rewrites one row per folder below it and per ancestor it gains or loses;
  while it runs, other tree writes to that type wait. If a link leads from inside the
  moved part back to the folder's old or new ancestors, everything below is recomputed
  instead, which is several times slower.
- **Privileges**: what the policy reads (relations, and `{conditions}` in permissions and rules) it reads with
  the privileges of whoever applied it, wherever it is checked. A condition on the row's own columns is
  written into the rules as it is; one that may read other rows (a subquery, a function other than a built-in
  that reads nothing, however its name is written, or an operator Postgres doesn't have for its own types) is
  called as a function per row the rules check, which costs more on large reads than the same test written as
  a relation.
- **Partitions go through their table**: apply turns row-level security on, with no rules
  of their own, for the partitions of a governed table and the tables that inherit from it,
  so the app role reads and writes them only through the table (whose rules and triggers
  are on it). A partition made after apply is open until the next apply; `authz.lint()`
  reports it. The owner writing to a partition directly skips the triggers.
- **Link rows are trusted as they are**: a row in a link table (`team_members`,
  `folder_teams`) grants what it says even when the object it names was deleted. Give link
  tables foreign keys to their objects with `ON DELETE CASCADE` (and `ON UPDATE CASCADE` for
  keys that change), as you would anyway. Shares are removed with their objects by rowstile.
  (A type with a `where` looks its rows up, so a leftover row naming one of its objects counts
  for nothing; don't rely on it.)
- **A permission named many times over is slow to plan.** Each permission is a view, and Postgres
  writes a view out in full every time a query names it, again for each view it names. A rule that reaches
  another type's permission (`folder.view`), which names others more than once, which do the same, multiplies:
  the policies in this repository make Postgres write out at most a dozen views for a read, and at around a
  hundred, planning alone takes tens to hundreds of milliseconds for every query, before a row is read.
  Tiers that include each other and inherit from the row above don't multiply: with `can edit = owner or
  editor or parent.edit` and `can view = edit or viewer or parent.view`, `view` looks up `parent.view` alone,
  which includes `parent.edit`, so each type in a chain adds the same few views. A query that joins tables
  pays for each of them.
  Planning is paid by every query that isn't a prepared statement. One that is gets planned in full its first
  five runs on a connection, and then Postgres usually keeps the plan: a read that took 13 ms to plan took
  0.1 ms from its sixth run. Whether queries are prepared is the driver's doing, not the policy's: behind a
  pooler that keeps no prepared statements, where the drivers are told to make none ([Behind a
  pooler](../operations.md#behind-a-pooler)), every query pays for its planning.
  `authz.lint()` warns when a table's select rule passes 50 (applying shows it). Name each permission once on
  the way: `can edit = owner or editor`, `can view = edit or viewer`, not `view` written out again inside
  three others. The same name twice in one `and` or `or` counts once.
- **Composite keys cost more to check** than single-column ones: ids are built as text per row
  (20,000 folders keyed `(org_id, id)`: a list of 7,000 takes about 0.4 s). The benchmark
  gate is measured on single keys.

## What a 0.x release promises

rowstile is a preview until 1.0. A minor release (0.1 to 0.2) may change the policy language, the `authz.*`
functions, the SDKs, the error codes and the file formats (`rowstile.toml`, the lock file). What it does keep:

- **Each release upgrades from the one before it**: a database applied by 0.1 is migrated by 0.2, and the
  suites test it. Skipping a release is not tested.
- **The changelog says what changed**, and its **Upgrading** says what to do: a policy line to rewrite, a call
  to rename, a migration to make.
- **A patch (0.1.1) only fixes.** Nothing to do when upgrading.
- **Security fixes go into the latest release only** ([SECURITY.md](../../SECURITY.md)).

What 1.0 promises is decided before 1.0, and this section is replaced by it.
