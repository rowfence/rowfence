# core

rowstile itself: the compiler and the `rowstile` command (Python 3.11 or newer, standard library only), and
their tests. What the language and the command do is in [the reference](../docs/reference/language.md); this
page is for working on them.

| folder | what |
|---|---|
| `authzlib/` | the compiler (Python 3, standard library only); `database.py` is what the command does to a database, `migrate.py` the migrations |
| `cli/` | `rowstile`, the command that compiles and applies, and `pgwire.py`, the small Postgres client it uses |
| `compile_policy.py` | the same compiler without a database: writes the SQL to a file (for development, tests and the editor) |
| `example/` | the docs app used throughout: its schema, `docs.authz` and the policy's tests (`docs.test.authz`) |
| `tests/` | every test suite; `run_tests.sh` runs them all, `ci.sh` on every Postgres version |
| `bench/` | the benchmarks: `benchmark.sql` (the docs app, bigger) and the scale benchmark |

From this folder:

    cli/rowstile migrate example/docs.authz --tool sql       # the next migration, from the lock file
    cli/rowstile --db "dbname=mydb" push example/docs.authz  # a development database, straight away
    ./run_tests.sh                                           # every test, from scratch (needs Postgres)
    ./ci.sh                                                  # ... on 16, 17 and 18, each in Docker

## Tested

`./run_tests.sh` runs everything against fresh databases, in about 15 minutes (a few
with `--quick`), as a non-superuser owner of the tables (started as a superuser, it makes one), on
the stock Postgres image:

| suite | what it checks |
|---|---|
| `tests/scenario.sql` | end-to-end checks through RLS as each user, plus the tests in `docs.authz` |
| `tests/multi_scenario.sql` | the second policy (`tests/multi.authz` on `tests/multi_schema.sql`): UUIDs, suspension, mixed-type trees, public and link access, caveats, custom roles, the masked view |
| `tests/difftest.py` | random data and 100 random changes per policy (moves, links, loops, nesting, shares, expiry and start times, id changes, TRUNCATE, multi-statement transactions); after each, `can`, `list`, `explain`, `who`, RLS reads, every policy expression and every column rule's condition (as the owner, and as the app role on the rows it may select) and the masked view are compared for every user (and one of them again with a scope) against a separate reference evaluator. Five policies (`--gen`: docs, alt, multi, composite, loop). |
| `tests/unit_test.py` | checks without a database, in about a second: the generated SQL against golden files (`--update` after an intended change), included files, what the command runs, its file reading, the version |
| `tests/identity.sh` | scopes, API keys, JWTs (bad signature, expiry, missing expiry, issuer, `alg: none`), view-as, group sync |
| `tests/governance.sh` | audit, feed, requests, break-glass, reviews, invariants, decision log, `--diff`, lint |
| `tests/masks.sh` | masks at apply time, later GRANTs reported by lint and taken back by applying, after renames, in `--diff` |
| `tests/tools_test.py` | the diagram, both clients (every statement prepared against the database; TypeScript type-checked with `tsc --strict` where it is installed), the editor grammar |
| `tests/client_types.py` | the generated TypeScript client under `tsc --strict`, no database: correct calls pass, wrong names don't (CI's `javascript` job) |
| `tests/apply.sh` | what applying does to a database: no extension, only if changed, both scenarios, tests, included files, who may apply, `diff`, `pg_dump` and restore, applying again after an upgrade, removing, and applying as a non-superuser owner |
| `tests/cli.sh` | `rowstile`: every command, included files from disk, errors and exit codes |
| `tests/migrations.sh` | `rowstile migrate` for each tool, migrations applied in order, out of order and on a new database, `--check`, `push`, a tree built beside while the app writes, `dev` writing the migration |
| `tests/review.sh` | `rowstile review` in a git repository with a review database: meaning, access, risk, tests, deploy, the comment, JSON and annotations, a refactor found equivalent, the database left as it was; `rowstile fmt` |
| `tests/migrate_test.py` | each kind of policy change, both ways: the migration leaves exactly what applying the new policy whole leaves (functions and their privileges, views, triggers, policies, catalogs, inheritance rows), with the app writing in between |
| `tests/concurrency.sh` | two sessions racing: moves, loops, sharing during a delete |
| `tests/adversarial.sh` | the app role, logged in as its own role, trying to read hidden rows (by id, COPY, leaky functions, prepared statements), reach rowstile's internals (and the catalog of every policy here against the rules, `tests/catalog.sql`), turn row-level security off, change or share what it may not, and learn about hidden objects |
| `tests/docs_test.sh` | the SQL of `docs/getting-started.md` runs as written and does what the guide says |
| `tests/fuzz_parser.py` | thousands of mutated policies: each is accepted or refused with a line number, never a crash |
| `tests/moves.sh` | moves and links of folders with hundreds below them: the stored rows are shifted (rows inside the moved part left alone), loops fall back to recomputing, and the tables match a rebuild after each |
| `tests/policy_errors.py` | policy mistakes (including included files passed as a map), each reported at compile or apply time, and awkward policies that must still work |
| `tests/keep.sh` | applying keeps the inheritance tables whose definition didn't change, and rebuilds the ones that did |
| `tests/principals.sh` | services that sign in as themselves: principal types, their keys and JWTs, `service:*` next to `user:*`, what the audit trail records |
| `tests/sessions.sh` | signed sessions: the app role can't choose its user by setting `authz.user_id`, widen its scopes, or reuse a sign-in in another transaction or connection |
| `tests/devx.sh` | what developers use day to day: named tests with their own data, refusals that say why, `authz.who_among`, drafting a policy, `rowstile dev`, `test`, `init`, `--as` |
| `tests/confidence_test.py` | `rowstile prove`, `test --coverage`, `snapshot`, `indexes`, `plans` and `bench`, on the docs example |
| `tests/lsp_test.py` | the language server over its protocol, as an editor uses it (no database) |
| `tests/mcp_test.py` | the MCP server over its protocol, as a coding agent's client uses it: each tool in a project folder |
| `tests/studio_test.py` | `rowstile why` and Studio's API: read-only unless `--write`, only for the page that has the token, on localhost |
| `tests/cookbook.sh` | the cookbook's recipes (`docs/cookbook/<name>.md` and its folder): each one's tables and rows load, its policy applies without a warning, its tests pass, and every line its page shows is in them |
| `tests/races.sh` | the full run and `--proofs`: every pair of tree writes raced in two sessions at each isolation level; the inheritance tables match a rebuild after each |
| `tests/stress.sh` | the full run and `--proofs`: 16 clients writing a folder tree at once at each isolation level; the tables match a rebuild afterwards |
| `tests/genpolicy.py` | the full run (12) and `--soak` (100, a new seed each night): random policies, each with its tables and data (write rules with conditions that read another table: a subquery, a function called by a quoted name, an operator), checked against the reference evaluator like the fixed ones |
