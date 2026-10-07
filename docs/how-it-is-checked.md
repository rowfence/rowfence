# How rowstile is checked

**Nobody outside the project has audited rowstile.** This page says what does check it, so that you can judge
for yourself. Every line names the test that does the checking; they all run in CI, in the open, and
[the table of suites](../core/README.md#tested) lists every one.

## Two ways to answer, which must agree

rowstile answers "may this person do that?" in two ways: with lookups into views for reads and lists, and with
a check of the single row for writes and `authz.can`. They are written separately, and they must give the same
answer. After every random change, [`tests/difftest.py`](../core/tests/difftest.py) asks both, for every
user, and compares.

## A second implementation

Tests written by the author of the code share the author's mistakes. So the answers are also compared with a
second implementation that shares no code with the first: the reference evaluator
([`authzlib/evaluate.py`](../core/authzlib/evaluate.py)), which works straight from the policy, on sets of
ids, to a fixed point, and knows nothing of the SQL the compiler writes.

- **Random data**: [`tests/difftest.py`](../core/tests/difftest.py) fills five policies' tables with random
  rows and makes a hundred random changes to each (moves, links, loops, groups inside groups, shares that
  start and end, ids that change, `TRUNCATE`, several statements in one transaction). After each change,
  `authz.can`, `authz.list`, `authz.explain`, `authz.who`, what row-level security lets each user read, every
  rule's condition and the masked views are compared with the evaluator's answer.
- **Random policies**: [`tests/genpolicy.py`](../core/tests/genpolicy.py) writes policies at random, with
  their tables and data, and checks them the same way: twelve on each full run, and a hundred with new seeds
  every night.
- **Random worlds**: the two above compare answers in one setting: plain tables, and the owner's session
  switched to the app role. [`tests/around.py`](../core/tests/around.py) takes the random policies again and
  draws what is around each one too: tables that are partitioned, or have a table that inherits from them;
  default privileges of the owner's; a login role that is a member of the app role and signs each user in;
  planner settings, a read-only transaction, a search path that starts with a schema of decoys; and, halfway,
  something changed behind the policy's back (a grant on rowstile's own tables, row-level security turned
  off, a new partition). Besides the comparisons above, asked in that session, it tries real writes as the
  app role on every row and undoes them, checks that no share outlives its row, that a role the policy
  doesn't name gets nothing, and that `authz.lint()` reports what changed and `rowstile apply` puts it right.
  A few on every run, sixty with new seeds every night.

## The boundary

The app role is the one rowstile doesn't trust ([the threat model](threat-model.md) says who is trusted with
what).

- [`tests/adversarial.sh`](../core/tests/adversarial.sh) logs in as the app role and tries to read hidden
  rows (by id, with `COPY`, through leaky functions and prepared statements), to reach rowstile's own tables
  and functions, to turn row-level security off, to change or share what it may not, and to learn whether
  a hidden row exists. It also checks the catalog each policy leaves: which functions run with their owner's
  rights, and that the app role may call the API and nothing else.
- [`tests/sessions.sh`](../core/tests/sessions.sh) checks that the app role can't choose who is signed in
  by setting a variable, widen an API key's scopes, or reuse a sign-in in another transaction or connection.
- [`tests/identity.sh`](../core/tests/identity.sh) covers API keys and JWTs: a bad signature, an expired
  token, one without an expiry, `alg: none`.

## Trees, under load

Inherited permissions are kept in tables by triggers, and those tables must match the tree at every commit.
[`tests/races.sh`](../core/tests/races.sh) races every pair of tree writes in two sessions at each isolation
level, and [`tests/stress.sh`](../core/tests/stress.sh) lets sixteen clients write one tree at once; after
each, the tables are compared with a rebuild.

## Proofs in small worlds

`rowstile prove` takes a policy's invariants ("never: someone views a workspace of an organisation they aren't
in") and looks for a small world in which one fails: a few users, a few rows, every way of linking them. It
answers with the smallest counterexample, or says that there is none among the worlds tried. It is a search,
not a proof for worlds of any size, and it reads the policy, not your data.

## What ships, and what the docs say

- **Migrations**: for each kind of policy change, [`tests/migrate_test.py`](../core/tests/migrate_test.py)
  checks that the migration leaves exactly what applying the new policy whole leaves: functions and their
  privileges, views, triggers, policies, the inheritance rows.
- **The parser**: [`tests/fuzz_parser.py`](../core/tests/fuzz_parser.py) feeds it thousands of broken
  policies; each is accepted, or refused with a line number, never a crash.
- **The docs**: the getting-started guide runs as written, every line the cookbook shows is in a policy that
  is applied and tested, and every line of code on the stack pages is in an app whose tests pass.
- **Three versions of Postgres**: every suite on PostgreSQL 16 for each change, and on 17 and 18
  [every night](../.github/workflows/nightly.yml), with the races, the stress test and the random policies.

## What a review of every file found

Before the first public release, every file was read with one question: what does the documentation promise
here, and does a test hold the code to it? It found 153 things to fix. Eleven were wrong access: a row seen or
written that the policy didn't allow, or refused when it allowed it. Ten of those eleven were found by reading,
one by the random policies. All 153 are fixed.

Then the suites themselves were tested: 44 mistakes were put into the compiler on purpose, one at a time. The
suites caught 42. The two they missed got tests.

## When something is found

Vulnerabilities are reported privately ([SECURITY.md](../SECURITY.md)) and published as advisories once
fixed. There has been one so far: GHSA-6g93-673q-c29f, in `@rowstile/prisma`, found by the project itself, and
fixed and published the same day.

## What this doesn't cover

- An audit by someone outside the project. There has been none.
- The limits [the threat model](threat-model.md#known-limits-accepted) accepts: side channels such as
  `EXPLAIN ANALYZE` row counts, tables without rules, `SECURITY DEFINER` functions an app adds.
- Managed Postgres services other than the two [it was tried on](managed-postgres.md), and macOS.
- Your policy. rowstile enforces what the policy says; whether it says what you meant is what its tests, its
  invariants and [the review of each change](reference/review.md) are for.
