#!/bin/bash
# run_tests.sh: every test, from scratch, against the Postgres the PG* variables point at.
#   PGHOST=... PGPORT=... PGUSER=postgres ./run_tests.sh           # the full run (long)
#   ./run_tests.sh --quick                                         # meant to stay under 10 minutes
#   ./run_tests.sh --proofs                                        # the race and stress tests, short
#   ./run_tests.sh --short                                         # what depends on the Postgres version: --quick
#                         without the checks that need no database, one random-change run, no migrate vs apply
#   SOAK_SEED=N ./run_tests.sh --soak                              # the random checks (random policies too), long, with a new seed
#                         (about 95 minutes; a random seed if SOAK_SEED is empty; the log says which)
# Needs psql, createdb, dropdb and python3. Creates and drops databases named authz_*, as a non-superuser.
# Each step's result line says how long it took.
set -u
cd "$(dirname "$0")"
# Every suite runs as a non-superuser owner, as on managed Postgres. Started as a superuser, this
# makes one (authz_owner: LOGIN, CREATEDB, CREATEROLE, and SET on the roles it creates) and runs again as it;
# PGSUPERUSER names the superuser for the few checks that a superuser's connection is refused.
if [ "$(psql -X -At -d postgres -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")" = t ]; then
  PGSUPERUSER=$(psql -X -At -d postgres -c "SELECT current_user")
  bash tests/make_owner.sh || exit 1
  echo "running as authz_owner, not the superuser $PGSUPERUSER"
  exec env PGSUPERUSER="$PGSUPERUSER" PGUSER=authz_owner bash "$PWD/run_tests.sh" "$@"
fi
MODE=full; case "${1:-}" in --quick) MODE=quick;; --proofs) MODE=proofs;; --short) MODE=short;; --soak) MODE=soak;; esac
STEPS=100; [ "$MODE" = quick ] || [ "$MODE" = short ] && STEPS=15
# --short leaves out what reads no database (the same on every version) and the longest cross-checks
every_version() { [ "$MODE" != short ]; }
DB=authz_tests
failed=()
step() { echo; echo "=== $1"; STEP_START=$SECONDS; }
record() {
  local took="($((SECONDS - STEP_START))s)"
  if [ "$1" -eq 0 ]; then echo "--- passed: $2 $took"; else echo "--- FAILED: $2 $took"; failed+=("$2"); fi
}
apply() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$1"; }

# --soak: the parser fuzzer and every random-change run, longer and with a seed of their own, then the race
# and stress tests below, longer too. Nightly runs it with the run's id, so each night tries new cases.
if [ "$MODE" = soak ]; then
  SEED=${SOAK_SEED:-$RANDOM}
  echo "seed $SEED (again: SOAK_SEED=$SEED ./run_tests.sh --soak)"
  step "broken policies are refused with a line number, never a crash (200000 cases, seed $SEED)"
  python3 tests/fuzz_parser.py --cases 200000 --seed "$SEED"
  record $? "fuzz parser"
  for gen in docs alt multi composite loop; do
    step "random changes, compared with the reference evaluator ($gen, 500 changes, seed $SEED)"
    python3 tests/difftest.py --gen "$gen" --steps 500 --seed "$SEED" --quiet --db "authz_diff_$gen"
    record $? "difftest $gen"
    dropdb --if-exists "authz_diff_$gen" >/dev/null 2>&1
  done
  step "random policies, compared with the reference evaluator (100 policies, seeds from $((SEED * 1000)))"
  python3 tests/genpolicy.py --policies 100 --steps 10 --seed "$((SEED * 1000))" --db authz_genpolicy
  record $? "genpolicy"
  dropdb --if-exists authz_genpolicy >/dev/null 2>&1
fi

if [ "$MODE" != proofs ] && [ "$MODE" != soak ]; then
if every_version; then
step "fast checks without a database: golden SQL, included files, the command's SQL, rowstile command"
python3 tests/unit_test.py 2>&1 | tail -n 3
record "${PIPESTATUS[0]}" "unit"

step "broken policies are refused with a line number, never a crash (mutated example policies)"
FUZZ=5000; [ "$MODE" = quick ] && FUZZ=1500
python3 tests/fuzz_parser.py --cases "$FUZZ"
record $? "fuzz parser"
fi

step "compile the example policy"
python3 compile_policy.py example/docs.authz > /tmp/authz_docs.sql &&
python3 compile_policy.py example/docs.authz --tests > /tmp/authz_docs_tests.sql
record $? "compile"

step "end-to-end scenario through RLS (tests/scenario.sql + the tests in docs.authz)"
dropdb --if-exists "$DB" >/dev/null 2>&1; createdb "$DB"
apply example/app_schema.sql && apply /tmp/authz_docs.sql &&
psql -X -q -v ON_ERROR_STOP=1 -v docs_tests=/tmp/authz_docs_tests.sql -d "$DB" -f tests/scenario.sql > /tmp/authz_scenario.log 2>&1
rc=$?; echo "$(grep -c 'ok  ' /tmp/authz_scenario.log) checks passed"; grep "FAIL\|ERROR" /tmp/authz_scenario.log
record $rc "scenario"

step "re-applying the policy keeps shares and stays consistent"
psql -X -q -d "$DB" -c "SELECT count(*) FROM authz.shares" -At > /tmp/authz_shares_before
apply /tmp/authz_docs.sql && apply /tmp/authz_docs.sql &&
[ "$(psql -X -q -d "$DB" -At -c 'SELECT count(*) FROM authz.shares')" = "$(cat /tmp/authz_shares_before)" ] &&
[ "$(psql -X -q -d "$DB" -At -c 'SELECT authz.verify()')" = "t" ]
record $? "re-apply"
tests/keep.sh >/tmp/authz_keep.log 2>&1; rc=$?; grep "FAIL" /tmp/authz_keep.log
record $rc "keep unchanged trees"
dropdb "$DB"

step "the share API and newer features (tests/multi_scenario.sql on tests/multi.authz)"
dropdb --if-exists "$DB" >/dev/null 2>&1; createdb "$DB"
python3 compile_policy.py tests/multi.authz > /tmp/authz_multi.sql &&
apply tests/multi_schema.sql && apply /tmp/authz_multi.sql &&
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f tests/multi_scenario.sql > /tmp/authz_multi_scenario.log 2>&1
rc=$?; echo "$(grep -c 'ok  ' /tmp/authz_multi_scenario.log) checks passed"; grep "FAIL\|ERROR" /tmp/authz_multi_scenario.log
record $rc "multi scenario"
dropdb "$DB"

if every_version; then
step "policy mistakes are reported with line numbers"
python3 tests/policy_errors.py | tail -n 1
record "${PIPESTATUS[0]}" "policy errors"
fi

step "identities: scopes, API keys, JWT, view as, group sync, signed sessions"
tests/identity.sh
record $? "identity"
tests/principals.sh
record $? "principals"
tests/sessions.sh
record $? "signed sessions"

step "governance: audit trail, change feed, requests, break glass, reviews, invariants, policy diff"
tests/governance.sh
record $? "governance"

step "masked columns: applying, lint, --diff"
tests/masks.sh
record $? "masks"

step "developer tools: diagram, Python and TypeScript clients, editor grammar"
python3 tests/tools_test.py
record $? "tools"
if every_version; then
  python3 tests/lsp_test.py | grep -v "^ok"
  record "${PIPESTATUS[0]}" "language server"
fi

step "applying with the rowstile command: no extension, no superuser, includes, diff, backup and restore, remove"
tests/apply.sh
record $? "apply"
step "the rowstile command"
tests/cli.sh
record $? "cli"
step "the command over tables named as Prisma names them: capital letters, in public"
tests/capitals.sh
record $? "capitals"
step "policy changes as migrations: each tool's files, in order, out of order, push, trees built beside"
tests/migrations.sh
record $? "migrations"
step "rowstile review and fmt: a pull request in a git repository, with a review database"
tests/review.sh
record $? "review"
if every_version; then
step "a migration leaves what applying the new policy whole leaves (each kind of change, both ways)"
python3 tests/migrate_test.py | grep -v "^ok"
record "${PIPESTATUS[0]}" "migrate vs apply"
fi
step "prove, coverage, snapshots, indexes, plans and bench"
python3 tests/confidence_test.py | grep -v "^ok"
record "${PIPESTATUS[0]}" "confidence"
step "why, and how to grant; Studio (read-only, and able to write)"
python3 tests/studio_test.py | grep -v "^ok"
record "${PIPESTATUS[0]}" "studio"
step "the MCP server, for coding agents: check, prove, push, test, why, lint"
python3 tests/mcp_test.py | grep -v "^ok"
record "${PIPESTATUS[0]}" "mcp"
step "day to day: named tests, refusals that say why, who_among, init, dev, --as"
tests/devx.sh
record $? "devx"

step "concurrent changes to the tree"
tests/concurrency.sh
record $? "concurrency"

step "moves and links of folders with many below them"
tests/moves.sh
record $? "moves"

step "the app role trying every way around the policy"
tests/adversarial.sh
record $? "adversarial"

step "docs/getting-started.md runs as written"
tests/docs_test.sh
record $? "docs"
step "the cookbook's recipes: each one's policy applies, its tests pass, and its page shows only what is tested"
tests/cookbook.sh
record $? "cookbook"

GENS="docs alt multi composite loop"; every_version || GENS=docs
for gen in $GENS; do
  step "random changes, compared with the reference evaluator ($gen, $STEPS changes)"
  python3 tests/difftest.py --gen "$gen" --steps "$STEPS" --seed 7 --quiet --db "authz_diff_$gen"
  record $? "difftest $gen"
  dropdb --if-exists "authz_diff_$gen" >/dev/null 2>&1
done
if [ "$MODE" = full ]; then
  step "random policies, compared with the reference evaluator (12 policies)"
  python3 tests/genpolicy.py --policies 12 --steps 8 --seed 1 --db authz_genpolicy
  record $? "genpolicy"
  dropdb --if-exists authz_genpolicy >/dev/null 2>&1
fi
fi

# Tree writes under concurrency: every pair raced at each isolation level, and a concurrent stress run;
# the inheritance tables must stay exact throughout.
# --proofs runs a short version on its own (--quick leaves it out, so each stays under 10 minutes).
if [ "$MODE" = full ] || [ "$MODE" = proofs ] || [ "$MODE" = soak ]; then
  STRESS=100; [ "$MODE" = proofs ] && STRESS=15; [ "$MODE" = soak ] && STRESS=300
  step "tree writes raced in pairs"
  tests/races.sh | grep -v "^ok"
  record "${PIPESTATUS[0]}" "races"
  step "tree writes under stress (${STRESS}s per isolation level)"
  tests/stress.sh $STRESS
  record $? "stress"
fi

echo
if [ ${#failed[@]} -eq 0 ]; then echo "ALL PASSED"; else echo "FAILED: ${failed[*]}"; exit 1; fi
