#!/bin/bash
# run_tests.sh: every test, from scratch, against the Postgres the PG* variables point at.
#   PGHOST=... PGPORT=... PGUSER=postgres ./run_tests.sh           # the full run (long)
#   ./run_tests.sh --quick                                         # meant to stay under 10 minutes
#   ./run_tests.sh --proofs                                        # the race and stress tests, short
#   ./run_tests.sh --short                                         # what depends on the Postgres version: --quick
#                         without the checks that need no database, one random-change run, no migrate vs apply
#   SOAK_SEED=N ./run_tests.sh --soak                              # the random checks (random policies too), long, with a new seed
#                         (about 110 minutes; a random seed if SOAK_SEED is empty; the log says which)
#   ROWSTILE_PART=command ./run_tests.sh --quick                   # one part of a run (below: the parts of each)
#   ROWSTILE_COVERAGE=/abs/dir ./run_tests.sh --quick              # also measure what the suites run (below)
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
# The parts of a run: CI runs them side by side, each on a runner and in a container of its own, and the run
# is as long as its longest part. ROWSTILE_PART names the one to run (none: the whole run, one part after the
# other). The workflows list them, and tests/unit_test.py checks they leave none out.
PARTS_SUITES="policy command random"                      # --quick, --short and the full run
PARTS_SOAK="changes-1 changes-2 policies around races"    # --soak
case "$MODE" in
  soak) PARTS=$PARTS_SOAK;; proofs) PARTS=races;; full) PARTS="$PARTS_SUITES races";; *) PARTS=$PARTS_SUITES;;
esac
PART=${ROWSTILE_PART:-}
case " $PARTS " in *" ${PART:-${PARTS%% *}} "*) ;; *) echo "no part '$PART' in this run: its parts are $PARTS"; exit 2;; esac
[ -z "$PART" ] || echo "part $PART (of: $PARTS)"
part() { [ -z "$PART" ] || [ "$PART" = "$1" ]; }
# ROWSTILE_COVERAGE=DIR: each Python process the suites start measures which lines and branches of authzlib and
# cli it runs, into DIR, each one marked with the step that ran it (tests/coverage.ini). It needs coverage.py: the
# image core/Dockerfile builds with COVERAGE=1 has it, and core/ci.sh --coverage uses that image. Each database is
# also asked, before it is dropped, which of rowstile's functions were called in it (tests/coverage-bin wraps
# createdb and dropdb; Postgres counts them with track_functions = all, which ci.sh --coverage sets).
# python3 tests/coverage_report.py DIR then says what nothing runs.
if [ -n "${ROWSTILE_COVERAGE:-}" ]; then
  mkdir -p "$ROWSTILE_COVERAGE/data" && ROWSTILE_COVERAGE=$(cd "$ROWSTILE_COVERAGE" && pwd) || exit 1
  export ROWSTILE_COVERAGE COVERAGE_PROCESS_START="$PWD/tests/coverage.ini" ROWSTILE_COVERAGE_CODE="$PWD"
  export ROWSTILE_COVERAGE_CONTEXT="" PATH="$PWD/tests/coverage-bin:$PATH"
  echo "measuring what the suites run, into $ROWSTILE_COVERAGE"
fi
STEPS_RUN=0
step() { echo; echo "=== $1"; STEP_START=$SECONDS; STEPS_RUN=$((STEPS_RUN + 1)); ROWSTILE_COVERAGE_CONTEXT=$1; }
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
  if part policies; then
  step "broken policies are refused with a line number, never a crash (200000 cases, seed $SEED)"
  python3 tests/fuzz_parser.py --cases 200000 --seed "$SEED"
  record $? "fuzz parser"
  step "simple conditions read as Postgres reads them (50000 made up, seed $SEED)"
  python3 tests/conditions_test.py --cases 50000 --seed "$SEED"
  record $? "conditions"
  fi
  for gen in docs alt multi composite loop cross; do
    # two parts, about as long as each other
    case "$gen" in docs|multi) part changes-1;; *) part changes-2;; esac || continue
    step "random changes, compared with the reference evaluator ($gen, 500 changes, seed $SEED)"
    python3 tests/difftest.py --gen "$gen" --steps 500 --seed "$SEED" --quiet --db "authz_diff_$gen"
    record $? "difftest $gen"
    dropdb --if-exists "authz_diff_$gen" >/dev/null 2>&1
  done
  if part policies; then
  step "random policies, compared with the reference evaluator (100 policies, seeds from $((SEED * 1000)))"
  python3 tests/genpolicy.py --policies 100 --steps 10 --seed "$((SEED * 1000))" --db authz_genpolicy
  record $? "genpolicy"
  dropdb --if-exists authz_genpolicy >/dev/null 2>&1
  fi
  if part around; then
  step "random policies in random worlds: the catalog, the session and the role around them (60, seeds from $((SEED * 1000)))"
  python3 tests/around.py --policies 60 --steps 8 --seed "$((SEED * 1000))" --db authz_around
  record $? "around"
  fi
fi

if [ "$MODE" != proofs ] && [ "$MODE" != soak ]; then
if part policy; then
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

fi
if part command; then
step "applying with the rowstile command: no extension, no superuser, includes, diff, backup and restore, remove"
tests/apply.sh
record $? "apply"
step "the rowstile command"
tests/cli.sh
record $? "cli"
step "the command over tables named as Prisma names them: capital letters, in public"
tests/capitals.sh
record $? "capitals"
step "tables under a governed one: partitions, and tables that inherit"
tests/children.sh
record $? "children"
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
fi
if part policy; then
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

fi
GENS="docs alt multi composite loop cross"; every_version || GENS=docs
for gen in $GENS; do
  # six policies: four in the random part, one with each of the two others, which are shorter, so that the
  # three parts are about as long as each other
  case "$gen" in composite) part policy;; multi) part command;; *) part random;; esac || continue
  step "random changes, compared with the reference evaluator ($gen, $STEPS changes)"
  python3 tests/difftest.py --gen "$gen" --steps "$STEPS" --seed 7 --quiet --db "authz_diff_$gen"
  record $? "difftest $gen"
  dropdb --if-exists "authz_diff_$gen" >/dev/null 2>&1
done
if part random; then
if [ "$MODE" = full ]; then
  step "random policies, compared with the reference evaluator (12 policies)"
  python3 tests/genpolicy.py --policies 12 --steps 8 --seed 1 --db authz_genpolicy
  record $? "genpolicy"
  dropdb --if-exists authz_genpolicy >/dev/null 2>&1
fi
# what is around the policy depends on the version of Postgres more than the policy does: a few on every run
AROUND=4; [ "$MODE" = full ] && AROUND=16
step "random policies in random worlds: the catalog, the session and the role around them ($AROUND policies)"
python3 tests/around.py --policies "$AROUND" --steps 6 --seed 1 --db authz_around
record $? "around"
step "simple conditions read as Postgres reads them (3000 made up)"
python3 tests/conditions_test.py --cases 3000 --seed 1
record $? "conditions"
fi
fi

# Tree writes under concurrency: every pair raced at each isolation level, and a concurrent stress run;
# the inheritance tables must stay exact throughout.
# --proofs runs a short version on its own (--quick leaves it out, so each stays under 10 minutes).
if { [ "$MODE" = full ] || [ "$MODE" = proofs ] || [ "$MODE" = soak ]; } && part races; then
  STRESS=100; [ "$MODE" = proofs ] && STRESS=15; [ "$MODE" = soak ] && STRESS=300
  step "tree writes raced in pairs"
  tests/races.sh | grep -v "^ok"
  record "${PIPESTATUS[0]}" "races"
  step "tree writes under stress (${STRESS}s per isolation level)"
  tests/stress.sh $STRESS
  record $? "stress"
fi

# measuring: the function calls of the databases still here (each one dropped earlier was asked then)
[ -z "${ROWSTILE_COVERAGE:-}" ] ||
  bash tests/coverage_functions.sh $(psql -X -At -d postgres -c "SELECT datname FROM pg_database WHERE datname LIKE 'authz%'")

echo
[ "$STEPS_RUN" -gt 0 ] || failed+=("no step ran")
if [ ${#failed[@]} -eq 0 ]; then echo "ALL PASSED"; else echo "FAILED: ${failed[*]}"; exit 1; fi
