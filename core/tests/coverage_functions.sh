#!/bin/bash
# coverage_functions.sh DB...: which of rowstile's functions in each database the suites called, added to
# $ROWSTILE_COVERAGE/functions.tsv: the step that made the database, the database, the schema, the function, its
# arguments, how often it was called (0: never) and what it is (its language; definer, set: SECURITY DEFINER, a
# SET clause). Postgres counts calls with track_functions = all (core/ci.sh --coverage sets it), only those that
# return (not one that raises), and none of a plain SQL function it inlines into the query that calls it. A
# database's counts go with it: run_tests.sh measures each one as it is dropped (tests/coverage-bin/dropdb) and
# those left at the end. tests/coverage_report.py reads the file.
[ -n "${ROWSTILE_COVERAGE:-}" ] || exit 0
for db in "$@"; do
  # the step that made it (tests/coverage-bin/createdb wrote it down), else the one running now
  step=$(awk -F '\t' -v db="$db" '$1 == db {s = $2} END {print s}' "$ROWSTILE_COVERAGE/databases.tsv" 2>/dev/null)
  [ -n "$step" ] || step=${ROWSTILE_COVERAGE_CONTEXT:-}
  psql -X -q -At -F $'\t' -d "$db" -c "
    SELECT n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid), coalesce(s.calls, 0),
      l.lanname || CASE WHEN p.prosecdef THEN ' definer' ELSE '' END
        || CASE WHEN p.proconfig IS NOT NULL THEN ' set' ELSE '' END
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_language l ON l.oid = p.prolang
    LEFT JOIN pg_catalog.pg_stat_user_functions s ON s.funcid = p.oid
    WHERE n.nspname IN ('authz', 'authz_gen', 'authz_int')" 2>/dev/null |
    awk -F '\t' -v step="$step" -v db="$db" 'BEGIN {OFS = "\t"} {print step, db, $0}' >> "$ROWSTILE_COVERAGE/functions.tsv"
done
exit 0
