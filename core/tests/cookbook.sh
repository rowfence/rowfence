#!/bin/bash
# cookbook.sh: the cookbook is tested. docs/cookbook.md's policy (docs/cookbook/policy.authz) applies to its
# tables, its tests pass, and every line the page shows is in the policy or the tests, so the page can't drift.
# The same for each recipe with a page of its own: docs/cookbook/<name>.md shows docs/cookbook/<name>/
# (schema.sql, policy.authz, tests.authz; rows.sql, a few rows for the playground, must load too).
#   PGHOST=... PGUSER=postgres tests/cookbook.sh
set -u
cd "$(dirname "$0")/.."
BOOK=../docs/cookbook
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }

# one book: its name, its page, its schema, its policy, its test files (the rest of the arguments)
book() {
  local name=$1 page=$2 schema=$3 policy=$4; shift 4
  local db="authz_cookbook_${name//-/_}" out rc missing
  CLI() { python3 cli/rowstile_cli.py --db "dbname=$db" "$@"; }
  dropdb --if-exists "$db" 2>/dev/null
  createdb "$db" || { bad "$name: createdb"; return; }
  if ! PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -d "$db" -f "$schema" >/dev/null; then
    bad "$name: its tables"; return
  fi
  out=$(CLI apply "$policy" 2>&1); case "$out" in *": applied") ok "$name: the policy applies";; *) bad "$name: apply" "$out";; esac
  case "$out" in *WARNING*) bad "$name: applying warns" "$out";; *) ok "$name: ... without warnings (authz.lint included)";; esac
  out=$(CLI test "$@" 2>&1); rc=$?
  [ $rc -eq 0 ] && ok "$name: its tests pass ($(echo "$out" | tail -n 1))" || bad "$name: tests" "$(echo "$out" | grep -A 8 FAIL | head -40)"
  local rows; rows="$(dirname "$schema")/rows.sql"
  if [ "$name" != cookbook ] && [ -f "$rows" ]; then
    psql -X -q -v ON_ERROR_STOP=1 -d "$db" -f "$rows" >/dev/null 2>&1 && ok "$name: the playground's rows load" || bad "$name: rows.sql"
  fi
  missing=$(python3 - "$page" "$policy" "$@" <<'PY'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
norm = lambda s: " ".join(s.split("--")[0].split())
have = set()
for f in sys.argv[2:]:
    have |= {norm(line) for line in open(f, encoding="utf-8")}
for block in re.findall(r"```authz\n(.*?)```", page, re.S):
    for line in block.splitlines():
        if norm(line) and norm(line) not in have:
            print(line.strip())
PY
)
  [ -z "$missing" ] && ok "$name: every line its page shows is in its tested policy or tests" || bad "$name: lines not in the policy or tests" "$missing"
  [ -z "${KEEP:-}" ] && dropdb "$db"
}

book cookbook "$BOOK.md" "$BOOK/schema.sql" "$BOOK/policy.authz" "$BOOK"/tests/*.authz

recipes=0
for dir in "$BOOK"/*/; do
  name=$(basename "$dir")
  [ -f "$dir/policy.authz" ] || continue
  recipes=$((recipes + 1))
  for f in schema.sql tests.authz; do [ -f "$dir/$f" ] || bad "$name: no $f"; done
  [ -f "$BOOK/$name.md" ] || { bad "$name: no page (docs/cookbook/$name.md)"; continue; }
  book "$name" "$BOOK/$name.md" "$dir/schema.sql" "$dir/policy.authz" "$dir/tests.authz"
done
# a page without its folder shows lines nothing tests
for page in "$BOOK"/*.md; do
  [ -e "$page" ] || continue
  name=$(basename "$page" .md)
  [ -f "$BOOK/$name/policy.authz" ] || bad "$name: a page without docs/cookbook/$name/policy.authz"
done
[ "$recipes" -gt 0 ] && ok "$recipes recipe(s) with a page of their own" || bad "no recipe folder was found"

if [ $fails -eq 0 ]; then echo "cookbook: all passed"; else echo "cookbook: $fails failed"; exit 1; fi
