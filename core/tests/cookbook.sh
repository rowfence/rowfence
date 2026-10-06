#!/bin/bash
# cookbook.sh: the cookbook is tested. Each recipe is a page, docs/cookbook/<name>.md, beside a folder,
# docs/cookbook/<name>/: schema.sql (its tables), rows.sql (a few rows, for the playground), policy.authz and
# tests.authz. For each: the tables and the rows load, the policy applies without a warning, its tests pass
# (with the rows there, as in the playground), and every line the page shows is in the policy or the tests, so
# the page can't drift. Its invariants, if it states any, are proved, and ask.sql, if it has one (what the
# playground asks first), runs as the app role. A page without its folder, or a folder without its page, fails.
#   PGHOST=... PGUSER=postgres tests/cookbook.sh
set -u
cd "$(dirname "$0")/.."
BOOK=../docs/cookbook
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }

recipe() {
  local name=$1 dir=$BOOK/$1 page=$BOOK/$1.md
  local db="authz_cookbook_${name//-/_}" out rc missing f
  for f in schema.sql rows.sql tests.authz; do [ -f "$dir/$f" ] || { bad "$name: no $f"; return; }; done
  [ -f "$page" ] || { bad "$name: no page (docs/cookbook/$name.md)"; return; }
  CLI() { python3 cli/rowstile_cli.py --db "dbname=$db" "$@"; }
  dropdb --if-exists "$db" 2>/dev/null
  createdb "$db" || { bad "$name: createdb"; return; }
  if ! PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -d "$db" -f "$dir/schema.sql" -f "$dir/rows.sql" >/dev/null; then
    bad "$name: its tables and rows"; dropdb "$db"; return
  fi
  out=$(CLI apply "$dir/policy.authz" 2>&1); case "$out" in *": applied") ok "$name: the policy applies";; *) bad "$name: apply" "$out";; esac
  case "$out" in *WARNING*) bad "$name: applying warns" "$out";; *) ok "$name: ... without warnings (authz.lint included)";; esac
  out=$(CLI test "$dir/tests.authz" 2>&1); rc=$?
  [ $rc -eq 0 ] && ok "$name: its tests pass ($(echo "$out" | tail -n 1))" || bad "$name: tests" "$(echo "$out" | grep -A 8 FAIL | head -40)"
  missing=$(python3 - "$page" "$dir/policy.authz" "$dir/tests.authz" <<'PY'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
norm = lambda s: " ".join(s.split("--")[0].split())
have = set()
for f in sys.argv[2:]:
    have |= {norm(line) for line in open(f, encoding="utf-8")}
blocks = re.findall(r"```authz\n(.*?)```", page, re.S)
if not blocks:
    print("(the page shows no policy)")
for block in blocks:
    for line in block.splitlines():
        if norm(line) and norm(line) not in have:
            print(line.strip())
PY
)
  [ -z "$missing" ] && ok "$name: every line its page shows is in its tested policy or tests" || bad "$name: lines not in the policy or tests" "$missing"
  # a recipe that states invariants shows them proved: rowstile prove finds no small world that breaks one
  if grep -q '^invariants' "$dir/policy.authz"; then
    out=$(python3 cli/rowstile_cli.py prove "$dir/policy.authz" 2>&1)
    if echo "$out" | grep -q '^  ok   holds' && ! echo "$out" | grep -q '^  no  '; then ok "$name: its invariants are proved"; else bad "$name: prove" "$out"; fi
  fi
  # the question the playground asks first, as its first user, runs
  if [ -f "$dir/ask.sql" ]; then
    out=$({ echo "BEGIN; SET LOCAL ROLE app_user; SELECT authz.act_as('user', '1');"; cat "$dir/ask.sql"; echo "; ROLLBACK;"; } |
      psql -X -q -At -v ON_ERROR_STOP=1 -d "$db" 2>&1) &&
      ok "$name: the playground's question runs as the app role" || bad "$name: ask.sql" "$out"
  fi
  [ -z "${KEEP:-}" ] && dropdb "$db"
}

recipes=0
for dir in "$BOOK"/*/; do
  [ -f "$dir/policy.authz" ] || continue
  recipes=$((recipes + 1))
  recipe "$(basename "$dir")"
done
# a page without its folder shows lines nothing tests
for page in "$BOOK"/*.md; do
  [ -e "$page" ] || continue
  name=$(basename "$page" .md)
  [ -f "$BOOK/$name/policy.authz" ] || bad "$name: a page without docs/cookbook/$name/policy.authz"
done
# the index names every recipe
for dir in "$BOOK"/*/; do
  name=$(basename "$dir")
  [ -f "$dir/policy.authz" ] || continue
  grep -qF "(cookbook/$name.md)" "$BOOK.md" || bad "$name: docs/cookbook.md doesn't link to it"
done
[ "$recipes" -ge 18 ] && ok "$recipes recipes" || bad "only $recipes recipes were found"

if [ $fails -eq 0 ]; then echo "cookbook: all passed"; else echo "cookbook: $fails failed"; exit 1; fi
