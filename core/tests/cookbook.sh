#!/bin/bash
# cookbook.sh: docs/cookbook.md is tested. Its policy (docs/cookbook/policy.authz) applies to its tables, its
# tests pass, and every line the cookbook shows is in the policy or the tests, so the page can't drift.
#   PGHOST=... PGUSER=postgres tests/cookbook.sh
set -u
cd "$(dirname "$0")/.."
DB=authz_cookbook
BOOK=../docs/cookbook
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
CLI() { python3 cli/rowstile_cli.py --db "dbname=$DB" "$@"; }

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$BOOK/schema.sql" >/dev/null || exit 1
out=$(CLI apply "$BOOK/policy.authz" 2>&1); case "$out" in *": applied") ok "the cookbook's policy applies";; *) bad "apply" "$out";; esac
case "$out" in *WARNING*) bad "applying warns" "$out";; *) ok "... without warnings (authz.lint included)";; esac
out=$(CLI test "$BOOK"/tests/*.authz 2>&1); rc=$?
[ $rc -eq 0 ] && ok "its tests pass ($(echo "$out" | tail -n 1))" || bad "tests" "$(echo "$out" | grep -A 8 FAIL | head -40)"
missing=$(python3 - "$BOOK" <<'PY'
import glob, re, sys
book = sys.argv[1]
page = open(book + ".md", encoding="utf-8").read()
norm = lambda s: " ".join(s.split("--")[0].split())
have = set()
for f in [book + "/policy.authz"] + glob.glob(book + "/tests/*.authz"):
    have |= {norm(line) for line in open(f, encoding="utf-8")}
for block in re.findall(r"```authz\n(.*?)```", page, re.S):
    for line in block.splitlines():
        if norm(line) and norm(line) not in have:
            print(line.strip())
PY
)
[ -z "$missing" ] && ok "every line the cookbook shows is in its tested policy or tests" || bad "lines not in the policy or tests" "$missing"
[ -z "${KEEP:-}" ] && dropdb "$DB"
if [ $fails -eq 0 ]; then echo "cookbook: all passed"; else echo "cookbook: $fails failed"; exit 1; fi
