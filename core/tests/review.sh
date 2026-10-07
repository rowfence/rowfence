#!/bin/bash
# review.sh: rowstile review in a git repository, with a database at the base branch's state, as CI
# runs it: what the pull request changes in meaning, access, risk, tests and deploy; the comment, the JSON and
# the annotations; the database left as it was. And rowstile fmt.
#   PGHOST=... PGUSER=... tests/review.sh
set -u
cd "$(dirname "$0")/.."
DB=authz_review
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
command -v git >/dev/null || { echo "skip  git is not installed"; exit 0; }
T=$(mktemp -d)
P="$T/p"
mkdir -p "$P/db/tests"
sed '/^test$/,$d' example/docs.authz > "$P/db/policy.authz"
cp example/docs.test.authz "$P/db/tests/docs.authz"
printf 'policy = "db/policy.authz"\ntests = ["db/tests/*.authz"]\n[migrations]\ntool = "sql"\ndir = "db/migrations"\n' > "$P/rowstile.toml"
CLI() { ( cd "$P" && python3 "$OLDPWD/cli/rowstile_cli.py" "$@" ); }
G() { git -C "$P" "$@"; }
# the project in a folder of the repository, as the file manager is in this one
git -C "$T" init -q -b main && G config user.email t@example.com && G config user.name t
CLI migrate >/dev/null && G add -A && G commit -q -m base || { bad "setting up the repository"; exit 1; }

# the review database: the base branch's migrations, then the review data
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
for f in "$P"/db/migrations/*.sql; do
  PGOPTIONS="-c client_min_messages=error" psql -X -q -1 -v ON_ERROR_STOP=1 -d "$DB" -f "$f" >/dev/null || { bad "base migration"; exit 1; }
done
PSQL -c "SET ROLE app_user" -c "SET authz.user_id = 5" -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" >/dev/null
before=$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")

echo "-- a pull request that changes inheritance"
sed -i 's/can view  = edit or viewer or (parent.view and {inherit})/can view  = edit or viewer or parent.view/' "$P/db/policy.authz"
sed -i 's/user $bo cannot view file $f/user $bo can view file $f/' "$P/db/tests/docs.authz"
sleep 1
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
[ $rc -eq 0 ] && ok "rowstile review runs, and exits 0 whatever it found (it reports, the tests gate)" || bad "review" "$out"
case "$out" in *"Meaning  1 permission changed, 3 permissions and rules change through it"*) ok "Meaning: what changed, and what changes through it";; *) bad "meaning" "$out";; esac
case "$out" in *"Access   "*"users gain \`view\` on"*"Nobody loses access."*) ok "Access: who gains what, on the review data";; *) bad "access" "$out";; esac
case "$out" in *"not a refactor: "*" differs for user "*" on "[a-z]*" "*) ok "... and the difference that makes it no refactor names who and what, in words";; *) bad "the counterexample's wording" "$out";; esac
case "$out" in *"folder.view\` allows more than before"*) ok "Risk: the permission widened, with an example";; *) bad "risk" "$out";; esac
case "$out" in *"Tests    "*"checks pass, "*" fail. 1 check changed what it expects."*) ok "Tests: the tests of the pull request ran, and the flipped check is named";;
  *) bad "tests" "$out";; esac
case "$out" in *"Deploy   2 migrations."*"Builds folder__linked_into_parent__tree beside the tables in use, then swaps in."*"Applied on the review database in"*)
  ok "Deploy: two migrations, the tree built beside, applied on the review data";; *) bad "deploy" "$out";; esac
[ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
  ok "the review database is left as it was" || bad "review left changes"
md=$(CLI --db "dbname=$DB" review --base main --markdown)
case "$md" in "<!-- rowstile review -->"*"<details><summary>Meaning</summary>"*"| \`folder.view\` (changed) |"*"<details><summary>Access</summary>"*"<details><summary>Deploy</summary>"*)
  ok "--markdown: the comment, with its marker and details";; *) bad "markdown" "$md";; esac
CLI review --base main --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['meaning']['changed'][0]['what'] == 'folder.view'" &&
  ok "--json" || bad "json"
case "$(CLI review --base main --annotations)" in "::warning file=p/db/policy.authz,line="*"a permission widened"*)
  ok "--annotations: on the policy line, its path from the repository's top folder";;
  *) bad "annotations" "$(CLI review --base main --annotations)";; esac

echo "-- a base git doesn't know, a policy with a mistake"
out=$(CLI review --base no-such-branch 2>&1); rc=$?
case "$out" in *"git doesn't know the commit to compare with, no-such-branch"*) [ $rc -eq 2 ] && ok "a base git doesn't know: said, exit 2 (not the whole policy as new)" || bad "unknown base exit" "$rc";;
  *) bad "unknown base" "$out";; esac
cp "$P/db/policy.authz" "$T/keep.authz"
sed -i 's/can view  = edit or viewer or parent.view/can view  = edit or viewer or nosuch.view/' "$P/db/policy.authz"
out=$(CLI review --base main 2>&1); rc=$?
case "$out" in *"Traceback"*) bad "a mistake in the policy gives a traceback" "$out";;
  *"has no relation or permission 'nosuch'"*"[AZ203]"*) [ $rc -eq 1 ] && ok "a mistake in the pull request's policy: check's message, exit 1" || bad "mistake exit" "$rc";;
  *) bad "a mistake in the policy" "$out";; esac
cp "$T/keep.authz" "$P/db/policy.authz"

echo "-- a refactor"
G checkout -q -- db && rm -f "$P"/db/migrations/*_authz_build_policy.sql && G clean -q -fd db
sed -i 's/can edit  = share or editor or (parent.edit and {inherit})/can edit  = editor or share or ({inherit} and parent.edit)/' "$P/db/policy.authz"
out=$(CLI review --base main 2>&1)
case "$out" in "Meaning  unchanged: every permission and rule grants the same in"*) ok "a refactor: meaning unchanged, checked in small worlds";; *) bad "refactor" "$out";; esac

echo "-- rowstile fmt"
G checkout -q -- db
out=$(CLI fmt --check 2>&1); rc=$?
case "$out" in *"db/policy.authz: not formatted"*) [ $rc -eq 1 ] && ok "fmt --check: exit 1, and which file" || bad "fmt --check exit" "$rc";; *) bad "fmt --check" "$out";; esac
out=$(CLI fmt 2>&1); out2=$(CLI fmt --check 2>&1); rc=$?
case "$out" in *"formatted db/policy.authz"*) [ $rc -eq 0 ] && ok "fmt writes it; then --check passes" || bad "fmt then check" "$out2";; *) bad "fmt" "$out";; esac
out=$(CLI review --base main 2>&1)
case "$out" in "Meaning  unchanged (only comments, spacing or order)"*"Deploy   no migration"*) ok "... and review says formatting changed nothing";; *) bad "review after fmt" "$out";; esac
# a Windows checkout: the file's lines end with CRLF, and stay so
sed -i 's/$/\r/' "$P/db/policy.authz"
out=$(CLI fmt --check 2>&1); rc=$?
[ $rc -eq 0 ] && ok "a CRLF file in fmt's layout passes --check" || bad "fmt --check on CRLF" "$out"
printf '\r\n\r\n' >> "$P/db/policy.authz"
out=$(CLI fmt 2>&1)
lines=$(wc -l < "$P/db/policy.authz"); crlf=$(grep -c $'\r$' "$P/db/policy.authz")
case "$out" in *"formatted db/policy.authz"*) [ "$lines" = "$crlf" ] && ok "... and fmt writes it back with CRLF" || bad "fmt on CRLF: endings" "$crlf of $lines";; *) bad "fmt on CRLF" "$out";; esac

echo "-- a base in the language before this one (a pull request that upgrades rowstile rewrites the policy)"
G checkout -q -- db && G clean -q -fd db
{ G checkout -q -b before && sed -i 's/^app role app_user/role app_user/' "$P/db/policy.authz" && G commit -q -am before &&
  G checkout -q main; } || bad "setting up the branch before"
out=$(CLI review --base before 2>&1); rc=$?
case "$out" in "Base     The policy at the base is written in the language before"*"\`role app_user\`, now \`app role app_user\`"*"Meaning  unchanged"*)
  [ $rc -eq 0 ] && ok "a base in the language before: read as that version meant it, and said" || bad "base before: exit" "$rc";;
  *) bad "a base in the language before" "$out";; esac

rm -rf "$T"
dropdb --if-exists "$DB" 2>/dev/null
[ $fails -eq 0 ] && echo "review: all passed" || { echo "review: $fails failed"; exit 1; }
