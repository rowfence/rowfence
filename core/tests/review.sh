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

echo "-- a pull request whose policy doesn't run on the review data"
G checkout -q -- db && rm -f "$P"/db/migrations/*_authz_build_policy.sql && G clean -q -fd db
sed -i 's/not {confidential}/not {confidentail}/' "$P/db/policy.authz"
sleep 1; CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
said="policy line 63: the condition {confidentail} doesn't run: column \"confidentail\" does not exist [AZ613]"
case "$out" in *Traceback*) bad "a condition Postgres refuses gives a traceback" "$out";;
  *"Access   not computed: $said"*"Tests    not run: the migration fails: $said"*"It fails on the review database: $said"*)
    [ $rc -eq 0 ] && [ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
    ok "a condition Postgres refuses: Access, Tests and Deploy say which and why; the review database is left as it was" ||
    bad "a condition Postgres refuses: exit or the database" "$rc";;
  *) bad "a condition Postgres refuses" "$out";; esac
G checkout -q -- db && G clean -q -fd db
sed -i 's/not {confidential}/not {confidential or name::int > 0}/' "$P/db/policy.authz"
sleep 1; CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
case "$out" in *Traceback*) bad "a condition that fails on a row gives a traceback" "$out";;
  *"Access   not computed: invalid input syntax for type integer: "*) [ $rc -eq 0 ] &&
    ok "... one that fails on a row of the review data: Access says why, and the review goes on" || bad "a condition that fails on a row: exit" "$rc";;
  *) bad "a condition that fails on a row" "$out";; esac
G checkout -q -- db && G clean -q -fd db

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

echo "-- the pull request that adds the policy: none at the base"
F="$T/first"; mkdir -p "$F/db"
{ git -C "$F" init -q -b main && git -C "$F" config user.email t@example.com && git -C "$F" config user.name t &&
  echo "# app" > "$F/README.md" && git -C "$F" add -A && git -C "$F" commit -q -m base; } || bad "setting up the new repository"
printf 'app role web\ntype user = public.users\ntype doc = public.docs\n  owner : user = owner_id\n  can view = owner\n' > "$F/db/policy.authz"
out=$( (cd "$F" && python3 "$OLDPWD/cli/rowstile_cli.py" review --base main db/policy.authz) 2>&1); rc=$?
if printf '%s\n' "$out" | grep -q '^ *changed '; then bad "a new policy: a declaration said to change from one nobody wrote" "$out"
else case "$out" in *"added    app role"*"after:  app role web"*"added    type user"*"after:  type user = public.users"*)
  [ $rc -eq 0 ] && ok "the pull request that adds the policy: each declaration added, its own app role and user type too" || bad "a new policy: exit" "$rc";;
  *) bad "a new policy" "$out";; esac; fi

rm -rf "$T"
dropdb --if-exists "$DB" 2>/dev/null
[ $fails -eq 0 ] && echo "review: all passed" || { echo "review: $fails failed"; exit 1; }
