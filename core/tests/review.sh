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
out=$(CLI review --base main db/nosuch.authz 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$out" = "db/nosuch.authz: No such file or directory" ] && ok "a policy file that isn't there: said, exit 2" || bad "review of a missing policy" "$rc $out"
{ cat "$P/db/policy.authz"; printf -- '-- caf\351\n'; } > "$P/db/latin.authz"
out=$(CLI review --base main db/latin.authz 2>&1); rc=$?
case "$out" in "db/latin.authz: not UTF-8 (the byte at "*"): save it as UTF-8") [ $rc -eq 2 ] && ok "... nor one that isn't UTF-8" || bad "review of a policy not UTF-8: exit" "$rc";;
  *) bad "review of a policy not UTF-8" "$out";; esac
rm "$P/db/latin.authz"
printf 'test "caf\351"\n  user 3 can view file 11\n' > "$P/db/tests/latin.authz"
out=$(CLI review --base main 2>&1); rc=$?
case "$out" in *"/db/tests/latin.authz: not UTF-8 (the byte at 9): save it as UTF-8") [ $rc -eq 2 ] && ok "a test file that isn't UTF-8: said, exit 2" || bad "review of a test file not UTF-8: exit" "$rc";;
  *) bad "review of a test file not UTF-8" "$out";; esac
rm "$P/db/tests/latin.authz"
out=$(CLI --db "dbname=authz_review_no_such_db" review --base main 2>&1); rc=$?
case "$out" in "can't connect: "*'database "authz_review_no_such_db" does not exist') [ $rc -eq 2 ] && ok "a review database that isn't there: can't connect, exit 2" || bad "review --db unreachable: exit" "$rc";;
  *) bad "review --db unreachable" "$out";; esac
dropdb --if-exists "${DB}_bare" 2>/dev/null; createdb "${DB}_bare"
out=$(CLI --db "dbname=${DB}_bare" review --base main 2>&1); rc=$?
case "$out" in *Traceback*) bad "a review database without the app's tables gives a traceback" "${out: -300}";;
  *"Access   not computed: the policy does not match this database:"*"table app.users not found [AZ601]"*)
    [ $rc -eq 0 ] && ok "a review database without the app's tables: Access says why it isn't computed, exit 0" || bad "review on a bare database: exit" "$rc";;
  *) bad "review on a bare database" "$out";; esac
dropdb --if-exists "${DB}_bare"

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

echo "-- a pull request whose policy reads a column its own migration of the app adds"
G checkout -q -- db && G clean -q -fd db
sed -i 's/^  owner  : user   = owner_id$/  owner  : user   = author_id/' "$P/db/policy.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
case "$out" in *"Traceback"*) bad "a column the review database doesn't have yet: a traceback" "$out";;
  *"Access   not computed: the policy does not match this database:"*"column author_id not found in app.files [AZ601]"*"Tests    not run: the migration fails: "*"**It fails on the review database: "*)
  [ $rc -eq 0 ] && ok "a column the review database doesn't have yet: Access not computed, and why; the review goes on, exit 0" ||
    bad "a column the review database doesn't have yet: exit" "$rc";;
  *) bad "a column the review database doesn't have yet" "$out";; esac
[ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
  ok "... and the review database is left as it was" || bad "review left changes after a failed diff"
G checkout -q -- db && G clean -q -fd db

echo "-- a pull request that lets a service in (a bot that signs in, which the app's own migration adds)"
PSQL -c "CREATE TABLE app.bots (id bigint PRIMARY KEY)" -c "CREATE TABLE app.folder_bots (folder_id bigint, bot_id bigint)" \
  -c "INSERT INTO app.bots VALUES (7)" -c "INSERT INTO app.folder_bots VALUES (2, 7)"
sed -i -e 's/^type org = app.orgs$/type bot = app.bots principal\n\ntype org = app.orgs/' \
  -e 's/^  editor      : team#member = app.folder_team_access(folder_id -> team_id) where {access = .edit.}$/&\n  bot_viewer  : bot         = app.folder_bots(folder_id -> bot_id)/' \
  -e 's/^           or linked_into.view  -- links pass on view, not edit$/           or linked_into.view or bot_viewer  -- links pass on view, not edit/' "$P/db/policy.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main --markdown 2>&1)
case "$out" in *"**Access**: 1 bot gains \`view\` on 1 file; 1 bot gains \`view\` on 1 folder. Nobody loses access."*)
  ok "Access says who gains: a bot, not a user";; *) bad "Access of a service" "$out";; esac
case "$out" in *"| gains | \`folder\` view | 1 bot | 1 | bot 7, folder 2: bot_viewer, bot_viewer: a row in app.folder_bots names |"*)
  ok "... and how it gains, asked as the bot, from what grants it alone";; *) bad "how a service gains" "$out";; esac
G checkout -q -- db && G clean -q -fd db
PSQL -c "DROP TABLE app.folder_bots, app.bots"

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
{ G checkout -q -b broken && sed -i 's/can edit  = share or editor or/can edit  = share or edtor or/' "$P/db/policy.authz" &&
  G commit -q -am broken && G checkout -q main; } || bad "setting up the branch broken"
out=$(CLI review --base broken 2>&1); rc=$?
case "$out" in *"db/policy.authz at broken: the policy at the base has a mistake: line "*": folder has no relation or permission 'edtor'"*"[AZ203]")
  [ $rc -eq 1 ] && ok "a base whose policy has a mistake (in this language and the one before): said, with the base's line, exit 1" || bad "a base with a mistake: exit" "$rc";;
  *) bad "a base with a mistake" "$out";; esac

echo "-- the review database"
G checkout -q -- db && G clean -q -fd db
# the tests alone change: nothing to migrate, and they run on the review data
sed -i 's/user $bo cannot view file $f/user $bo can view file $f/' "$P/db/tests/docs.authz"
out=$(CLI --db "dbname=$DB" review --base main 2>&1)
case "$out" in *"Tests    "*" checks pass, 1 fail. 1 check changed what it expects."*"Deploy   no migration: nothing the database holds changes."*)
  ok "a pull request that changes the tests alone: nothing to migrate, and they run on the review data";; *) bad "the tests alone" "$out";; esac
G checkout -q -- db
# a project that keeps no migrations (rowstile apply): the pull request's policy is applied whole on the review data
N="$T/nolock"; mkdir -p "$N/db/tests"
sed '/^test$/,$d' example/docs.authz > "$N/db/policy.authz"; cp example/docs.test.authz "$N/db/tests/docs.authz"
printf 'policy = "db/policy.authz"\ntests = ["db/tests/*.authz"]\n' > "$N/rowstile.toml"
{ git -C "$N" init -q -b main && git -C "$N" config user.email t@example.com && git -C "$N" config user.name t &&
  git -C "$N" add -A && git -C "$N" commit -q -m base; } || bad "setting up a repository without migrations"
sed -i 's/can view  = edit or viewer or (parent.view and {inherit})/can view  = edit or viewer or parent.view/' "$N/db/policy.authz"
out=$( (cd "$N" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" review --base main) 2>&1)
case "$out" in *"Tests    9 checks pass, 1 fail."*"Deploy   no lock file, so no migrations"*)
  [ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
  ok "a project without migrations: the policy applied whole on the review data, its tests run there, all undone" ||
  bad "a project without migrations: the database changed";; *) bad "a project without migrations" "$out";; esac
# a review database a policy was pushed to since: the migrations from the base's lock refuse to run there
sed -e '/^test$/,$d' -e 's/^  can share = owner or folder.share$/  can share = owner or folder.share\n  can print = view/' \
  example/docs.authz > "$T/pushed.authz"
CLI --db "dbname=$DB" push --development "$T/pushed.authz" >/dev/null 2>&1 || bad "a push to the review database"
sed -i 's/can view  = edit or viewer or (parent.view and {inherit})/can view  = edit or viewer or parent.view/' "$P/db/policy.authz"
sleep 1; CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1)
case "$out" in *"Tests    not run: the migration fails: rowstile: this migration changes the policy the migration before it left"*"It fails on the review database: rowstile: this migration changes"*"[AZ607]"*)
  ok "a review database not where the base's lock says: the migrations refuse it, and Tests and Deploy say so";;
  *) bad "a review database not where the base's lock says" "$out";; esac
G checkout -q -- db && G clean -q -fd db

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
# without --base: main, also from a branch (HEAD isn't main: the policy is committed on the branch)
{ git -C "$F" checkout -q -b feature && git -C "$F" add -A && git -C "$F" commit -q -m policy; } || bad "setting up the branch feature"
out=$( (cd "$F" && python3 "$OLDPWD/cli/rowstile_cli.py" review db/policy.authz) 2>&1); rc=$?
case "$out" in *"added    app role"*"after:  app role web"*) [ $rc -eq 0 ] && ok "without --base, the review compares with main" || bad "review without --base: exit" "$rc";;
  *) bad "review without --base" "$out";; esac
git -C "$F" branch -q -m main trunk
out=$( (cd "$F" && python3 "$OLDPWD/cli/rowstile_cli.py" review db/policy.authz) 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$out" = "rowstile review: which commit to compare with? --base main (or a commit)" ] &&
  ok "... and where there is no main or master, asks which commit" || bad "review without --base, no main" "$rc $out"

echo "-- a policy in several files, at the base and in the pull request"
I="$T/inc"; mkdir -p "$I/db/parts"
printf 'include "parts/types.authz"\n' > "$I/db/policy.authz"
printf 'app role web\ntype user = public.users\ntype doc = public.docs\n  owner : user = owner_id\n  can view = owner\n' > "$I/db/parts/types.authz"
{ git -C "$I" init -q -b main && git -C "$I" config user.email t@example.com && git -C "$I" config user.name t &&
  git -C "$I" add -A && git -C "$I" commit -q -m base; } || bad "setting up the repository with includes"
printf '  can edit = owner\n' >> "$I/db/parts/types.authz"
out=$( (cd "$I" && python3 "$OLDPWD/cli/rowstile_cli.py" review --base main db/policy.authz) 2>&1); rc=$?
case "$out" in "Meaning  1 permission added"*) [ $rc -eq 0 ] && ok "a policy that includes files: the base's are read from git too" || bad "includes at the base: exit" "$rc";;
  *) bad "includes at the base" "$out";; esac

echo "-- a review database whose owner may not switch to the app role"
# since PostgreSQL 16 a role that makes another gets ADMIN on it, not SET (the suites' owner has
# createrole_self_grant, which would hide it); the tests run as the app role
N=authz_review_plain
R=authz_review_plain_app
dropdb --if-exists "$N" 2>/dev/null; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1
createdb "$N" || exit 1
PGOPTIONS="-c createrole_self_grant= -c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$N" \
  -c "CREATE ROLE $R" -c "CREATE SCHEMA app" -c "CREATE TABLE app.users (id bigint PRIMARY KEY)" \
  -c "CREATE TABLE app.notes (id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, body text)" \
  -c "GRANT USAGE ON SCHEMA app TO $R" -c "GRANT SELECT ON app.users TO $R" -c "GRANT SELECT, UPDATE ON app.notes TO $R" >/dev/null || exit 1
Q="$T/plain"; mkdir -p "$Q/db/tests"
printf 'app role %s\ntype user = app.users\ntype note = app.notes\n  owner : user = owner_id\n  can edit = owner\nrules app.notes\n  select : edit\n  update : edit\n' "$R" > "$Q/db/policy.authz"
printf 'test "the owner reads its note"\n  as user 1 sees 1 {SELECT FROM app.notes}\n' > "$Q/db/tests/t.authz"
printf 'policy = "db/policy.authz"\ntests = ["db/tests/*.authz"]\n[migrations]\ntool = "sql"\ndir = "db/migrations"\n' > "$Q/rowstile.toml"
QCLI() { ( cd "$Q" && python3 "$OLDPWD/cli/rowstile_cli.py" "$@" ); }
{ git -C "$Q" init -q -b main && git -C "$Q" config user.email t@example.com && git -C "$Q" config user.name t &&
  QCLI migrate >/dev/null && git -C "$Q" add -A && git -C "$Q" commit -q -m base; } || bad "setting up the plain owner's repository"
for f in "$Q"/db/migrations/*.sql; do
  PGOPTIONS="-c client_min_messages=error" psql -X -q -1 -v ON_ERROR_STOP=1 -d "$N" -f "$f" >/dev/null || bad "the plain owner's base migration"
done
sed -i 's/^  can edit = owner$/&\n  can view = edit/' "$Q/db/policy.authz"
out=$(QCLI --db "dbname=$N" review --base main 2>&1); rc=$?
case "$out" in *"may not switch to the app role $R (SET ROLE), and this looks at the data as the app does [AZ618]"*"HINT: "*"GRANT \"$R\" TO \"$PGUSER\""*)
  [ $rc -eq 1 ] && ok "the review says what to grant, exit 1" || bad "review as a plain owner: exit" "$rc";;
  *) bad "review as a plain owner" "$out";; esac
dropdb --if-exists "$N"; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1

rm -rf "$T"
dropdb --if-exists "$DB" 2>/dev/null
[ $fails -eq 0 ] && echo "review: all passed" || { echo "review: $fails failed"; exit 1; }
