#!/bin/bash
# devx.sh: what developers use day to day. Named tests that bring their own data, refusals that say why
# (the error, authz.explain_rule), authz.who_among, applying only when changed, the warning for rule
# conditions that read governed tables, drafting a policy, and the rowstile command: dev, test, init, --as.
#   PGHOST=... PGUSER=postgres tests/devx.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_devx}
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
CLI() { python3 cli/rowstile_cli.py --db "dbname=$DB" "$@"; }
run() { out=$(CLI "$@" 2>&1); rc=$?; }
# a statement as the app role, signed in as user $1: its error (message and detail), or 'ok'
as() { psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user" -c "SET authz.user_id = '$1'" -c "$2" 2>&1; }
# the rows of a test run of these named test files (tab-separated: test, line, ok, detail), without the
# policy's own test section (it needs the example scenario's shares)
rows() { python3 tests/test_rows.py "dbname=$DB" "$@" | awk -F'\t' '$1 != "test section"'; }

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
run apply example/docs.authz; [ "$out" = "example/docs.authz: applied" ] || { bad "apply" "$out"; exit 1; }
T=$(mktemp -d)

echo "-- named tests: their own data, rolled back"
before=$(PSQL -c "SELECT (SELECT count(*) FROM app.users) || '/' || (SELECT count(*) FROM app.files)")
cp example/docs.test.authz "$T/docs.test.authz"
out=$(rows "$T/docs.test.authz" | awk -F'\t' '{n++; if ($3 == "t") y++} END {print y+0 "/" n+0}')
case "$out" in "0/"*) bad "named tests" "$out";; *) [ "${out%/*}" = "${out#*/}" ] && ok "the example's named tests pass ($out)" || bad "named tests" "$out";; esac
[ "$(PSQL -c "SELECT (SELECT count(*) FROM app.users) || '/' || (SELECT count(*) FROM app.files)")" = "$before" ] &&
  ok "... and leave no rows behind" || bad "named tests left rows"
sed 's/user $bo cannot view file $f/user $bo can view file $f/' example/docs.test.authz > "$T/t.authz"
out=$(rows "$T/t.authz" | awk -F'\t' '$3 == "f" {print $2 ": " $4}')
case "$out" in "t.authz line 13: user \$bo can view file \$f"*"does not hold view on file"*) ok "a failing check names its file and line, and explains itself";;
  *) bad "failing check" "$out";; esac
sed 's/as user $bo refused {INSERT/as user $bo allowed {INSERT/' example/docs.test.authz > "$T/t.authz"
out=$(rows "$T/t.authz" | awk -F'\t' '$3 == "f" {print $4}')
case "$out" in *"refused: permission denied: user 9002 may not insert this row into app.files"*"no   folder.edit"*) ok "an 'allowed' that is refused shows the refusal and why";;
  *) bad "allowed but refused" "$out";; esac
printf '%s\n' 'test "ids of several columns"' '  given m = {SELECT 7 AS org_id, 42 AS id}' "  as anyone sees 1 {SELECT WHERE \$m = '(7,42)'}" > "$T/c.authz"
out=$(rows "$T/c.authz" | awk -F'\t' '$1 == "ids of several columns" {print $3}' | tr '\n' ' ')
[ "$out" = "t " ] && ok "given binds several returned columns as one id, as Postgres writes the row" || bad "composite given" "$out"
cat > "$T/w.authz" <<'EOF'
test "a write, however it starts"
  given ann  = {INSERT INTO app.users (id, name) VALUES (9001, 'Ann') RETURNING id;}
  given bo   = {INSERT INTO app.users (id, name) VALUES (9002, 'Bo') RETURNING id}
  given acme = {INSERT INTO app.orgs (id, name) VALUES (9001, 'Acme') RETURNING id}
  given top  = {INSERT INTO app.folders (org_id, owner_id, name) VALUES ($acme, $ann, 'Top') RETURNING id}
  as user $bo refused {WITH x AS (SELECT 1) UPDATE app.folders SET name = 'x' WHERE id = $top}
  as user $bo refused {/* hidden from Bo */ UPDATE app.folders SET name = 'x' WHERE id = $top}
  as user $ann allowed {WITH x AS (SELECT 1) UPDATE app.folders SET name = 'x' WHERE id = $top}
  as user $bo allowed {WITH x AS (SELECT 1) SELECT FROM app.folders WHERE id = $top}
  as user $ann sees 1 {SELECT FROM app.folders WHERE id = $top;}
  given f    = {INSERT INTO app.files (folder_id, owner_id, name) VALUES ($top, $ann, 'a') RETURNING id}
  as user $ann refused {INSERT INTO app.files (id, folder_id, owner_id, name) VALUES ($f, $top, $ann, 'twice')}
EOF
out=$(rows "$T/w.authz" | awk -F'\t' '$1 != "invariants" {print $3}' | tr -d '\n')
[ "$out" = tttttf ] && ok "a write after WITH or a comment that changes no row is refused; a read of no row is allowed; sees takes a final ;" || bad "writes however they start" "$(rows "$T/w.authz")"
out=$(rows "$T/w.authz" | awk -F'\t' '$3 == "f" {print $4}')
case "$out" in *"error: "*) ok "... and an error that isn't a refusal fails 'refused' too";; *) bad "refused by another error" "$out";; esac
sed 's/as user $bo refused {WITH/as user $bo allowed {WITH/' "$T/w.authz" > "$T/t.authz"
out=$(rows "$T/t.authz" | awk -F'\t' '$3 == "f" {print $4}')
case "$out" in *"refused: it changed no rows"*) ok "... 'allowed' on one fails, and says it changed no rows";; *) bad "allowed, no rows" "$out";; esac
printf '%s\n' 'test "x"' '  given a = {SELECT 1 WHERE false}' '  anyone cannot view file 1' > "$T/x.authz"
out=$(rows "$T/x.authz" | awk -F'\t' '$1 == "x" {print $4}')
case "$out" in *"returned 0 rows: it must return one"*) ok "a given that returns no row is an error, named";; *) bad "given no row" "$out";; esac

echo "-- refusals that say why"
out=$(as 1 "INSERT INTO app.files (folder_id, owner_id, name) VALUES (6, 2, 'x')")
case "$out" in *"42501"*"permission denied: user 1 may not insert this row into app.files"*"insert : folder.edit and owner"*"no   owner"*)
  ok "a refused insert says which rule, and which part of it";; *) bad "refused insert" "$out";; esac
case "$out" in *"CONSTRAINT NAME:  authz_insert"*"TABLE NAME:  files"*|*"TABLE NAME:  files"*"CONSTRAINT NAME:  authz_insert"*) ok "... with the table and the policy in the error's fields";;
  *) bad "error fields" "$out";; esac
out=$(as 6 "INSERT INTO app.files (folder_id, owner_id, name) VALUES (6, 6, 'x')")
case "$out" in *"no   you have no access to folder 6"*) ok "... and says nothing about a folder the user can't see";; *) bad "no leak" "$out";; esac
out=$(as 5 "UPDATE app.folders SET inherit = false WHERE id = 1 RETURNING id")
[ "$out" = 1 ] && ok "an allowed update is not refused" || bad "allowed update" "$out"

echo "-- authz.explain_rule"
out=$(as 1 "SELECT array_to_string(authz.explain_rule('app.files', 'update', '11'), '|')")
case "$out" in "yes  update : edit"*) ok "an update that would be allowed: yes";; *) bad "explain update yes" "$out";; esac
out=$(as 1 "SELECT authz.explain_rule('app.files', 'delete', '999999') IS NULL")
[ "$out" = t ] && ok "a row that isn't there: NULL (404, not 403)" || bad "explain missing" "$out"
out=$(as 6 "SELECT authz.explain_rule('app.files', 'update', '11') IS NULL")
[ "$out" = t ] && ok "... and one the user can't see: NULL too" || bad "explain invisible" "$out"
out=$(as 2 "SELECT array_to_string(authz.explain_rule('app.files', 'update', '12', '{\"name\": \"x\"}'), '|')")
case "$out" in "no   update : edit"*"after the change:"*) ok "an update the user may not make: no, before and after the change";; *) bad "explain update" "$out";; esac
out=$(as 1 "SELECT authz.explain_rule('app.nothing', 'insert')")
case "$out" in *"no rules for table app.nothing"*) ok "a table without rules is named";; *) bad "no rules" "$out";; esac

echo "-- authz.who_among"
out=$(as '' "SELECT string_agg(x, ',' ORDER BY x) FROM authz.who_among('file', 11, 'view', ARRAY['1','2','3','4','5','6','7']) x")
[ -n "$out" ] && ok "who of these may view file 11: $out" || bad "who_among" "$out"
want=$(for u in 1 2 3 4 5 6 7; do [ "$(as $u "SELECT authz.can('file', 11, 'view')")" = t ] && printf '%s,' $u; done)
[ "$out," = "$want" ] && ok "... the same as asking authz.can as each of them" || bad "who_among vs can" "$out vs $want"
out=$(as 4 "SELECT count(*) FROM authz.who_among('file', 11, 'view', ARRAY['1']); SELECT current_setting('authz.user_id')" | tail -n 1)
[ "$out" = 4 ] && ok "... and whoever was signed in stays signed in" || bad "who_among restores" "$out"
PSQL -c "DROP ROLE IF EXISTS authz_devx_other" -c "CREATE ROLE authz_devx_other" -c "GRANT USAGE ON SCHEMA authz TO authz_devx_other" \
     -c "GRANT EXECUTE ON FUNCTION authz.who_among(text, text, text, text[], text) TO authz_devx_other" >/dev/null
out=$(PSQL -c "SET ROLE authz_devx_other" -c "SELECT authz.who_among('file', '11', 'view', ARRAY['1'])" 2>&1)
case "$out" in *"permission denied"*) ok "a role that may not sign people in may not use it";; *) bad "who_among needs SET" "$out";; esac

echo "-- applying, and what it warns about"
{ cat example/docs.authz; printf '%s\n' 'rules app.teams' '  select : {exists (select 1 from app.files f where f.owner_id = authz.uid())}'; } > "$T/trap.authz"
run apply "$T/trap.authz"
qual=$(PSQL -c "SELECT qual FROM pg_policies WHERE schemaname = 'app' AND tablename = 'teams' AND policyname = 'authz_select'")
case "$out $qual" in *"row-level security"*) bad "a rule condition that reads a governed table is warned about" "$out";;
  *"authz_gen.team__check_"*) ok "a rule condition that reads a governed table runs with the policy's rights, as a function";;
  *) bad "the rule condition" "$qual";; esac
CLI apply example/docs.authz >/dev/null 2>&1

echo "-- drafting a policy (rowstile init)"
mkdir -p "$T/i" && ( cd "$T/i" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app ) > "$T/init.log" 2>&1
out=$(cat "$T/i/db/policy.authz" 2>/dev/null)
case "$out" in *"type folder = app.folders"*"parent : folder = parent_id"*"member : user = app.org_members(org_id -> user_id)"*"update parent_id after : parent.edit"*)
  ok "a draft: types, relations from columns and link tables, rules";; *) bad "draft" "${out:0:400} $(cat "$T/init.log")";; esac
run apply "$T/i/db/policy.authz"; case "$out" in *": applied") ok "... which applies";; *) bad "draft applies" "$out";; esac
CLI apply example/docs.authz >/dev/null 2>&1
out=$(mkdir -p "$T/j" && cd "$T/j" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema nosuch 2>&1)
case "$out" in *"no tables to draft a policy from in nosuch"*) ok "a schema with no tables is named";; *) bad "draft empty" "$out";; esac
# in a Next.js app on Prisma: the tool, the generated names, the SDK packages and the setup line
mkdir -p "$T/k/prisma" "$T/k/src"
printf '{\n    "name": "shop",\n    "dependencies": {"next": "16", "@prisma/client": "7", "react": "19"}\n}\n' > "$T/k/package.json"
printf 'datasource db {\n  provider = "postgresql"\n}\n' > "$T/k/prisma/schema.prisma"
printf 'export const db = new PrismaClient({ adapter });\n' > "$T/k/src/db.ts"
out=$(cd "$T/k" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"found   Next.js, Prisma (prisma/schema.prisma)"*"added   @rowstile/prisma, @rowstile/next, @rowstile/react, rowstile"*"in src/db.ts"*"signedIn("*)
  ok "init finds Next.js and Prisma, adds the SDK, says which line to change";; *) bad "init stack" "$out";; esac
grep -q 'tool = "prisma"' "$T/k/rowstile.toml" && grep -q 'dir  = "prisma/migrations"' "$T/k/rowstile.toml" && grep -q 'ts = "src/authz.gen.ts"' "$T/k/rowstile.toml" &&
  grep -q '"@rowstile/prisma": "^' "$T/k/package.json" && grep -q '^    "name": "shop"' "$T/k/package.json" && grep -q 'linguist-generated' "$T/k/.gitattributes" &&
  ok "... in rowstile.toml, package.json (its layout kept) and .gitattributes" || bad "init stack files" "$(cat "$T/k/rowstile.toml" "$T/k/package.json")"
# ...and that the app's client takes a URL of its own, not Prisma's, which is the owner's
case "$out" in *"process.env.ROWSTILE_APP_URL"*"never the one this command uses"*) ok "... and that the app connects with its own URL, as the app role";;
  *) bad "init: the app's connection" "$out";; esac
# in a FastAPI app that got FastAPI through rowstile's extras, with a role of its own name: the stack is found, the
# role named is the policy's, and rowstile isn't asked for again
mkdir -p "$T/f"
printf '[project]\nname = "tracker"\ndependencies = [\n    "rowstile[asyncpg,fastapi,sqlalchemy]>=0.1.0a4",\n]\n' > "$T/f/pyproject.toml"
printf 'script_location = migrations\n' > "$T/f/alembic.ini"
out=$(cd "$T/f" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app --role tracker_app 2>&1)
case "$out" in *"to your Python dependencies"*|*"(app_user)"*) bad "init in a FastAPI app asks again, or names another role" "$out";;
  *"found   FastAPI, SQLAlchemy, Alembic"*"Rowstile(app, engine"*"connects as (tracker_app)"*) ok "init finds FastAPI through rowstile's extras, and names the policy's role";;
  *) bad "init in a FastAPI app" "$out";; esac
grep -q "(tracker_app)" "$T/f/db/tests/first.authz" && ok "... in the first test file too" || bad "init: the role in the test file" "$(cat "$T/f/db/tests/first.authz")"
# a schema as Prisma names it (capitals), a column named like an SQL word, a link table named like a permission,
# one through a unique column, a name with a space, and the migration tool's own table: the draft compiles and applies
dropdb --if-exists "${DB}_names" 2>/dev/null; createdb "${DB}_names"
psql -X -q -v ON_ERROR_STOP=1 -d "${DB}_names" >/dev/null <<'SQL'
CREATE SCHEMA pr;
CREATE TABLE pr."User" (id serial PRIMARY KEY, email text UNIQUE);
CREATE TABLE pr."Post" (id serial PRIMARY KEY, "authorId" int REFERENCES pr."User", "order" int REFERENCES pr."User");
CREATE TABLE pr."Comment" (id serial PRIMARY KEY, "postId" int REFERENCES pr."Post", "authorId" int REFERENCES pr."User");
CREATE TABLE pr.post_views (post_id int REFERENCES pr."Post", user_id int REFERENCES pr."User", PRIMARY KEY (post_id, user_id));
CREATE TABLE pr.teams (id serial PRIMARY KEY, slug text UNIQUE);
CREATE TABLE pr.team_members (team_slug text REFERENCES pr.teams (slug), user_id int REFERENCES pr."User", PRIMARY KEY (team_slug, user_id));
CREATE TABLE pr."_prisma_migrations" (id varchar(36) PRIMARY KEY);
CREATE TABLE pr."owner list" (id serial PRIMARY KEY, "owner id" int REFERENCES pr."User");
SQL
mkdir -p "$T/n"
out=$(cd "$T/n" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_names" init --schema pr 2>&1)
draft=$(cat "$T/n/db/policy.authz" 2>/dev/null)
case "$draft" in *'type user = pr.User'*'author : user = authorId'*'viewer : user = pr.post_views(post_id -> user_id)'*'insert : author'*'pr._prisma_migrations: the migration tool'*'pr.owner list: a name the policy language'*)
  ok "a draft of a schema with capitals and awkward names: quoted where SQL reads it, the rest left out and said";; *) bad "draft names" "$out $draft";; esac
out=$(cd "$T/n" && python3 "$OLDPWD/cli/rowstile_cli.py" check 2>&1); rc=$?
[ $rc -eq 0 ] && ok "... which compiles" || bad "draft names compile" "$out"
out=$(cd "$T/n" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_names" apply 2>&1); rc=$?
case "$out" in *": applied") ok "... and applies";; *) bad "draft names apply" "$out";; esac
dropdb --if-exists "${DB}_names" 2>/dev/null
# shapes real apps have (Chatwoot, GitLab, Documenso, Plausible): accounts beside users, a foreign key declared
# twice, a loop of foreign keys where only orgs have owners, a membership with an id of its own: the draft takes
# users, one relation, a loop that compiles, a link; it applies, and lint finds no view written out too often
dropdb --if-exists "${DB}_apps" 2>/dev/null; createdb "${DB}_apps"
psql -X -q -v ON_ERROR_STOP=1 -d "${DB}_apps" >/dev/null <<'SQL'
CREATE SCHEMA lo;
CREATE TABLE lo.accounts (id bigserial PRIMARY KEY, name text);
CREATE TABLE lo.users (id bigserial PRIMARY KEY, account_id bigint REFERENCES lo.accounts);
CREATE TABLE lo.orgs (id bigserial PRIMARY KEY, owner_id bigint REFERENCES lo.users, settings_id bigint);
CREATE TABLE lo.settings (id bigserial PRIMARY KEY, email_id bigint);
CREATE TABLE lo.emails (id bigserial PRIMARY KEY, domain_id bigint);
CREATE TABLE lo.domains (id bigserial PRIMARY KEY, org_id bigint REFERENCES lo.orgs);
ALTER TABLE lo.orgs ADD FOREIGN KEY (settings_id) REFERENCES lo.settings;
ALTER TABLE lo.settings ADD FOREIGN KEY (email_id) REFERENCES lo.emails;
ALTER TABLE lo.emails ADD FOREIGN KEY (domain_id) REFERENCES lo.domains;
ALTER TABLE lo.emails ADD CONSTRAINT fk_again FOREIGN KEY (domain_id) REFERENCES lo.domains NOT VALID;
CREATE TABLE lo.org_memberships (id bigserial PRIMARY KEY, org_id bigint NOT NULL REFERENCES lo.orgs,
                                 user_id bigint NOT NULL REFERENCES lo.users, note text, UNIQUE (org_id, user_id));
CREATE TABLE lo.projects (id bigserial PRIMARY KEY, org_id bigint REFERENCES lo.orgs, lead_id bigint REFERENCES lo.users);
CREATE TABLE lo.tasks (id bigserial PRIMARY KEY, project_id bigint REFERENCES lo.projects, author_id bigint REFERENCES lo.users);
SQL
mkdir -p "$T/a"
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_apps" init --schema lo 2>&1)
draft=$(cat "$T/a/db/policy.authz" 2>/dev/null)
case "$draft" in *'type user = lo.users'*'type domain = lo.domains'*'membership : user = lo.org_memberships(org_id -> user_id)'*'can view = author or project.view'*)
  ok "a draft of real apps' shapes: users, not accounts; a membership with an id; each parent named once";; *) bad "draft apps" "$out $draft";; esac
[ "$(grep -c 'update domain_id after' <<<"$draft")" = 1 ] && ok "... a foreign key declared twice is one relation" || bad "draft apps: the key twice" "$draft"
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" check 2>&1); rc=$?
[ $rc -eq 0 ] && ok "... which compiles (the loop of foreign keys too)" || bad "draft apps compile" "$out"
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_apps" apply 2>&1); rc=$?
case "$out" in *": applied") ok "... and applies";; *) bad "draft apps apply" "$out";; esac
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_apps" lint 2>&1)
case "$out" in *"name others more than once"*) bad "draft apps: lint warns of views written out again" "$out";;
  *) ok "... and lint finds no permission named again and again";; esac
# round the loop as the org's owner: the domain, its address, the settings that use it, and the org
psql -X -q -d "${DB}_apps" -c "INSERT INTO lo.users (id) VALUES (1), (2);
  INSERT INTO lo.orgs (id, owner_id) VALUES (1, 1); INSERT INTO lo.domains (id, org_id) VALUES (1, 1);
  INSERT INTO lo.emails (id, domain_id) VALUES (1, 1); INSERT INTO lo.settings (id, email_id) VALUES (1, 1);
  INSERT INTO lo.orgs (id, owner_id, settings_id) VALUES (2, 2, 1)" >/dev/null
out=$(psql -X -q -At -d "${DB}_apps" -c "SET authz.user_id = '1'" -c "SELECT authz.can('domain', '1', 'edit'), authz.can('email', '1', 'edit'),
  authz.can('setting', '1', 'edit'), authz.can('org', '2', 'edit')" -c "SET authz.user_id = '2'" -c "SELECT authz.can('domain', '1', 'edit')" 2>&1 | tr '\n' ' ')
[ "$out" = "t|t|t|t f " ] && ok "... and round the loop the org's owner edits each in turn, the other owner none of them" || bad "draft apps: the loop" "$out"
dropdb --if-exists "${DB}_apps" 2>/dev/null

echo "-- the rowstile command"
mkdir -p "$T/p/tests"
sed '/^test$/,$d' example/docs.authz > "$T/p/policy.authz"     # its old test section needs the scenario's shares
cp example/docs.test.authz "$T/p/tests/docs.authz"
printf 'policy = "policy.authz"\ntests = ["tests/*.authz"]\ndatabase = "dbname=%s"\n[clients]\npy = "out/authz_client.py"\n' "$DB" > "$T/p/rowstile.toml"
( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?
case "$(cat "$T/dev.log")" in *"isn't marked as a development database"*"[AZ610]"*"nothing applied"*) [ $rc -eq 1 ] &&
  ok "dev won't push to a database with a policy that isn't marked as a development database" || bad "dev unmarked exit" "$rc";;
  *) bad "dev on an unmarked database" "$(cat "$T/dev.log")";; esac
CLI push --development example/docs.authz >/dev/null 2>&1 || bad "push --development"
( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?
case "$(cat "$T/dev.log")" in *"ok   compiles"*"applied in"*"check(s) pass"*"wrote out/authz_client.py"*) [ $rc -eq 0 ] &&
  ok "dev --once: compiles, applies, tests, writes the client" || bad "dev exit" "$rc";; *) bad "dev --once" "$(cat "$T/dev.log")";; esac
sed -i 's/can edit  = share or editor or/can edit  = share or edtor or/' "$T/p/policy.authz"
( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?
case "$(cat "$T/dev.log")" in *"policy.authz: line "*"edtor"*"nothing applied"*) [ $rc -eq 1 ] && ok "... a mistake stops it before applying, exit 1" || bad "dev mistake exit" "$rc";;
  *) bad "dev mistake" "$(cat "$T/dev.log")";; esac
run test example/docs.test.authz
case "$out" in *"ok    user \$ann can edit file \$f"*"policy tests passed"*) [ $rc -eq 0 ] && ok "test runs named test files, exit 0" || bad "test exit" "$rc";;
  *) bad "test" "$out";; esac
printf 'test "fails"\n  anyone can view file 11\n' > "$T/p/broken.authz"
run test "$T/p/broken.authz"
case "$out" in *"broken.authz line 2: anyone can view file 11"*) echo "$out" | grep -q "1 policy test(s) failed" && [ $rc -eq 1 ] &&
  ok "... and a failing one fails it, exit 1" || bad "test fail exit" "$rc";; *) bad "test fail" "$out";; esac
run can --as user:1 file 11 edit; [ "$out" = yes ] && ok "can --as user:1" || bad "can" "$out"
run explain --as user:6 file 11 view; case "$out" in "no   user 6 does not hold view on file 11"*) ok "explain --as";; *) bad "explain" "$out";; esac
run sql --as user:2 "SELECT count(*) AS n FROM app.folders"; case "$out" in *"(1 row, as user:2; rolled back)"*) ok "sql --as runs as the app role";; *) bad "sql" "$out";; esac
run sql --as user:2 "DELETE FROM app.users"; [ "$(PSQL -c "SELECT count(*) > 0 FROM app.users")" = t ] && ok "... and rolls back" || bad "sql rollback" "$out"
run explain-rule --as user:1 app.files insert --row '{"folder_id": 6, "owner_id": 2}'
case "$out" in "no   insert"*"no   owner"*) ok "explain-rule --as";; *) bad "explain-rule" "$out";; esac
[ -f "$T/i/db/policy.authz" ] && [ -f "$T/i/rowstile.toml" ] && [ -f "$T/i/db/tests/first.authz" ] && grep -q "authz.act_as" "$T/init.log" &&
  ok "init writes a policy, a test file and rowstile.toml, and says what's next" || bad "init" "$(cat "$T/init.log")"
# the note for coding agents: written with the paths init wrote; a second init leaves it as it is, and one
# in a project that has an AGENTS.md adds its section at the end
grep -q "^wrote AGENTS.md" "$T/init.log" && grep -q '^- The policy is `db/policy.authz`, its tests `db/tests/\*.authz`' "$T/i/AGENTS.md" &&
  ok "init writes AGENTS.md: where the policy is, and the loop" || bad "init AGENTS.md" "$(cat "$T/init.log" "$T/i/AGENTS.md" 2>&1)"
before=$(cksum < "$T/i/AGENTS.md")
out=$(cd "$T/i" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"kept AGENTS.md (it has rowstile's section already)"*) [ "$(cksum < "$T/i/AGENTS.md")" = "$before" ] &&
  ok "... a second init changes nothing in it" || bad "init AGENTS.md twice" "$out";; *) bad "init AGENTS.md twice" "$out";; esac
mkdir -p "$T/ag" && printf '# The app\n\nRun the tests with make.\n' > "$T/ag/AGENTS.md"
out=$(cd "$T/ag" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"added   rowstile's section to AGENTS.md"*) [ "$(head -1 "$T/ag/AGENTS.md")" = "# The app" ] && [ "$(grep -c "rowstile:begin" "$T/ag/AGENTS.md")" = 1 ] &&
  ok "... and an AGENTS.md that is there keeps its text, with the section added" || bad "init AGENTS.md added" "$(cat "$T/ag/AGENTS.md")";;
  *) bad "init AGENTS.md added" "$out";; esac

rm -r "$T"
[ -z "${KEEP:-}" ] && { dropdb "$DB"; psql -X -q -d postgres -c "DROP ROLE IF EXISTS authz_devx_other" >/dev/null 2>&1; }
if [ $fails -eq 0 ]; then echo "devx: all passed"; else echo "devx: $fails failed"; exit 1; fi
