#!/bin/bash
# sessions.sh: signed sessions: authz.user_id and the other settings are plain settings anyone
# may set. Only the signature authz.act_as() and the logins make keeps the app role from choosing its own
# user by setting them, widening its scopes, or reusing a sign-in in another transaction or on another
# connection.
#   PGHOST=... PGUSER=postgres tests/sessions.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_sessions}
APP=authz_sess_app          # logs in, a member of app_user
OTHER=authz_sess_other      # logs in, not a member of app_user
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
# as $APP (or $ROLE), in one transaction: the last line of output, or the error's SQLSTATE
as() { psql -X -q -At -1 -U "${ROLE:-$APP}" -d "$DB" -v VERBOSITY=sqlstate "$@" 2>&1 | tail -n 1; }
expect() {   # $1 label, $2 expected (an SQLSTATE for errors), rest: psql arguments
  local label=$1 want=$2; shift 2
  local got; got=$(as "$@"); got=${got#ERROR:  }
  [ "$got" = "$want" ] && ok "$label" || bad "$label" "expected '$want', got '$got'"
}
ACT() { echo "DO \$\$ BEGIN PERFORM authz.act_as($1); END \$\$"; }

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
python3 cli/rowstile_cli.py --db "dbname=$DB" apply example/docs.authz >/dev/null 2>&1 || { bad "apply"; exit 1; }
for r in $APP $OTHER; do psql -X -q -d postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
psql -X -q -d postgres -c "CREATE ROLE $APP LOGIN IN ROLE app_user" -c "ALTER ROLE $APP SET jit = off" \
     -c "CREATE ROLE $OTHER LOGIN" >/dev/null
PSQL -c "GRANT USAGE ON SCHEMA app, authz TO $OTHER" -c "GRANT EXECUTE ON FUNCTION authz.connection_check() TO $OTHER" >/dev/null
# erin shares the Company folder with the org, as in tests/adversarial.sh
PSQL -c "SET ROLE app_user; SET authz.user_id = 5; SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" >/dev/null
# what carol (user 3) sees, as the owner says it: the owner's and superusers' sessions may set it
carol=$(PSQL -c "SET ROLE app_user" -c "SET authz.user_id = 3" -c "SELECT count(*) FROM app.files")
all=$(PSQL -c "SELECT count(*) FROM app.files")
[ "$carol" -gt 0 ] && [ "$carol" -lt "$all" ] && ok "the owner's session sets authz.user_id and is believed (carol sees $carol of $all)" ||
  bad "setup" "$carol of $all"

echo "-- the settings are anyone's to set"
expect "the app's login role sets authz.user_id, and Postgres doesn't stop it" "t" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT current_setting('authz.user_id') = '1'"
expect "... but nobody signed in is an error, not an empty result" "28000" -c "SELECT count(*) FROM app.files"
expect "... and so is a user set directly" "28000" -c "SET LOCAL authz.user_id = 1" -c "SELECT count(*) FROM app.files"

echo "-- signing in"
expect "authz.act_as signs carol in: she sees her files" "$carol" -c "$(ACT "'user', '3'")" -c "SELECT count(*) FROM app.files"
expect "act_as(NULL, NULL): nobody, on purpose, no error" "0" -c "$(ACT "NULL, NULL")" -c "SELECT count(*) FROM app.files WHERE id = 12"
expect "changing authz.user_id after signing in is an error" "28000" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT count(*) FROM app.files"
expect "... authz.principal_type too" "28000" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.principal_type = 'user'" \
  -c "SELECT count(*) FROM app.files"
expect "... authz.acting_user too" "28000" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.acting_user = 'x'" \
  -c "SELECT authz.share('file', 11, 'viewer', 'user', 4)"
expect "a forged signature is an error" "28000" -c "SET LOCAL authz.user_id = 1" -c "SET LOCAL authz.session = 'deadbeef'" \
  -c "SELECT count(*) FROM app.files"
expect "sharing as a chosen user is refused" "28000" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT authz.share('folder', 1, 'viewer', 'user', 3)"
expect "... and so is asking can() as one" "28000" -c "$(ACT "'user', '3'")" -c "SET LOCAL authz.user_id = 1" \
  -c "SELECT authz.can('folder', 5, 'view')"

echo "-- a signature is good for one transaction on one connection"
got=$(psql -X -q -At -U "$APP" -d "$DB" -v VERBOSITY=sqlstate 2>&1 <<'SQL' | tail -n 1
BEGIN;
SELECT authz.act_as('user', '1');
SELECT current_setting('authz.session') AS sig \gset
COMMIT;
BEGIN;
SET LOCAL authz.user_id = 1;
SELECT set_config('authz.session', :'sig', true);
SELECT count(*) FROM app.files;
COMMIT;
SQL
)
[ "$got" = "ERROR:  28000" ] && ok "a signature from an earlier transaction is refused in the next one" || bad "replay in the next transaction" "$got"
sig=$(psql -X -q -At -U "$APP" -d "$DB" -c "BEGIN" -c "SELECT authz.act_as('user', '1')" -c "SELECT current_setting('authz.session')" -c "COMMIT" | tail -n 1)
expect "... and one from another connection too" "28000" -c "SET LOCAL authz.user_id = 1" -c "SELECT set_config('authz.session', '$sig', true)" \
  -c "SELECT count(*) FROM app.files"
got=$(psql -X -q -At -U "$APP" -d "$DB" -v VERBOSITY=sqlstate 2>&1 <<'SQL' | tail -n 1
BEGIN;
SELECT authz.act_as('user', '3');
SAVEPOINT s;
SELECT authz.act_as('user', '1');
ROLLBACK TO SAVEPOINT s;
SELECT count(*) FROM app.files;
COMMIT;
SQL
)
[ "$got" = "$carol" ] && ok "a sign-in rolled back with a savepoint gives back the one before it" || bad "savepoint" "$got"

echo "-- keys and scopes"
key=$(PSQL -c "SET authz.user_id = 3" -c "SELECT authz.create_api_key('sessions test', 'read')" | tail -n 1)
expect "a read-only key signs carol in" "$carol" -c "SELECT authz.login_key('$key') IS NOT NULL" -c "SELECT count(*) FROM app.files"
expect "... and can't write" "UPDATE 0" -c "SELECT authz.login_key('$key') IS NOT NULL" -c "\\set QUIET off" \
  -c "UPDATE app.files SET name = name WHERE id = 11"
expect "clearing its scopes is an error, not a way to write" "28000" -c "SELECT authz.login_key('$key') IS NOT NULL" \
  -c "SET LOCAL authz.scopes = ''" -c "UPDATE app.files SET name = name WHERE id = 11"
expect "who_among isn't a way out of a key's scopes" "42501" -c "SELECT authz.login_key('$key') IS NOT NULL" \
  -c "SELECT count(*) FROM authz.who_among('file', '11', 'view', ARRAY['1', '2'])"

echo "-- rowstile's own functions switch users and sign again"
alice=$(as -c "$(ACT "'user', '1'")" -c "SELECT count(*) FROM app.files")
expect "who checks each person, and alice is still signed in afterwards" "$alice" -c "$(ACT "'user', '1'")" \
  -c "SELECT count(*) > 0 FROM authz.who('file', '11', 'view')" -c "SELECT count(*) FROM app.files"
expect "explain for carol, then alice again" "$alice" -c "$(ACT "'user', '1'")" \
  -c "SELECT count(*) > 0 FROM authz.explain('file', '11', 'view', '3')" -c "SELECT count(*) FROM app.files"
want=$(for u in 1 2 3 4 5; do [ "$(as -c "$(ACT "'user', '$u'")" -c "SELECT authz.can('file', 11, 'view')")" = t ] && printf '%s,' $u; done)
expect "who_among asks each one in turn" "${want%,}" -c "$(ACT "'user', '3'")" \
  -c "SELECT string_agg(x, ',' ORDER BY x) FROM authz.who_among('file', '11', 'view', ARRAY['1', '2', '3', '4', '5']) x"
expect "... and leaves carol signed in" "$carol" -c "$(ACT "'user', '3'")" \
  -c "SELECT count(*) FROM authz.who_among('file', '11', 'view', ARRAY['1', '2'])" -c "SELECT count(*) FROM app.files"

echo "-- what is wrong with a connection (authz.connection_check)"
expect "the app's role: nothing to report" "0" -c "SELECT count(*) FROM authz.connection_check()"
got=$(PSQL -c "SELECT string_agg(severity || ': ' || problem, '; ') FROM authz.connection_check()")
case "$got" in *"error: $(PSQL -c "SELECT current_user") owns app."*" owners skip row-level security"*|"error: "*" is a superuser"*)
  ok "the owner's connection: an error";; *) bad "owner connection" "$got";; esac
if [ -n "${PGSUPERUSER:-}" ]; then
  got=$(PSQL -U "$PGSUPERUSER" -c "SELECT string_agg(severity || ': ' || problem, '; ') FROM authz.connection_check()")
  case "$got" in "error: $PGSUPERUSER is a superuser"*) ok "a superuser's connection: an error";; *) bad "superuser connection" "$got";; esac
fi
ROLE=$OTHER expect "a role the policy doesn't govern: an error" "t" \
  -c "SELECT bool_or(severity = 'error' AND problem LIKE '%is not the policy''s app role app_user%') FROM authz.connection_check()"
got=$(PSQL -c "SET ROLE app_user" -c "SELECT string_agg(problem, '; ') FROM authz.connection_check() WHERE severity = 'error'")
case "$got" in "this connection logs in as $(PSQL -c "SELECT current_user"), a superuser, BYPASSRLS or the policy's owner, and switched to app_user: RESET ROLE leaves row-level security"*)
  ok "the owner's login, switched to the app role: an error (RESET ROLE, and settings believed unsigned)";; *) bad "owner as app role" "$got";; esac
if [ -n "${PGSUPERUSER:-}" ]; then
  got=$(PSQL -U "$PGSUPERUSER" -c "SET ROLE app_user" -c "SELECT count(*) FROM authz.connection_check() WHERE problem LIKE 'this connection logs in as $PGSUPERUSER, %'")
  [ "$got" = 1 ] && ok "... and a superuser's" || bad "superuser as app role" "$got"
fi
expect "a login in the app role: no errors" "0" -c "SELECT count(*) FROM authz.connection_check() WHERE severity = 'error'"
expect "... nor after SET ROLE app_user" "0" -c "SET ROLE app_user" -c "SELECT count(*) FROM authz.connection_check() WHERE severity = 'error'"
PSQL -c "ALTER TABLE app.files DISABLE ROW LEVEL SECURITY"
expect "row-level security off on a table with rules: an error" "row-level security is off on app.files: the policy's rules don't apply to it"   -c "SELECT problem FROM authz.connection_check() WHERE severity = 'error'"
PSQL -c "ALTER TABLE app.files ENABLE ROW LEVEL SECURITY"

echo "-- who may sign in whom"
expect "the key is out of the app role's reach" "42501" -c "SELECT value FROM authz.settings WHERE key = 'session_key'"
expect "... and so is the signing" "42501" -c "SELECT authz_int.session_sig()"
ROLE=$OTHER expect "a role that isn't the app role can't act_as" "42501" -c "$(ACT "'user', '1'")"
expect "act_as names only types that sign in" "22023" -c "$(ACT "'folder', '1'")"

PSQL -c "REVOKE ALL ON SCHEMA app, authz FROM $OTHER" -c "REVOKE ALL ON FUNCTION authz.connection_check() FROM $OTHER" >/dev/null 2>&1
dropdb "$DB"
for r in $APP $OTHER; do psql -X -q -d postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
[ $fails -eq 0 ] && echo "sessions: all passed" || { echo "sessions: $fails failed"; exit 1; }
