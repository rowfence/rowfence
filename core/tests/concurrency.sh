#!/bin/bash
# concurrency.sh: two sessions changing the folder tree at the same time.
#   PGHOST=... PGPORT=... PGUSER=... tests/concurrency.sh [database]
# Each case resets the example app, races two psql sessions, then checks that
# the closure tables still match a rebuild and that no loop slipped through.
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_concurrency}
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
out=$(mktemp)
python3 authzc.py example/docs.authz > "/tmp/${DB}_docs.sql" || exit 1

reset() {
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null 2>&1 &&
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "/tmp/${DB}_docs.sql" >/dev/null 2>&1 || { echo "setup failed"; exit 1; }
}
check() {   # $1 = label, $2 = SQL that must return t
  if [ "$(psql -X -Atq -d "$DB" -c "$2")" = "t" ]; then echo "ok    $1"; else echo "FAIL  $1"; fails=$((fails + 1)); fi
}
expect_in_a() {   # $1 = label, $2 = text session A must have printed
  if grep -q "$2" "$out"; then echo "ok    $1"; else echo "FAIL  $1 (session A said: $(tr '\n' ' ' < "$out"))"; fails=$((fails + 1)); fi
}

echo "-- 1. REPEATABLE READ: add a folder under a folder someone else just moved"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;   -- snapshot taken here
SELECT pg_sleep(1.5);
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (60, 1, 4, 1, 'under Design');
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 4"   # Design into Globex
wait
expect_in_a "the late writer gets a serialization error (the app retries)" "could not serialize access"
check "inheritance tables match a rebuild" "SELECT authz.verify()"
check "no stale folder 60" "SELECT NOT EXISTS (SELECT 1 FROM app.folders WHERE id = 60)"

echo "-- 2. REPEATABLE READ: two moves that together would make a loop"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT count(*) FROM app.folders;
SELECT pg_sleep(1.5);
UPDATE app.folders SET parent_id = 2 WHERE id = 4;   -- Design into Handbook
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 4 WHERE id = 2"   # Handbook into Design
wait
expect_in_a "the late writer gets a serialization error" "could not serialize access"
check "inheritance tables match a rebuild" "SELECT authz.verify()"
check "no loop" "SELECT NOT (EXISTS (SELECT 1 FROM app.folders WHERE id = 4 AND parent_id = 2)
                             AND EXISTS (SELECT 1 FROM app.folders WHERE id = 2 AND parent_id = 4))"

echo "-- 3. READ COMMITTED: the same two moves"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN;
UPDATE app.folders SET parent_id = 2 WHERE id = 4;
SELECT pg_sleep(1.5);
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 4 WHERE id = 2" > "$out.b" 2>&1
wait
if grep -q "cannot be moved inside itself" "$out.b"; then echo "ok    the second move waits, then is refused"; else echo "FAIL  second move: $(cat "$out.b")"; fails=$((fails + 1)); fi
check "inheritance tables match a rebuild" "SELECT authz.verify()"

echo "-- 4. READ COMMITTED: unrelated moves at the same time both succeed"
reset
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN;
UPDATE app.folders SET parent_id = 2 WHERE id = 4;
SELECT pg_sleep(1);
COMMIT;
SQL
sleep 0.3
psql -X -q -d "$DB" -c "UPDATE app.folders SET parent_id = 20 WHERE id = 6" > "$out.b" 2>&1
wait
check "both moves are in" "SELECT (SELECT parent_id FROM app.folders WHERE id = 4) = 2 AND (SELECT parent_id FROM app.folders WHERE id = 6) = 20"
check "inheritance tables match a rebuild" "SELECT authz.verify()"

echo "-- 5. sharing a file while someone deletes it"
reset
psql -X -q -d "$DB" -c "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (40, 4, 1, 'doomed.md')"
psql -X -q -d "$DB" > "$out" 2>&1 <<'SQL' &
BEGIN;
DELETE FROM app.files WHERE id = 40;
SELECT pg_sleep(1.5);
COMMIT;
SQL
sleep 0.5
psql -X -q -d "$DB" -c "SET ROLE app_user; SET authz.user_id = 1; SELECT authz.share('file', 40, 'viewer', 'user', 4)" > "$out.b" 2>&1
wait
if grep -q "you cannot share file 40" "$out.b"; then echo "ok    the share waits for the delete, then is refused"; else echo "FAIL  share: $(cat "$out.b")"; fails=$((fails + 1)); fi
check "no share is left on the deleted id" "SELECT NOT EXISTS (SELECT 1 FROM authz.shares WHERE object_type = 'file' AND object_id = '40')"

rm -f "$out" "$out.b"
dropdb "$DB"
if [ $fails -eq 0 ]; then echo "concurrency: all passed"; else echo "concurrency: $fails failed"; exit 1; fi
