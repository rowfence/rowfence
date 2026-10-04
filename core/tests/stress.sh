#!/bin/bash
# stress.sh: 16 clients writing a folder tree at once (create, move, link, unlink, delete, at random places)
# for SECONDS seconds at each isolation level, retrying 40001/40P01 as an app would; afterwards the
# inheritance tables must match a rebuild (authz.verify()). Moves that would make a loop, and deletes of
# folders that still hold something, are refused and count as done.
#   PGHOST=... PGUSER=postgres tests/stress.sh [SECONDS]   (default 60 per isolation level)
set -u
cd "$(dirname "$0")/.."
DB=authz_stress
SECONDS_EACH=${1:-60}
fails=0
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
python3 compile_policy.py example/docs.authz > "/tmp/${DB}_docs.sql" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "/tmp/${DB}_docs.sql" >/dev/null || exit 1
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" >/dev/null <<'SQL' || exit 1
SET client_min_messages = warning;
-- 2,000 more folders under the example's, each under a random earlier one; 100 of them also linked elsewhere
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
SELECT i, 1, CASE WHEN i = 100 THEN 1 ELSE 100 + floor(random() * (i - 100))::int END, 1, 'f' || i
FROM generate_series(100, 2099) i;
INSERT INTO app.folder_links SELECT DISTINCT 100 + floor(random() * 2000)::int, 100 + floor(random() * 2000)::int
FROM generate_series(1, 100) ON CONFLICT DO NOTHING;
DELETE FROM app.folder_links WHERE folder_id = parent_id;
SELECT setval(pg_get_serial_sequence('app.folders', 'id'), 1000000);
CREATE SCHEMA stress;
-- runs a write; refusals that are part of the game (a loop, a folder that isn't empty, a duplicate) are fine,
-- while 40001 and 40P01 go back to pgbench, which retries the transaction
CREATE FUNCTION stress.try(stmt text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE stmt;
EXCEPTION WHEN check_violation OR foreign_key_violation OR unique_violation THEN NULL;
END $$;
SQL
W=$(mktemp -d)
cat > "$W/create.sql" <<'EOF'
\set p random(100, 2099)
SELECT stress.try(format('INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, %s, 1, %L)', :p, 'new'));
EOF
cat > "$W/move.sql" <<'EOF'
\set m random(101, 2099)
\set t random(100, 2099)
SELECT stress.try(format('UPDATE app.folders SET parent_id = %s WHERE id = %s', :t, :m));
EOF
cat > "$W/link.sql" <<'EOF'
\set m random(101, 2099)
\set t random(100, 2099)
SELECT stress.try(format('INSERT INTO app.folder_links VALUES (%s, %s) ON CONFLICT DO NOTHING', :m, :t));
EOF
cat > "$W/unlink.sql" <<'EOF'
\set m random(101, 2099)
DELETE FROM app.folder_links WHERE folder_id = :m;
EOF
cat > "$W/delete.sql" <<'EOF'
\set m random(101, 2099)
SELECT stress.try(format('DELETE FROM app.folders WHERE id = %s', :m));
EOF
cat > "$W/pair.sql" <<'EOF'
-- two writes in one transaction, so locks are taken across statements (the deadlock case)
\set m random(101, 2099)
\set t random(100, 2099)
\set p random(100, 2099)
BEGIN;
SELECT stress.try(format('UPDATE app.folders SET parent_id = %s WHERE id = %s', :t, :m));
SELECT stress.try(format('INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, %s, 1, %L)', :p, 'new'));
COMMIT;
EOF

for level in "read committed" "repeatable read" "serializable"; do
  # (PGOPTIONS splits on spaces: "read committed" needs its space escaped)
  PGOPTIONS="-c default_transaction_isolation=${level// /\\ } -c statement_timeout=120s" pgbench -n -d "$DB" -c 16 -j 4 \
    -T "$SECONDS_EACH" --max-tries=50 -f "$W/create.sql@4" -f "$W/move.sql@2" -f "$W/link.sql@1" \
    -f "$W/unlink.sql@1" -f "$W/delete.sql@1" -f "$W/pair.sql@1" > "$W/out" 2>&1
  tps=$(sed -n 's/^tps = \([0-9.]*\) .*/\1/p' "$W/out")
  retried=$(sed -n 's/^number of transactions retried: \([0-9]*\).*/\1/p' "$W/out")
  failed=$(sed -n 's/^number of failed transactions: \([0-9]*\).*/\1/p' "$W/out")
  aborted=$(grep -c "aborted in command" "$W/out")
  if [ -z "$tps" ]; then
    echo "FAIL  $level: pgbench didn't run: $(head -c 300 "$W/out" | tr '\n' ' ')"; fails=$((fails + 1)); continue
  fi
  echo "info  $level: $tps writes/s for ${SECONDS_EACH}s, ${retried:-0} retried, ${failed:-0} failed after 50 tries, $aborted clients stopped"
  [ "$aborted" = 0 ] || { echo "FAIL  $level: a client stopped on an error: $(grep -m1 "aborted in command" -A2 "$W/out" | tr '\n' ' ')"; fails=$((fails + 1)); }
  if [ "$(psql -X -At -d "$DB" -c "SELECT authz.verify()")" = t ]; then
    echo "ok    $level: the inheritance tables match a rebuild"
  else
    echo "FAIL  $level: the inheritance tables don't match a rebuild"; fails=$((fails + 1))
  fi
done

rm -rf "$W"
[ -z "${KEEP:-}" ] && dropdb "$DB"
if [ $fails -eq 0 ]; then echo "stress: all passed"; else echo "stress: $fails failed"; exit 1; fi
