#!/bin/bash
# races.sh: every pair of tree writes (create, move, link, unlink, delete) raced in two sessions, at each
# isolation level, in two ways: the second waits for the first's locks ("wait"), or took its snapshot
# before the first committed ("stale"). After each race the inheritance tables must match a rebuild
# (authz.verify()), and the only errors allowed are 40001 (serialization) and 40P01 (deadlock): the
# retryable ones. Each race gets its own small subtree, so nothing is reset between.
#   PGHOST=... PGUSER=postgres tests/races.sh
# (Written for narrower tree locks too, where it also races small and type-wide locks against each other;
# tree writes take the type-wide lock.)
set -u
cd "$(dirname "$0")/.."
DB=authz_races
b1=""; b2=""   # (extra statements per session; the narrow-locks branch uses them to pick the lock kind)
fails=0; n=0; retryable=0; waited=0
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
python3 authzc.py example/docs.authz > "/tmp/${DB}_docs.sql" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "/tmp/${DB}_docs.sql" >/dev/null || exit 1
T=$(mktemp -d)

# the write of kind $1 in the subtree at $2, by session $3 (1 or 2): r = $2, a = r+1 and b = r+2 under r,
# c = r+3 under a (and linked into b), l = r+4 under b
op() {
  local b=$2
  case $1 in
    create) echo "INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES ($((b + 4 + $3)), 1, $((b + 3)), 1, 'new');";;
    move)   echo "UPDATE app.folders SET parent_id = $((b + 2)) WHERE id = $((b + 1));";;
    link)   echo "INSERT INTO app.folder_links VALUES ($((b + 1)), $((b + 2))) ON CONFLICT DO NOTHING;";;
    unlink) echo "DELETE FROM app.folder_links WHERE folder_id = $((b + 3)) AND parent_id = $((b + 2));";;
    delete) echo "DELETE FROM app.folders WHERE id = $((b + 4));";;
  esac
}
setup() {
  local b=$1
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -c "INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES
    ($b, 1, 1, 1, 'r'), ($((b + 1)), 1, $b, 1, 'a'), ($((b + 2)), 1, $b, 1, 'b'),
    ($((b + 3)), 1, $((b + 1)), 1, 'c'), ($((b + 4)), 1, $((b + 2)), 1, 'l')" \
    -c "INSERT INTO app.folder_links VALUES ($((b + 3)), $((b + 2)))" >/dev/null || exit 1
}
# errors other than the retryable ones
bad_errors() { grep "ERROR" "$@" | grep -v "could not serialize access\|deadlock detected" ; }

for level in "read committed" "repeatable read" "serializable"; do
  for pattern in wait stale; do
    for k1 in create move link unlink delete; do
      for k2 in create move link unlink delete; do
        n=$((n + 1)); b=$((10000 + n * 10))
        setup $b
        if [ $pattern = wait ]; then
          # the first holds its locks for a while; the second arrives meanwhile
          printf "BEGIN ISOLATION LEVEL %s;\n%s\n%s\nSELECT pg_sleep(0.4);\nCOMMIT;\n" "$level" "$b1" "$(op $k1 $b 1)" \
            | psql -X -q -d "$DB" > "$T/1" 2>&1 &
          sleep 0.15
          start=$(date +%s%N)
          printf "BEGIN ISOLATION LEVEL %s;\n%s\n%s\nCOMMIT;\n" "$level" "$b2" "$(op $k2 $b 2)" | psql -X -q -d "$DB" > "$T/2" 2>&1
          [ $(( ($(date +%s%N) - start) / 1000000 )) -gt 150 ] && waited=$((waited + 1))
          wait
        else
          # the second takes its snapshot, the first commits, then the second writes
          printf "BEGIN ISOLATION LEVEL %s;\n%s\nSELECT count(*) FROM app.folders;\nSELECT pg_sleep(0.3);\n%s\nCOMMIT;\n" \
            "$level" "$b2" "$(op $k2 $b 2)" | psql -X -q -d "$DB" > "$T/2" 2>&1 &
          sleep 0.1
          printf "BEGIN;\n%s\n%s\nCOMMIT;\n" "$b1" "$(op $k1 $b 1)" | psql -X -q -d "$DB" > "$T/1" 2>&1
          wait
        fi
        grep -q "could not serialize access\|deadlock detected" "$T/1" "$T/2" && retryable=$((retryable + 1))
        what="$level, $pattern: $k1 then $k2"
        if [ -n "$(bad_errors "$T/1" "$T/2")" ]; then
          echo "FAIL  $what: $(bad_errors "$T/1" "$T/2" | head -2 | tr '\n' ' ')"; fails=$((fails + 1))
        elif [ "$(psql -X -At -d "$DB" -c "SELECT authz.verify()")" != t ]; then
          echo "FAIL  $what: the inheritance tables don't match a rebuild"; fails=$((fails + 1))
          psql -X -q -d "$DB" -c "SELECT authz_int.\"folder__parent__tree_rebuild\"(), authz_int.\"folder__linked_into_parent__tree_rebuild\"()" >/dev/null
        fi
      done
    done
  done
  echo "ok    $level: 50 races, inheritance tables exact after each"
done
echo "info  $n races: $retryable ended in a retryable error (40001/40P01), $waited second writers waited for the first"
[ $waited -gt 0 ] && echo "ok    overlapping writes wait for each other" || { echo "FAIL  no write ever waited"; fails=$((fails + 1)); }

rm -rf "$T"
dropdb "$DB"
if [ $fails -eq 0 ]; then echo "races: all passed"; else echo "races: $fails failed"; exit 1; fi
