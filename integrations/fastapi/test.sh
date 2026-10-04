#!/bin/bash
# test.sh: the Python SDK's conformance suite, against a fresh Postgres in Docker.
#   integrations/fastapi/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/fastapi/test.sh     # the app through PgBouncer in transaction mode
# (to look at: check 14 migrates it once more, so the tests run again only on a new one, which this script makes)
# Check 11 first: a fresh database, migrated with Alembic (rowstile's policy is one of the revisions), then
# the policy's tests, then Alembic's own diff, which must show no change. Then the other checks (pytest).
set -u
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-py
PORT=${CONFORMANCE_PORT:-25440}      # below 49152: above it Windows reserves ranges for itself, and Docker can't publish there
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the database: not a superuser, as on managed Postgres
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_URL="postgresql+psycopg://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_OWNER_DSN="postgresql://conf_owner:owner@localhost:$PORT/conf"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_URL="postgresql+asyncpg://conf_app:app@localhost:$APP_PORT/conf"
rc=0
uv run --quiet alembic upgrade head || { echo "FAIL  11: alembic upgrade head"; rc=1; }
uv run --quiet rowstile test >/tmp/conformance-policy-tests.log 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat /tmp/conformance-policy-tests.log; echo "FAIL  11: policy tests"; rc=1; }
uv run --quiet alembic check >/tmp/conformance-alembic-check.log 2>&1 &&
  echo "ok    11: ... and Alembic's own diff shows no change" || { cat /tmp/conformance-alembic-check.log; echo "FAIL  11: alembic check"; rc=1; }
uv run --quiet rowstile migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
uv run --quiet pytest -q -p no:cacheprovider "$@" || rc=1
[ -n "${KEEP:-}" ] || { [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"; docker rm -f "$NAME" >/dev/null; }
exit $rc
