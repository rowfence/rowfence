#!/bin/bash
# The messenger's tests: the database (rowfence from this repository) in Docker, the API tests on the host.
#   examples/messenger/test.sh [pytest args]     KEEP=1 leaves the database running
set -u
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
export MS_ADMIN_URL=postgresql://postgres:postgres@localhost:25433/messenger MS_APP_PASSWORD=ms_app
export MS_DATABASE_URL=postgresql://ms_app:ms_app@localhost:25433/messenger
python3 check_public_surface.py || exit 1
# every change to db/policy.authz has its migration (rowfence migrate writes it)
python3 ../../core/cli/rowfence_cli.py migrate --check || exit 1
docker compose down -v >/dev/null 2>&1        # a new database each time: migrations run from the start
docker compose up -d --build --wait db || exit 1
cd backend
rc=0
uv run python ../db/migrate.py --client || exit 1
if ! git diff --quiet -- app/authz_client.py; then
  echo "app/authz_client.py was out of date with db/policy.authz (now rewritten: commit it)"; rc=1
fi
# the policy's own tests (db/tests/*.authz, named in rowfence.toml), then the API
uv run python ../../../core/cli/rowfence_cli.py test || rc=1
uv run pytest -q "$@" || rc=1
cd ..
[ -n "${KEEP:-}" ] || docker compose down
exit $rc
