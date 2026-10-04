#!/bin/bash
# test.sh: the file manager's tests, against Postgres and RustFS in containers.
#   examples/filemanager/test.sh          # starts db and storage (docker compose), migrates, runs the tests
#   KEEP=1 examples/filemanager/test.sh   # leaves the containers running afterwards
# Also checks that the generated client matches the applied policy, and that the app uses only
# rowfence's public surface (check_public_surface.py).
set -u
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
export FM_ADMIN_URL=postgresql://postgres:postgres@localhost:25432/filemanager FM_APP_PASSWORD=fm_app
export FM_DATABASE_URL=postgresql://fm_app:fm_app@localhost:25432/filemanager
export FM_S3_ENDPOINT=http://localhost:29000
python3 check_public_surface.py || exit 1
# every change to db/policy.authz has its migration (rowfence migrate writes it)
python3 ../../core/cli/rowfence_cli.py migrate --check || exit 1
docker compose down -v >/dev/null 2>&1        # a new database each time: migrations run from the start
docker compose up -d --build --wait db storage || exit 1
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
