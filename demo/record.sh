#!/bin/bash
# record.sh: records the demo (demo.tape) into demo/out/demo.gif and demo.mp4, in containers.
#
#   demo/record.sh            # then look at demo/out/, and copy demo.gif over demo/demo.gif if it is the one
#
# What it shows is real: a Postgres container holds the app of docs/getting-started.md (its tables, its rows,
# one share), a folder holds that guide's policy and tests as a git repository, and the tape types the
# commands of this checkout in it. So the recording is made again after any change to what the commands print:
# at each release, at least.
# Needs Docker, bash and Python (Git Bash works on Windows). About three minutes, and longer the first time:
# the recorder's image is 3 GB.
set -eu
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
REPO=$(pwd -W 2>/dev/null || pwd)
NET=rowstile-demo
PG=rowstile-demo-pg
PYTHON=$(command -v python3 || command -v python)
WORK=$(mktemp -d)
# as Docker and a Windows Python name it (Git Bash: C:/..., not /tmp/...)
WORK_W=$(cd "$WORK" && (pwd -W 2>/dev/null || pwd))
mkdir -p demo/out

cleanup() {
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK" "$WORK.sql"
}
trap cleanup EXIT
docker rm -f "$PG" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true

# the recorder, with git (the review reads the base branch's policy from it), and Postgres with the command
docker build -q -t rowstile-demo-vhs demo >/dev/null
docker image inspect rowstile:16 >/dev/null 2>&1 ||
  docker build -q -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile . >/dev/null

# the project: the guide's policy and tests, committed on main
"$PYTHON" demo/files.py "$WORK_W" "$WORK_W.sql"
(cd "$WORK" && git init -q -b main . && git config core.autocrlf false && git add -A &&
  git -c user.name=demo -c user.email=demo@example.com commit -q -m "the policy and its tests")

# the database: the guide's tables and rows
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" -e POSTGRES_HOST_AUTH_METHOD=trust rowstile:16 >/dev/null
for _ in $(seq 30); do docker exec "$PG" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
docker exec "$PG" psql -X -q -U postgres -c "CREATE DATABASE notes" >/dev/null
docker exec -i "$PG" psql -X -q -U postgres -d notes -v ON_ERROR_STOP=1 < "$WORK.sql" >/dev/null
URL="postgres://postgres@$PG/notes"
# main's policy in force, and one share: the writers (bo's team) are viewers of the project
docker run --rm --network "$NET" -v "$REPO:/repo:ro" -v "$WORK_W:/work" -w /work -e DATABASE_URL="$URL" \
  --entrypoint bash rowstile-demo-vhs -c 'git config --global --add safe.directory /work && /repo/core/cli/rowstile push'
docker exec -i "$PG" psql -X -q -U postgres -d notes -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
SET authz.user_id = '1';
SELECT authz.share('project', '1', 'viewer', 'team', '10', 'member');
SQL

docker run --rm --network "$NET" -v "$REPO:/repo:ro" -v "$WORK_W:/work" -v "$REPO/demo/out:/out" -w /out \
  -v "$REPO/demo/demo.tape:/demo.tape:ro" -e DATABASE_URL="$URL" rowstile-demo-vhs /demo.tape
ls -l demo/out
