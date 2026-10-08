#!/bin/bash
# ci.sh: every test, on every supported PostgreSQL version, each in its own container.
#   core/ci.sh                 # PostgreSQL 16, 17 and 18, run_tests.sh --quick in each
#   core/ci.sh --full 16       # the full run_tests.sh, on 16 only
#   core/ci.sh --proofs 16     # the race and stress tests (short), on 16 only
#   core/ci.sh --short 17 18   # what depends on the version (run_tests.sh --short), on 17 and 18
#   SOAK_SEED=N core/ci.sh --soak 16   # the random checks, long, with a new seed (run_tests.sh --soak)
#   ROWSTILE_PART=command core/ci.sh 16   # one part of a run (run_tests.sh names them): CI runs the parts side by side
# Needs Docker and bash (Git Bash works on Windows). Builds rowstile:<version> from Dockerfile,
# mounts the repository, runs the tests in it and removes the container. Exit status: 0 only if
# every version passed.
set -u
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1           # Git Bash: don't rewrite /src into a Windows path
REPO=$(pwd -W 2>/dev/null || pwd)
MODE=--quick
case "${1:-}" in --full) MODE=""; shift;; --proofs) MODE=--proofs; shift;; --short) MODE=--short; shift;; --soak) MODE=--soak; shift;; esac
VERSIONS=${*:-16 17 18}
# how long one version's suites may take, on the clock: two hours; the soak three and a half (its random
# policies alone may take one, and it shares the machine with the night's other jobs)
LIMIT=7200; [ "$MODE" = --soak ] && LIMIT=12600
failed=()
# where the logs go: /tmp, or ROWSTILE_CI_LOGS (CI gives each job its own: self-hosted runners may share a machine)
LOGS=${ROWSTILE_CI_LOGS:-/tmp}
name=""
# with Docker Desktop, each docker command in WSL crosses to the engine over a link that drops connections held
# long under load: the suites run detached, and write their log and exit code into the mounted checkout (.ci/)
mkdir -p .ci
# a docker command, again when the link to the engine fails (up to 5 tries)
retry() { local n; for n in 1 2 3 4 5; do "$@" && return 0; sleep $((n * 2)); done; return 1; }
# a run stopped half way (Ctrl-C, a cancelled CI job) removes its container too, and the database's volume
trap '[ -z "$name" ] || docker rm -f -v "$name" >/dev/null 2>&1' EXIT
trap 'exit 130' INT TERM
for v in $VERSIONS; do
  echo "=== PostgreSQL $v"
  if ! docker build -q -t "rowstile:$v" --build-arg "PG_MAJOR=$v" -f core/Dockerfile . >/dev/null; then
    echo "--- FAILED: building the image"; failed+=("$v (build)"); continue
  fi
  name="rowstile-ci-$v-$$"
  # labelled with the job (ROWSTILE_CI_JOB in CI), whose cleanup removes only its own
  # The server doesn't wait for the disk: the databases last as long as the container, and no suite stops the
  # server to see what it kept. What the suites check is the same, sooner (they make and drop many databases).
  retry docker run -d --name "$name" --label "rowstile.ci=${ROWSTILE_CI_JOB:-local}" -e POSTGRES_HOST_AUTH_METHOD=trust -v "$REPO:/src" "rowstile:$v" \
    -c fsync=off -c synchronous_commit=off -c full_page_writes=off >/dev/null || { failed+=("$v (start)"); continue; }
  for _ in $(seq 60); do docker exec "$name" pg_isready -q -h /var/run/postgresql 2>/dev/null && break; sleep 1; done
  sleep 2                              # the image's entrypoint restarts the server once after initdb
  out=".ci/$name"; rm -f "$out.log" "$out.rc"
  retry docker exec -d -e SOAK_SEED="${SOAK_SEED:-}" -e ROWSTILE_PART="${ROWSTILE_PART:-}" -e PGHOST=/var/run/postgresql -e PGUSER=postgres -w /src/core "$name" \
    bash -c "bash run_tests.sh $MODE > /src/$out.log 2>&1; echo \$? > /src/$out.rc" || { failed+=("$v (start)"); continue; }
  # the exit code appears when the suites end; a container that stopped or went first ends the wait too, and so
  # does the limit
  started=$SECONDS; why=""
  while [ ! -f "$out.rc" ]; do
    sleep 5; waited=$((SECONDS - started))
    [ -f "$out.rc" ] && break
    state=$(retry docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null) || state="not there"
    if [ "$state" != true ]; then why="the container stopped before the suites ended (running: $state, after ${waited}s)"
    elif [ "$waited" -ge "$LIMIT" ]; then why="the suites were still running after ${waited}s (the limit is ${LIMIT}s): stopped there"
    else continue; fi
    [ -f "$out.rc" ] && { why=""; break; }
    echo 1 > "$out.rc"
  done
  rc=$(cat "$out.rc"); cp "$out.log" "$LOGS/rowstile-ci-$v.log"; rm -f "$out.log" "$out.rc"
  # said in the copy: the log itself was made inside the container (by root, on Linux), and this user can't add to it
  [ -z "$why" ] || echo "FAILED: $why" >> "$LOGS/rowstile-ci-$v.log"
  grep -E "^(--- |ALL PASSED|FAILED)" "$LOGS/rowstile-ci-$v.log"
  [ $rc -eq 0 ] || failed+=("$v")
  retry docker rm -f -v "$name" >/dev/null 2>&1; name=""
done
echo
if [ ${#failed[@]} -eq 0 ]; then echo "CI PASSED on PostgreSQL $VERSIONS"; else
  echo "CI FAILED on PostgreSQL ${failed[*]} (logs: $LOGS/rowstile-ci-<version>.log)"; exit 1; fi
