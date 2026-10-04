#!/bin/bash
# regress.sh: a small run of the scale benchmark, compared with bench/baseline.txt (see regress.py).
#   core/bench/regress.sh             # fails when something got more than twice as slow, or a gate fails
#   core/bench/regress.sh --record    # make this machine's run the baseline (after an intended change)
# 10k folders and 200k files, short steps: a few minutes. The baseline belongs to the machine that
# recorded it; CI's runners (GitHub's) differ from the dev laptop, so CI records its own on the first run.
# The scale gate's speed limits are shown, not judged (SPEED_GATES=0): they are for the gate's size on a
# machine of its own; here speed is judged against the baseline, and failed writes and verify() still fail.
# A run that fails is run once more, and only a second failure counts: the machine may be busy with
# something else for a while (a CI runner is a shared machine), and a slower commit is slower both times.
set -u
cd "$(dirname "$0")/../.."
export FILES=${FILES:-200000} FOLDERS=${FOLDERS:-10000} USERS=${USERS:-500} TEAMS=${TEAMS:-50}
export SPEED_GATES=${SPEED_GATES:-0}
# reads arrive at 25/s per CPU, at most the gate's 400 (the dev laptop's 16 CPUs): on GitHub's runners (2 CPUs, 4 for
# a public repository) 400 reads/s keep both busy, and their p95 measures the wait for a CPU (126 ms; 2.3 ms here)
cpus=$(nproc 2>/dev/null || echo 16)
export READ_RATE=${READ_RATE:-$(( cpus * 25 < 400 ? cpus * 25 : 400 ))}
export DURATION=${DURATION:-15} GATE_DURATION=${GATE_DURATION:-20}
export OUT=core/bench/results/regress-latest.txt
BASELINE=${BASELINE:-core/bench/baseline.txt}
bash core/bench/scale.sh || exit 1
if [ "${1:-}" = --record ] || [ ! -f "$BASELINE" ]; then
  python3 core/bench/regress.py "$OUT" "$BASELINE" --record
  exit
fi
python3 core/bench/regress.py "$OUT" "$BASELINE" && exit 0
echo "== slower than the baseline: running once more; only a second failure counts"
bash core/bench/scale.sh || exit 1
python3 core/bench/regress.py "$OUT" "$BASELINE"
