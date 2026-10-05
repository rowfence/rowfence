#!/usr/bin/env python3
"""latency.py: percentiles from pgbench's per-transaction logs (pgbench -l --log-prefix=PREFIX).

    python3 bench/latency.py PREFIX name0 name1 ...     # names of the -f scripts, in order

Prints one row per script and one for all of them: transactions, failed, p50/p95/p99/max in ms.
With --rate, "end to end" adds the schedule lag (time spent waiting to start), which is what a
caller arriving at that rate would see.
"""

import glob
import sys


def pct(xs: list[float], p: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    return xs[min(len(xs) - 1, round(p / 100 * (len(xs) - 1)))]


def main() -> None:
    prefix, names = sys.argv[1], sys.argv[2:]
    lat: dict[int, list[float]] = {}
    e2e: dict[int, list[float]] = {}
    failed: dict[int, int] = {}
    rated = False
    for path in glob.glob(prefix + ".[0-9]*"):  # PREFIX.<pid>[.<thread>], not PREFIX.out
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                f = line.split()
                if len(f) < 6:
                    continue
                script = int(f[3])
                if f[2] in ("failed", "skipped"):
                    failed[script] = failed.get(script, 0) + 1
                    continue
                t = int(f[2]) / 1000.0
                lat.setdefault(script, []).append(t)
                if len(f) >= 7:
                    rated = True
                    e2e.setdefault(script, []).append(t + int(f[6]) / 1000.0)
    rows = [
        (names[s] if s < len(names) else str(s), lat.get(s, []), e2e.get(s, []), failed.get(s, 0))
        for s in sorted(set(lat) | set(failed))
    ]
    rows.append(("all", [x for r in rows for x in r[1]], [x for r in rows for x in r[2]], sum(r[3] for r in rows)))
    head = f"{'script':<16}{'txns':>8}{'failed':>8}{'p50 ms':>11}{'p95 ms':>11}{'p99 ms':>11}{'max ms':>11}"
    if rated:
        head += f"{'e2e p95':>11}"
    print(head)
    for name, xs, es, nf in rows:
        line = (
            f"{name:<16}{len(xs):>8}{nf:>8}{pct(xs, 50):>11.2f}{pct(xs, 95):>11.2f}{pct(xs, 99):>11.2f}"
            f"{(max(xs) if xs else float('nan')):>11.2f}"
        )
        if rated:
            line += f"{pct(es, 95):>11.2f}"
        print(line)


if __name__ == "__main__":
    main()
