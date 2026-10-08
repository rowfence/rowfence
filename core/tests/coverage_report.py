#!/usr/bin/env python3
"""coverage_report: what the suites run of authzlib and cli, and what nothing runs.

    python3 tests/coverage_report.py [--out DIR] [--diff REF] DIR [DIR ...]

Each DIR is one that run_tests.sh measured into (ROWSTILE_COVERAGE=DIR; core/ci.sh --coverage makes
.ci/coverage-<version>), whose data/ holds a file per Python process the suites started, or such a data folder
itself (CI's parts). Run it where coverage.py is (the image core/Dockerfile builds with COVERAGE=1). It combines
them into --out (the first DIR if not given): .coverage, coverage.json (coverage.py's report) and report.txt:

  - for each file, its lines and branches, and how many of them the suites run (this part is printed too);
  - the lines and branches nothing runs, with their text, the files with the most first;
  - compiled, never judged: what runs of the code that writes the SQL deciding who may do what (DECIDES), but only
    in steps that don't compare the database's answers with the reference evaluator (ORACLE): its SQL was made,
    and difftest, genpolicy and around never judged it.

With --diff REF it also prints the lines changed since REF (git diff REF...HEAD) that nothing runs, and exits 1 if
there are any.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import contextlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)  # core/: where the measured code is
SETTINGS = os.path.join(HERE, "coverage.ini")
# the steps of run_tests.sh that compare the database's answers with the reference evaluator's, by their names
# (CoverageReport in unit_test.py checks it against the steps that run difftest, genpolicy and around)
ORACLE = re.compile(r"compared with the reference evaluator|in random worlds")
# the code that writes the SQL deciding who may do what
DECIDES = (
    "authzlib/compiler.py",
    "authzlib/insight.py",
    "authzlib/output.py",
    "authzlib/sqlutil.py",
    "authzlib/trees.py",
)

Answer = Any  # coverage.py's JSON report, as read


@dataclass
class Function:
    name: str  # Class.method, as coverage.py names it
    lines: list[int]  # its statements


@dataclass
class File:
    """What the suites ran of one file."""

    name: str  # relative to core/: authzlib/compiler.py
    statements: list[int]
    missing: list[int]  # the statements no step ran
    never: dict[int, list[int]]  # a line that ran -> where its branches never went (negative: out of the function)
    branches: int
    branches_run: int
    functions: list[Function] = field(default_factory=list)
    steps: dict[int, set[str]] = field(default_factory=dict)  # a line -> the steps that ran it


def relative(path: str) -> str:
    """A measured file's name as the report gives it: relative to core/, with forward slashes."""
    return (os.path.relpath(path, CODE) if os.path.isabs(path) else path).replace(os.sep, "/")


def combine(dirs: Sequence[str], out: str) -> tuple[str, str]:
    """Every DIR's data in one file, and coverage.py's report of it: (data file, JSON report), in `out`."""
    os.makedirs(out, exist_ok=True)
    data, report = os.path.join(out, ".coverage"), os.path.join(out, "coverage.json")
    parts = [os.path.join(d, "data") if os.path.isdir(os.path.join(d, "data")) else d for d in dirs]
    env = dict(os.environ, ROWSTILE_COVERAGE=out, ROWSTILE_COVERAGE_CODE=CODE, ROWSTILE_COVERAGE_CONTEXT="")
    env.pop("COVERAGE_PROCESS_START", None)  # coverage.py's own commands measure nothing
    for command, *args in (["combine", "--keep", *parts], ["json", "-o", report]):
        p = subprocess.run(
            [sys.executable, "-m", "coverage", command, f"--rcfile={SETTINGS}", f"--data-file={data}", *args],
            cwd=CODE,
            env=env,
            capture_output=True,
            text=True,
        )
        if p.returncode:
            raise SystemExit(f"coverage {command} failed:\n{p.stdout}{p.stderr}")
    return data, report


def steps_by_line(data: str) -> dict[str, dict[int, set[str]]]:
    """For each file, the steps that ran each of its lines: coverage.py's data file is SQLite, and with branches
    measured it holds each step's jumps from line to line (a negative line: into or out of a function)."""
    out: dict[str, dict[int, set[str]]] = {}
    with contextlib.closing(sqlite3.connect(data)) as db:
        rows = db.execute(
            "SELECT f.path, c.context, a.fromno, a.tono FROM arc a JOIN file f ON f.id = a.file_id "
            "JOIN context c ON c.id = a.context_id"
        )
        for path, step, a, b in rows:
            lines = out.setdefault(relative(path), {})
            for n in (a, b):
                if n > 0:
                    lines.setdefault(n, set()).add(step)
    return out


def read(report: str, steps: dict[str, dict[int, set[str]]]) -> list[File]:
    """coverage.py's JSON report, with the steps that ran each line."""
    with open(report, encoding="utf-8") as fh:
        doc: Answer = json.load(fh)
    files = []
    for path, f in sorted(doc["files"].items()):
        name = relative(path)
        missing = set(f["missing_lines"])
        never: dict[int, list[int]] = {}
        for a, b in f["missing_branches"]:
            if a not in missing:  # a line that never ran is listed as such, not by its branches
                never.setdefault(a, []).append(b)
        files.append(
            File(
                name=name,
                statements=sorted(set(f["executed_lines"]) | missing),
                missing=sorted(missing),
                never={k: sorted(v) for k, v in never.items()},
                branches=f["summary"]["num_branches"],
                branches_run=f["summary"]["covered_branches"],
                functions=[
                    Function(n, sorted(set(g["executed_lines"]) | set(g["missing_lines"])))
                    for n, g in f.get("functions", {}).items()
                    if n  # "": the module's own lines
                ],
                steps=steps.get(name, {}),
            )
        )
    return files


def ranges(lines: Iterable[int], statements: Iterable[int]) -> list[tuple[int, int]]:
    """Lines as runs: a run goes on until a statement that isn't among the lines (it ran) comes between."""
    missing = sorted(set(lines))
    ran = sorted(set(statements) - set(missing))
    out: list[tuple[int, int]] = []
    for n in missing:
        if out and bisect.bisect_right(ran, out[-1][1]) == bisect.bisect_left(ran, n):
            out[-1] = (out[-1][0], n)
        else:
            out.append((n, n))
    return out


def judged(f: File) -> set[int]:
    """The lines of f that ran in a step comparing answers with the reference evaluator."""
    return {n for n, steps in f.steps.items() if any(ORACLE.search(s) for s in steps)}


def mistakes(code: str) -> set[int]:
    """The lines of code that report a mistake or handle one: each fail(...) call, raise, and except clause, whole
    (no policy that compiles reaches them)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise | ast.ExceptHandler) or (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "fail"
        ):
            out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return out


def never_judged(f: File, code: str | None = None) -> tuple[list[int], list[str]]:
    """What ran of f, but never in a step that compares answers with the reference evaluator: the lines (but those
    that report a mistake in the policy, which no policy that compiles reaches), and the functions none of whose
    lines ever did."""
    seen = judged(f)
    skip = mistakes("\n".join(source(f.name)) if code is None else code)
    lines = sorted(n for n in f.steps if n not in seen and n not in skip)
    functions = [
        fn.name for fn in f.functions if any(n in f.steps for n in fn.lines) and not any(n in seen for n in fn.lines)
    ]
    return lines, functions


def changed(diff: str) -> dict[str, set[int]]:
    """The lines of core/'s files a diff (git diff -U0) adds or changes, on its new side, by name under core/."""
    out: dict[str, set[int]] = {}
    name: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            name = path[len("b/core/") :] if path.startswith("b/core/") else None
        elif name and line.startswith("@@ "):
            m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                out.setdefault(name, set()).update(range(start, start + count))
    return out


def source(name: str) -> list[str]:
    try:
        with open(os.path.join(CODE, name), encoding="utf-8") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def text(lines: list[str], n: int) -> str:
    s = lines[n - 1].strip() if 0 < n <= len(lines) else ""
    return s if len(s) <= 90 else s[:87] + "..."


def share(part: int, whole: int) -> str:
    return f"{100 * part / whole:6.1f}" if whole else "     -"


def where(target: int) -> str:
    return "the function's end" if target < 0 else f"line {target}"


def table(files: Sequence[File]) -> list[str]:
    """Each file's lines and branches, and how many of them ran."""
    out = [f"{'':34}{'lines':>22}{'branches':>23}", f"{'':34}{'run':>8}{'of':>7}{'%':>7}{'run':>9}{'of':>7}{'%':>7}"]
    total = [0, 0, 0, 0]
    for f in files:
        run = len(f.statements) - len(f.missing)
        out.append(
            f"{f.name:34}{run:>8}{len(f.statements):>7}{share(run, len(f.statements)):>7}"
            f"{f.branches_run:>9}{f.branches:>7}{share(f.branches_run, f.branches):>7}"
        )
        total = [total[0] + run, total[1] + len(f.statements), total[2] + f.branches_run, total[3] + f.branches]
    out.append(
        f"{'total':34}{total[0]:>8}{total[1]:>7}{share(total[0], total[1]):>7}"
        f"{total[2]:>9}{total[3]:>7}{share(total[2], total[3]):>7}"
    )
    return out


def summary(files: Sequence[File]) -> str:
    """The totals, in a line."""
    lines = sum(len(f.statements) for f in files)
    run = lines - sum(len(f.missing) for f in files)
    branches, taken = sum(f.branches for f in files), sum(f.branches_run for f in files)
    return (
        f"run: {run} of {lines} lines ({share(run, lines).strip()}%), "
        f"{taken} of {branches} branches ({share(taken, branches).strip()}%)"
    )


def not_run(f: File, only: set[int] | None = None) -> list[str]:
    """The lines of f nothing runs, as runs of lines, and the branches never taken from lines that ran; with
    `only`, those among these lines."""
    lines = source(f.name)
    missing = [n for n in f.missing if only is None or n in only]
    entries = [(a, f"{a if a == b else f'{a}-{b}':>11}  {text(lines, a)}") for a, b in ranges(missing, f.statements)]
    entries += [
        (n, f"{n:>11}  never to {', '.join(where(t) for t in targets)}: {text(lines, n)}")
        for n, targets in f.never.items()
        if only is None or n in only
    ]
    return [entry for _, entry in sorted(entries)]


def report(files: Sequence[File]) -> list[str]:
    out = ["What the suites run of authzlib and cli (core/tests/coverage_report.py)", "", *table(files), ""]
    missed = sorted((f for f in files if f.missing or f.never), key=lambda f: (-len(f.missing), f.name))
    out.append("Not run: each run of lines nothing runs, and each branch never taken (the files with most first)")
    for f in missed:
        branches = sum(len(t) for t in f.never.values())
        out += ["", f"{f.name}: {len(f.missing)} lines, and {branches} branches from lines that ran", *not_run(f)]
    out += [
        "",
        "Compiled, never judged: lines of the code that writes the SQL deciding who may do what, run only in steps",
        "that compare no answers with the reference evaluator (difftest, genpolicy and around never met them)",
    ]
    for f in files:
        if f.name not in DECIDES:
            continue
        code = source(f.name)
        lines, functions = never_judged(f, "\n".join(code))
        if not lines:
            continue
        out += ["", f"{f.name}: {len(lines)} lines; functions none of whose lines they met: {len(functions)}"]
        out += [f"  {name}" for name in functions]
        out += [f"{a if a == b else f'{a}-{b}':>11}  {text(code, a)}" for a, b in ranges(lines, f.statements)]
    return out


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="What the suites run of authzlib and cli, and what nothing runs.")
    ap.add_argument("dirs", nargs="+", metavar="DIR", help="where run_tests.sh measured (ROWSTILE_COVERAGE)")
    ap.add_argument("--out", metavar="DIR", help="where the combined data and the report go (the first DIR)")
    ap.add_argument("--diff", metavar="REF", help="also the lines changed since REF that nothing runs (exit 1 if any)")
    a = ap.parse_args(argv)
    out = a.out or a.dirs[0]
    data, json_report = combine(a.dirs, out)
    files = read(json_report, steps_by_line(data))
    with open(os.path.join(out, "report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report(files)) + "\n")
    print("\n".join(table(files)))
    print(f"\n{summary(files)}; what nothing runs, line by line: {os.path.join(out, 'report.txt')}")
    if not a.diff:
        return 0
    # (in a container the checkout is someone else's, which git refuses unless told: this only reads)
    diff = subprocess.run(
        ["git", "-c", "safe.directory=*", "diff", "-U0", "--no-color", "--no-ext-diff", f"{a.diff}...HEAD", "--"]
        + ["authzlib", "cli"],
        cwd=CODE,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    new = changed(diff)
    found = [line for f in files if f.name in new for line in not_run(f, new[f.name])]
    print(f"\nChanged since {a.diff} and not run: {len(found)} (each a run of lines, or a branch never taken)")
    for f in files:
        if f.name in new and (lines := not_run(f, new[f.name])):
            print(f.name, *lines, sep="\n")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
