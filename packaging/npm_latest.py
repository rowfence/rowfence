#!/usr/bin/env python3
"""npm's `latest` while only alphas and candidates are published: it follows `next`.

    python3 packaging/npm_latest.py          # says what it would move, package by package
    python3 packaging/npm_latest.py --move   # moves it (the release workflow, by npm's trusted publishing)

A release publishes an alpha or a candidate under `next`. `latest` is what a plain `npm i rowstile` gets and what
a package's page on npmjs.com shows, and npm gave it to the first version ever published: left alone it stays
there. So, until a final release exists, each release moves `latest` to where `next` is, on every package. From
the first final release on, this moves nothing: that release is published as `latest`, and later alphas stay
under `next`.

Moving a tag by trusted publishing needs npm 11.21.0 or newer, and **Allow npm dist-tag** ticked in each
package's trusted publisher on npmjs.com (off by default). Without it npm refuses, this says which packages,
and nothing else is touched: what was published stays published. Standard library only.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINAL = re.compile(r"\d+\.\d+\.\d+")
NEEDS = (11, 21, 0)


def names() -> list[str]:
    """Every package a release publishes: the launcher, one per platform, the TypeScript SDK's."""
    with open(os.path.join(ROOT, "packaging", "npm", "build.mjs"), encoding="utf-8") as fh:
        platforms = re.findall(r'^  "([a-z0-9-]+)": \{ triple:', fh.read(), re.M)
    sdk = []
    for path in sorted(glob.glob(os.path.join(ROOT, "sdk", "typescript", "*", "package.json"))):
        with open(path, encoding="utf-8") as fh:
            sdk.append(str(json.load(fh)["name"]))
    return ["rowstile", *(f"@rowstile/cli-{p}" for p in platforms), *sdk]


def target(dist_tags: dict[str, str], versions: list[str]) -> tuple[str | None, str]:
    """The version `latest` moves to (None: it stays), and why, from a package's tags and published versions."""
    final = sorted(v for v in versions if FINAL.fullmatch(v))
    if final:
        return None, f"{final[-1]} is released: latest is a release's from now on"
    following = dist_tags.get("next")
    if not following:
        return None, "nothing is published under next"
    if dist_tags.get("latest") == following:
        return None, f"latest is {following} already"
    return following, f"latest {dist_tags.get('latest', 'nothing')} -> {following}"


def npm(*args: str) -> subprocess.CompletedProcess[str]:
    command = shutil.which("npm")
    if not command:
        raise SystemExit("npm_latest.py: npm isn't on the PATH")
    return subprocess.run([command, *args], capture_output=True, text=True, encoding="utf-8", check=False)


def published(name: str) -> tuple[dict[str, str], list[str]]:
    """A package's tags and versions, as the registry has them."""
    out = npm("view", name, "dist-tags", "versions", "--json")
    if out.returncode != 0:
        raise SystemExit(f"npm_latest.py: npm view {name}: {out.stderr.strip() or out.stdout.strip()}")
    said = json.loads(out.stdout)
    versions = said.get("versions", [])
    return dict(said.get("dist-tags", {})), [versions] if isinstance(versions, str) else list(versions)


def new_enough(version: str) -> bool:
    """Whether this npm moves a tag by trusted publishing: 11.21.0 or newer, and on 12 from 12.2.0."""
    found = tuple(int(n) for n in re.findall(r"\d+", version)[:3])
    return found >= (12, 2, 0) or (12, 0, 0) > found >= NEEDS


def main(argv: list[str]) -> None:
    if argv not in ([], ["--move"]):
        raise SystemExit(__doc__)
    move = argv == ["--move"]
    if move and not new_enough(npm("--version").stdout.strip()):
        raise SystemExit(
            f"npm_latest.py: moving a tag by trusted publishing needs npm 11.21.0 or newer (12.2.0 on 12), this is "
            f"{npm('--version').stdout.strip()}"
        )
    refused = []
    for name in names():
        version, why = target(*published(name))
        if version is None or not move:
            print(f"{name}: {why}" + ("" if version is None else " (not moved: run with --move)"))
            continue
        out = npm("dist-tag", "add", f"{name}@{version}", "latest")
        if out.returncode == 0:
            print(f"{name}: {why}")
        else:
            lines = (out.stderr.strip() or out.stdout.strip()).splitlines()
            refused.append(name)
            print(f"{name}: not moved, npm refused: {' '.join(lines[-3:])}")
    if refused:
        said = (
            f"npm's latest was not moved on {len(refused)} package(s): {', '.join(refused)}. Everything published "
            "stays published. If npm says the trusted publisher cannot manage dist-tags, tick Allow npm dist-tag in "
            "each package's settings on npmjs.com (Trusted publisher), then: gh workflow run release.yml -f latest=true"
        )
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::warning::{said}")
        raise SystemExit(f"npm_latest.py: {said}")


if __name__ == "__main__":
    main(sys.argv[1:])
