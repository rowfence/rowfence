#!/usr/bin/env python3
"""client_types: the generated TypeScript client (rowstile client ts) under tsc --strict. It accepts correct
calls and refuses names the policy doesn't have. No database.

    python3 tests/client_types.py        # needs tsc: on PATH, or the repository's (npm ci at the root)

tools_test.py runs the same check where tsc is installed; CI's javascript job runs this file.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import compile_policy  # noqa: E402

USE = """import { authz, asUser, Queryable } from "./authz";
declare const db: Queryable;
async function main() {
  await asUser(db, 7, async (tx) => {
    const a = authz(tx);
    const ok: boolean = await a.can("file", 11, "edit");
    await a.share("folder", 3, "viewer", "user", 4, { expiresAt: new Date() });
    // @ts-expect-error: files have no permission 'fly'
    await a.can("file", 11, "fly");
    // @ts-expect-error: 'owner' is not a shared relation
    await a.share("folder", 3, "owner", "user", 4);
    // @ts-expect-error: no type 'robot'
    await a.list("robot", "view");
    return ok;
  });
}
main();
"""


def tsc() -> list[str] | None:
    """How to run tsc here: the one on PATH, else the repository's own (node_modules, after npm ci)."""
    found = shutil.which("tsc")
    if found:
        return [found]
    local = os.path.join(os.path.dirname(ROOT), "node_modules", "typescript", "bin", "tsc")
    node = shutil.which("node")
    return [node, local] if node and os.path.exists(local) else None


def type_check(ts: str, use: str = USE) -> tuple[bool, str] | None:
    """Whether `use` type-checks against the client `ts`, and tsc's output; None when there is no tsc."""
    cmd = tsc()
    if cmd is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in (("authz.ts", ts), ("use.ts", use)):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        r = subprocess.run([*cmd, "--noEmit", "--strict", "--target", "es2020", "--module", "esnext", "--moduleResolution", "bundler",
                            os.path.join(tmp, "use.ts")], capture_output=True, text=True)
    return r.returncode == 0, r.stdout + r.stderr


def main() -> None:
    policy = os.path.join(ROOT, "example", "docs.authz")
    ts = compile_policy.load(policy).client("ts", "docs.authz")
    fails = 0
    for label, use, want in (
            ("tsc --strict accepts correct calls and refuses wrong names", USE, True),
            # each @ts-expect-error above must be needed: without them, the wrong names are errors
            ("... and a wrong name is an error", USE.replace("    // @ts-expect-error: files have no permission 'fly'\n", ""), False),
            ("... as is a relation that isn't shared", USE.replace("    // @ts-expect-error: 'owner' is not a shared relation\n", ""), False)):
        got = type_check(ts, use)
        if got is None:
            raise SystemExit("client_types: tsc not found (install TypeScript, or npm ci at the repository's root)")
        if got[0] == want:
            print(f"ok    {label}")
        else:
            fails += 1
            print(f"FAIL  {label}: {got[1]}")
    print("client_types: all passed" if not fails else f"client_types: {fails} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
