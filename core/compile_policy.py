#!/usr/bin/env python3
"""compile_policy: compile a .authz policy file into PostgreSQL.

    python3 compile_policy.py docs.authz > docs.sql              # views, triggers, RLS, API
    python3 compile_policy.py docs.authz --tests [tests/*.authz] > docs_tests.sql   # the policy's tests, and more
    python3 compile_policy.py docs.authz --check                 # only report mistakes
    python3 compile_policy.py docs.authz --diff [--users 1,2] | psql   # who gains/loses access
                                                         # if applied (rolled back)
    python3 compile_policy.py docs.authz --graph > docs.mmd      # Mermaid diagram of the policy
    python3 compile_policy.py docs.authz --client ts > authz.ts  # typed helpers (ts or py)

Apply the output with psql as a superuser (or the owner of the tables). It runs
in one transaction, so a policy change applies fully or not at all, and
re-applying replaces the previous version while keeping people's shares.
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from authzlib import Compiler, PolicyError, parse_policy


def load(path: str) -> Compiler:
    with open(path, encoding="utf-8") as fh:
        return Compiler(parse_policy(fh.read(), path))


def main() -> None:
    if isinstance(sys.stdout, io.TextIOWrapper):    # the SQL, the graph and the clients are UTF-8 everywhere
        sys.stdout.reconfigure(encoding="utf-8")
    argv = sys.argv[1:]
    users: list[str] | None = None
    client: str | None = None
    if "--client" in argv:
        i = argv.index("--client")
        if i + 1 >= len(argv) or argv[i + 1] not in ("ts", "py"):
            print("--client needs a language: ts or py", file=sys.stderr)
            sys.exit(2)
        client = argv[i + 1]
        del argv[i:i + 2]
    if "--users" in argv:
        i = argv.index("--users")
        if i + 1 >= len(argv):
            print(__doc__, file=sys.stderr)
            sys.exit(2)
        users = [u for u in argv[i + 1].split(",") if u]
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 and not (args and "--tests" in argv):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    path = args[0]
    try:
        compiler = load(path)
        if "--tests" in sys.argv:
            extra: dict[str, str] = {}
            for name in args[1:]:
                with open(name, encoding="utf-8") as fh:
                    extra[name] = fh.read()
            compiler.add_test_files(extra)
            out = compiler.compile_tests(path)
        elif "--diff" in sys.argv:
            out = compiler.compile_diff(path, users)
        elif "--graph" in sys.argv:
            compiler.compile(path)          # reports the same mistakes a compile would
            out = compiler.graph()
        elif client:
            compiler.compile(path)
            out = compiler.client(client, os.path.basename(path))
        else:
            out = compiler.compile(path)
        if "--check" in sys.argv:
            print(f"{path}: ok")
            return
    except PolicyError as e:
        print(f"{path}: {e}", file=sys.stderr)
        sys.exit(1)
    except (OSError, UnicodeDecodeError) as e:
        print(f"{e.filename or path}: {e.strerror}" if isinstance(e, OSError) else f"{path}: not UTF-8: {e}", file=sys.stderr)
        sys.exit(2)
    sys.stdout.write(out)


if __name__ == "__main__":
    main()
