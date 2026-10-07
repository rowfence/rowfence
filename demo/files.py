#!/usr/bin/env python3
"""The demo's files, taken from docs/getting-started.md so the two can't drift: the guide's tables and rows
(one SQL file), its policy and its tests (as the guide names them), and a rowstile.toml.

    python3 demo/files.py <folder for the project> <file for the SQL>
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    work, schema = sys.argv[1:]
    with open(os.path.join(HERE, "..", "docs", "getting-started.md"), encoding="utf-8") as fh:
        text = fh.read()
    blocks = re.findall(r"```(sql|authz)[ \t]*([^\n]*)\n(.*?)```", text, re.S)
    with open(schema, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(next(body for kind, _, body in blocks if kind == "sql"))
    for kind, name, body in blocks:
        if kind == "authz" and name:
            path = os.path.join(work, *name.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(body)
    with open(os.path.join(work, "rowstile.toml"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write('policy   = "db/policy.authz"\ntests    = ["db/tests/*.authz"]\ndatabase = "env:DATABASE_URL"\n')


if __name__ == "__main__":
    main()
