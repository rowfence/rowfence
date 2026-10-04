"""rowstile init: a first policy drafted from the database's catalog, a test file, and rowstile.toml."""
from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rowstile_cli import Config

CONFIG = "rowstile.toml"


def write_new(path: str, text: str, written: list[str]) -> None:
    if os.path.exists(path):
        print(f"kept {path} (it is there already)")
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    written.append(path)


def init(policy: str, opts: dict[str, str], cfg: Config) -> None:
    """Writes the drafted policy, a first test file and rowstile.toml, keeping any that exist."""
    out = opts.get("--out", "db")
    written: list[str] = []
    policy_path = os.path.join(out, "policy.authz")
    write_new(policy_path, policy, written)
    m = re.search(r"^role (\S+)", policy, re.M)
    role = m.group(1) if m else "app_user"      # a draft always has one
    first = re.search(r"^type (?!user\b)(\w+) = (\S+)", policy, re.M)
    example = first.group(1) if first else "user"
    write_new(os.path.join(out, "tests", "first.authz"), f'''-- Named tests: each brings its own data and rolls it back. rowstile test (or rowstile dev) runs them.
-- A test's lines:
--   given name = {{INSERT ... RETURNING id}}      rows it needs; $name is what RETURNING gave
--   user $name can|cannot PERM TYPE $id           a permission, as someone
--   as user $name allowed|refused {{SQL}}           a statement as the app role ({role}), signed in as someone
--   as user $name sees N {{SELECT ...}}             how many rows they see

test "nobody signed in sees a {example}"
  anyone cannot view {example} 1
''', written)
    import stack
    found = stack.detect(os.getcwd())
    if found.found:
        via = " from DATABASE_URL" if os.environ.get("DATABASE_URL") else ""
        print(f"found   {', '.join(found.found)}, Postgres{via}")
    if cfg.path is None:
        database = "env:DATABASE_URL"
        extra = stack.config_lines(found) or ['# [clients]                    # generated on each change by rowstile dev',
                                              '# py = "app/authz_client.py"', '# ts = "src/authz.ts"']
        write_new(CONFIG, f'''policy   = "{policy_path.replace(os.sep, "/")}"
tests    = ["{os.path.join(out, "tests").replace(os.sep, "/")}/*.authz"]
database = "{database}"     # a DSN or URL, or env:NAME for an environment variable holding one
''' + "\n".join(extra) + "\n", written)
    else:
        print(f"using {os.path.relpath(cfg.path)} (it is there already)")
    for path in written:
        print(f"wrote {path}")
    if found.tool and CONFIG in written:
        import migrations
        lock = os.path.join(out, "policy.lock").replace(os.sep, "/")
        marked = migrations.mark_generated(os.getcwd(), migrations.generated_patterns(found.tool, found.migrations_dir, lock))
        if marked:
            print("wrote   .gitattributes (reviews show the generated files collapsed)")
    from authzlib import __version__
    if found.npm:
        added = stack.add_npm(os.getcwd(), found.npm, __version__)
        if added:
            print(f"added   {', '.join(added)} to package.json (then: npm install)")
    if found.pip:
        req = stack.pip_requirement(found.pip, __version__)
        print(f"add     {req} to your Python dependencies (pip install '{req}', or uv add '{req}')")
    setup = ""
    if found.setup:
        where = f"in {found.setup_file}" if found.setup_file else "where the app makes its database client"
        lines = "\n".join("       " + line for line in found.setup)
        setup = f"""
  2. Sign every transaction in, {where}:
{lines}
     The role your app connects as ({role}) must not bypass row-level security:
       CREATE ROLE {role} LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;
       ALTER ROLE {role} SET jit = off;"""
    else:
        setup = f"""
  2. The role your app connects as ({role}) must not bypass row-level security:
       CREATE ROLE {role} LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;
       ALTER ROLE {role} SET jit = off;
     It says who is signed in first in each transaction: SELECT authz.act_as('user', '42')
     (the generated clients' sign_in does it)."""
    print(f"""
Next:
  1. Read {policy_path}: every '-- decide:' is a choice only you can make.{setup}
  3. rowstile dev      applies the policy on each save, runs the tests, writes the clients
                       (set DATABASE_URL, or database in {CONFIG}, to a development database)""")
