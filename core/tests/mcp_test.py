#!/usr/bin/env python3
"""mcp_test: the MCP server (`rowfence mcp`) over its protocol, as a coding agent's client would use it: the
handshake and the tools, then each tool in a project folder (rowfence.toml, a policy, tests) on a scratch
database: check, prove, push, test, why, lint.

    PGHOST=... PGUSER=... python3 tests/mcp_test.py [--db authz_mcp]     (--no-db: only what needs none)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
fails = 0
# an answer from the server: its shape is what the checks check
Answer = Any


def check(label: str, ok: object, detail: object = "") -> None:
    global fails
    if ok:
        print(f"ok    {label}")
    else:
        fails += 1
        print(f"FAIL  {label}{': ' + str(detail)[:800] if detail else ''}")


class Client:
    def __init__(self, cwd: str, *args: str) -> None:
        self.p = subprocess.Popen([sys.executable, os.path.join(ROOT, "cli", "rowfence_cli.py"), *args, "mcp"], cwd=cwd,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert self.p.stdin is not None and self.p.stdout is not None
        self.stdin, self.stdout = self.p.stdin, self.p.stdout
        self.n = 0

    def send(self, obj: object) -> None:
        self.stdin.write((obj if isinstance(obj, str) else json.dumps(obj)).encode() + b"\n")
        self.stdin.flush()

    def read(self) -> Answer:
        return json.loads(self.stdout.readline())

    def request(self, method: str, params: object = None) -> Answer:
        self.n += 1
        self.send({"jsonrpc": "2.0", "id": self.n, "method": method, **({"params": params} if params is not None else {})})
        msg = self.read()
        assert msg.get("id") == self.n, msg
        return msg

    def tool(self, name: str, **arguments: object) -> Answer:
        msg = self.request("tools/call", {"name": name, "arguments": arguments})
        return msg.get("result", msg.get("error"))

    def close(self) -> int:
        self.stdin.close()
        return self.p.wait(timeout=10)


def protocol(folder: str) -> None:
    print("-- the protocol")
    c = Client(folder)
    r = c.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "test", "version": "1"}})["result"]
    check("initialize: the version asked for, tools, and what the server is", r["protocolVersion"] == "2025-06-18"
          and "tools" in r["capabilities"] and r["serverInfo"]["name"] == "rowfence" and "push" in r["instructions"], r)
    r = c.request("initialize", {"protocolVersion": "1999-01-01", "capabilities": {}})["result"]
    check("... a version it doesn't know: its newest", r["protocolVersion"] == "2025-11-25", r)
    c.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    check("notifications get no answer (the next answer is the ping's)", c.request("ping")["result"] == {})
    tools = {t["name"]: t for t in c.request("tools/list")["result"]["tools"]}
    check("the tools", sorted(tools) == ["check", "lint", "prove", "push", "review", "test", "why"], sorted(tools))
    check("... each with its input and output", all(t["inputSchema"]["type"] == "object" and t["outputSchema"]["required"]
                                                   for t in tools.values()))
    check("... why needs who, the type, the id and the permission", tools["why"]["inputSchema"]["required"] == ["as", "type", "id", "perm"])
    check("... push is the only one that changes anything", [n for n, t in tools.items() if not t["annotations"]["readOnlyHint"]] == ["push"]
          and tools["push"]["annotations"]["destructiveHint"])
    r = c.request("tools/call", {"name": "fly", "arguments": {}})
    check("an unknown tool: an error naming the tools", r["error"]["code"] == -32602 and "check" in r["error"]["message"], r)
    r = c.request("tools/call", {"name": "why", "arguments": {"as": "user:1"}})
    check("a missing argument: named", r["error"]["code"] == -32602 and "type" in r["error"]["message"], r)
    r = c.request("resources/list")
    check("a method it doesn't have: -32601", r["error"]["code"] == -32601, r)
    c.send("{not json")
    check("a line that isn't JSON: a parse error, and the server carries on", c.read()["error"]["code"] == -32700
          and c.request("ping")["result"] == {})
    c.send("[" * 100000 + "]" * 100000)
    check("... nor does one nested too deep to read end it", c.read()["error"]["code"] == -32700
          and c.request("ping")["result"] == {})
    check("it stops when its input closes", c.close() == 0)


def without_db(folder: str) -> None:
    print("-- check and prove (no database)")
    c = Client(folder)
    r = c.tool("check")
    check("check: the policy rowfence.toml names compiles", not r["isError"] and r["structuredContent"]["ok"]
          and r["content"][0]["text"].strip().endswith(": ok"), r)
    policy = os.path.join(folder, "db", "policy.authz")
    with open(policy, encoding="utf-8") as fh:
        good = fh.read()
    with open(policy, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("type robot = app.robots\n  owner : martian = owner_id\n")
    r = c.tool("check")
    s = r["structuredContent"]
    line = good.count("\n") + 2
    check("a mistake: an answer (not a failed call), with the file, the line and the message",
          not r["isError"] and not s["ok"] and s["error"]["file"] == "db/policy.authz" and s["error"]["line"] == line
          and "martian" in s["error"]["message"], r)
    check("... its code, and its page: what it means and the same mistake fixed", s["error"].get("code") == "AZ201"
          and not s["error"]["message"].endswith("]") and s["error"]["help"].startswith("# AZ201: Unknown type")
          and "## Fixed" in r["content"][0]["text"], r)
    with open(policy, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(good.replace("app role app_user", 'app role app_user\ninclude "roles.authz"', 1))
    with open(os.path.join(folder, "db", "roles.authz"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("type robot = app.robots\n  owner : martian = owner_id\n")
    s = c.tool("check")["structuredContent"]
    check("... in an included file: that file's path, and its line", s.get("error", {}).get("file") == "db/roles.authz"
          and s["error"]["line"] == 2, s)
    with open(policy, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(good)
    r = c.tool("check", policy="db/nothing.authz")
    check("a policy file that isn't there: a failed call", r["isError"] and r["structuredContent"]["exit_code"] == 2, r)
    r = c.tool("prove", worlds=40)
    s = r["structuredContent"]
    check("prove: the docs example's counterexample (an owner outside the org may share)", not r["isError"] and not s["ok"]
          and "never folder: share and not org.member" in s["output"] and "the smallest found" in s["output"], r)
    c.close()


def with_db(folder: str, db: str) -> None:
    print("-- push, test, why, lint (a scratch database)")
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
                   check=True, capture_output=True, env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"))
    c = Client(folder, "--db", f"dbname={db}")
    r = c.tool("test")
    check("test before a policy is applied: says so", not r["structuredContent"]["ok"] and "no policy is applied" in r["content"][0]["text"], r)
    r = c.tool("push")
    check("push: the policy applied (the whole policy, the first time)", not r["isError"] and r["structuredContent"]["ok"]
          and "applied" in r["content"][0]["text"], r)
    r = c.tool("push")
    check("... again: unchanged", r["structuredContent"]["ok"] and "unchanged" in r["content"][0]["text"], r)
    r = c.tool("test")
    s = r["structuredContent"]
    check("test: the policy's tests and the named tests pass", s["ok"] and "policy tests passed" in s["output"], r)
    r = c.tool("test", coverage=True)
    check("... with coverage", r["structuredContent"]["ok"] and "branch" in r["structuredContent"]["output"], r)
    with open(os.path.join(folder, "db", "tests", "wrong.authz"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write('test "a wrong expectation"\n'
                 "  given ann  = {INSERT INTO app.users (id, name) VALUES (9101, 'Ann') RETURNING id}\n"
                 "  given acme = {INSERT INTO app.orgs (id, name) VALUES (9101, 'Acme') RETURNING id}\n"
                 "  given top  = {INSERT INTO app.folders (org_id, owner_id, name) VALUES ($acme, $ann, 'Top') RETURNING id}\n"
                 "  user $ann cannot view folder $top\n")
    r = c.tool("test", files=["db/tests/wrong.authz"])
    s = r["structuredContent"]
    check("a failing test: an answer (not a failed call), naming the check", not r["isError"] and not s["ok"]
          and s["exit_code"] == 1 and "FAIL" in s["output"], r)
    r = c.tool("why", **{"as": "user:3", "type": "folder", "id": "3", "perm": "edit"})
    s = r["structuredContent"]
    check("why: no, why not, and the smallest change", s["ok"] and s["output"].startswith("no: user:3 does not hold edit on folder 3")
          and "share editor on folder 3 with user 3" in s["output"], r)
    r = c.tool("why", **{"as": "user:2", "type": "folder", "id": "3", "perm": "fly"})
    check("... a permission the type doesn't have: named", not r["structuredContent"]["ok"] and "no permission fly" in r["content"][0]["text"], r)
    r = c.tool("lint")
    check("lint: the example leaves nothing open", r["structuredContent"]["ok"], r)
    # a database with a policy that nobody marked as a development database (applied, as production is)
    other = db + "_unmarked"
    subprocess.run(["dropdb", "--if-exists", other], capture_output=True)
    subprocess.run(["createdb", other], check=True)
    subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", other, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
                   check=True, capture_output=True, env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"))
    subprocess.run([sys.executable, os.path.join(ROOT, "cli", "rowfence_cli.py"), "--db", f"dbname={other}", "apply"],
                   cwd=folder, check=True, capture_output=True)
    c2 = Client(folder, "--db", f"dbname={other}")
    with open(os.path.join(folder, "db", "policy.authz"), "a", encoding="utf-8", newline="\n") as fh:
        fh.write("\n-- a change\n")
    r = c2.tool("push")
    check("push to a database nobody marked: refused", not r["structuredContent"]["ok"] and "AZ610" in r["content"][0]["text"], r)
    for flag in ("--development", "--force", "--downgrade", "-d"):
        r = c2.tool("push", policy=flag)
        check(f"push with {flag} as the policy: not an option the agent may pass", "starts with '-'" in str(r.get("message")), r)
    r = c2.tool("push")
    check("... and the database is still not marked", not r["structuredContent"]["ok"] and "AZ610" in r["content"][0]["text"], r)
    r = c2.tool("review", base="--output=x")
    check("review's base can't be an option either", "starts with '-'" in str(r.get("message")), r)
    r = c2.tool("why", **{"as": "user:3", "type": "folder", "id": "--development", "perm": "edit"})
    check("... nor why's id", "starts with '--'" in str(r.get("message")), r)
    c2.close()
    subprocess.run(["dropdb", "--if-exists", other], capture_output=True)
    subprocess.run(["psql", "-X", "-q", "-d", db, "-c", "CREATE VIEW app.all_files AS SELECT * FROM app.files",
                    "-c", "GRANT SELECT ON app.all_files TO app_user"], check=True, capture_output=True)
    r = c.tool("lint")
    s = r["structuredContent"]
    first = s["output"].split("\n")[2]
    check("... a view that reads a governed table as its owner: an error, first", not r["isError"] and not s["ok"]
          and first.startswith("error") and "app.all_files" in first, r)
    c.close()
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)


def project() -> str:
    """A project folder: rowfence.toml, the docs example's policy and its named tests."""
    folder = tempfile.mkdtemp(prefix="pga_mcp_")
    os.makedirs(os.path.join(folder, "db", "tests"))
    with open(os.path.join(ROOT, "example", "docs.authz"), encoding="utf-8") as fh:
        policy = fh.read().split("\ntest\n")[0] + "\n"          # its test section needs the scenario's data
    with open(os.path.join(folder, "db", "policy.authz"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(policy)
    shutil.copy(os.path.join(ROOT, "example", "docs.test.authz"), os.path.join(folder, "db", "tests", "docs.authz"))
    with open(os.path.join(folder, "rowfence.toml"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write('policy = "db/policy.authz"\ntests = ["db/tests/docs.authz"]\n')
    return folder


def main() -> None:
    folder = project()
    try:
        protocol(folder)
        without_db(folder)
        if "--no-db" not in sys.argv:
            with_db(folder, sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_mcp")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    print(f"mcp: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
