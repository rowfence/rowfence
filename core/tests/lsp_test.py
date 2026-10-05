#!/usr/bin/env python3
"""lsp_test.py: the language server (`rowstile lsp`) over its protocol, as an editor would use it.
No database needed.   python3 tests/lsp_test.py"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = 0
# an answer from the server: its shape is what the checks check
Answer = Any


def ok(what: str, cond: object, got: Answer = None) -> None:
    global fails
    if cond:
        print(f"ok    {what}")
    else:
        fails += 1
        print(f"FAIL  {what}{': ' + json.dumps(got)[:400] if got is not None else ''}")


class Client:
    def __init__(self, cwd: str) -> None:
        self.p = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "lsp"],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        assert self.p.stdin is not None and self.p.stdout is not None
        self.stdin, self.stdout = self.p.stdin, self.p.stdout
        self.n = 0
        self.notes: list[Answer] = []

    def send(self, obj: object) -> None:
        body = json.dumps(obj).encode()
        self.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self.stdin.flush()

    def read(self) -> Answer:
        length = -1
        while True:
            line = self.stdout.readline().strip()
            if not line:
                break
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        return json.loads(self.stdout.read(length))

    def request(self, method: str, params: object) -> Answer:
        self.n += 1
        self.send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        while True:
            msg = self.read()
            if msg.get("id") == self.n:
                return msg.get("result", msg.get("error"))
            self.notes.append(msg)

    def notify(self, method: str, params: object) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def diagnostics(self, uri: str) -> Answer:
        """The next diagnostics published for uri (a request in between flushes them)."""
        self.request("textDocument/documentSymbol", {"textDocument": {"uri": uri}})
        found = [
            m for m in self.notes if m.get("method") == "textDocument/publishDiagnostics" and m["params"]["uri"] == uri
        ]
        self.notes.clear()
        return found[-1]["params"]["diagnostics"] if found else None

    def close(self) -> None:
        self.request("shutdown", None)
        self.notify("exit", None)
        self.p.wait(timeout=10)


def uri(path: str) -> str:
    return Path(os.path.abspath(path)).as_uri()


def pos(text: str, needle: str, offset: int = 0, nth: int = 0) -> dict[str, int]:
    """(line, character) of the nth occurrence of needle, plus offset characters."""
    start = -1
    for _ in range(nth + 1):
        start = text.index(needle, start + 1)
    line = text.count("\n", 0, start)
    return {"line": line, "character": start - (text.rfind("\n", 0, start) + 1) + offset}


with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(ROOT, "example", "docs.authz"), encoding="utf-8") as fh:
        policy = fh.read()
    path = os.path.join(d, "policy.authz")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(policy)
    with open(os.path.join(d, "rowstile.toml"), "w", encoding="utf-8") as fh:
        fh.write('policy = "policy.authz"\n')
    u = uri(path)
    c = Client(d)
    caps = c.request("initialize", {"processId": None, "rootUri": uri(d), "capabilities": {}})
    ok(
        "initialize says what it can do",
        caps["capabilities"].get("hoverProvider") and caps["capabilities"].get("completionProvider"),
        caps,
    )
    c.notify("textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": policy}})
    ok("a good policy has no errors", c.diagnostics(u) == [], c.diagnostics(u))

    broken = policy.replace("can edit  = share or editor", "can edit  = share or edtor", 1)
    c.notify("textDocument/didChange", {"textDocument": {"uri": u, "version": 2}, "contentChanges": [{"text": broken}]})
    d1 = c.diagnostics(u)
    want = pos(broken, "edtor")["line"]
    ok(
        "a mistake shows up while typing, on its line",
        d1 and d1[0]["range"]["start"]["line"] == want and "edtor" in d1[0]["message"],
        d1,
    )
    ok(
        "... with its code beside the message (rowstile help AZ203)",
        d1 and d1[0].get("code") == "AZ203" and not d1[0]["message"].endswith("]"),
        d1,
    )
    c.notify("textDocument/didChange", {"textDocument": {"uri": u, "version": 3}, "contentChanges": [{"text": policy}]})
    ok("... and goes away when fixed", c.diagnostics(u) == [])

    def at(needle: str, offset: int = 1, nth: int = 0) -> dict[str, object]:
        return {"textDocument": {"uri": u}, "position": pos(policy, needle, offset, nth)}

    h = c.request("textDocument/hover", at("parent.share", len("parent.") + 1))
    ok(
        "hover on parent.share shows folder.share",
        h and "folder.share = owner or org.admin" in h["contents"]["value"],
        h,
    )
    ok("... and that it inherits through parent", h and "inherits through `parent`" in h["contents"]["value"], h)
    h = c.request("textDocument/hover", at("folder.edit and owner", 1))
    ok("hover on a relation in rules shows where it comes from", h and "folder_id" in h["contents"]["value"], h)
    h = c.request("textDocument/hover", at("type team", 6))
    ok(
        "hover on a type shows its table and key",
        h and "app.teams" in h["contents"]["value"] and "id bigint" in h["contents"]["value"],
        h,
    )

    dfn = c.request("textDocument/definition", at("org.admin", len("org.") + 1))
    ok(
        "definition of org.admin is the admin line of org",
        dfn and dfn["range"]["start"]["line"] == pos(policy, "admin  : user")["line"],
        dfn,
    )
    rule = "  select                            : view"
    dfn = c.request("textDocument/definition", at(rule, rule.index("view")))
    ok(
        "definition of a permission in rules goes to the type's",
        dfn and dfn["range"]["start"]["line"] == pos(policy, "can view  = edit or viewer", 0, 1)["line"],
        dfn,
    )

    refs = c.request("textDocument/references", at("can share = owner or org.admin", 5))
    lines = sorted({r["range"]["start"]["line"] for r in refs or []})
    ok("references of folder.share include parent.share and the rules", len(lines) >= 4, refs)

    line = pos(policy, "  can edit  = share or editor")["line"]
    comp = c.request(
        "textDocument/completion",
        {
            "textDocument": {"uri": u},
            "position": {"line": line, "character": len("  can edit  = share or editor or (parent.")},
        },
    )
    labels = {i["label"] for i in comp or []}
    ok("completion after parent. offers folder's permissions", {"share", "edit", "view"} <= labels, sorted(labels))
    comp = c.request(
        "textDocument/completion", {"textDocument": {"uri": u}, "position": {"line": line, "character": 4}}
    )
    labels = {i["label"] for i in comp or []}
    ok(
        "completion inside a type offers its relations and permissions",
        {"owner", "parent", "view"} <= labels,
        sorted(labels),
    )

    syms = c.request("textDocument/documentSymbol", {"textDocument": {"uri": u}})
    folder = next((s for s in syms if s["name"] == "folder"), None)
    ok(
        "the outline lists types with their permissions",
        folder and {"share", "edit", "view"} <= {k["name"] for k in folder["children"]},
        syms,
    )

    tests = os.path.join(d, "policy.test.authz")
    good = "test \"owner\"\n  given ann = {INSERT INTO app.users (id, name) VALUES (1, 'Ann') RETURNING id}\n  user $ann cannot view file 1\n"
    tu = uri(tests)
    c.notify("textDocument/didOpen", {"textDocument": {"uri": tu, "languageId": "authz", "version": 1, "text": good}})
    ok("a test file is checked against the policy in rowstile.toml", c.diagnostics(tu) == [], c.diagnostics(tu))
    bad = good.replace("cannot view file", "cannot vew file")
    c.notify("textDocument/didChange", {"textDocument": {"uri": tu, "version": 2}, "contentChanges": [{"text": bad}]})
    d2 = c.diagnostics(tu)
    ok(
        "... and a permission that doesn't exist is marked on its line",
        d2 and d2[0]["range"]["start"]["line"] == 2 and "vew" in d2[0]["message"],
        d2,
    )
    c.close()

    # rowstile.toml names a variable for the database, and the editor's environment doesn't have it
    with open(os.path.join(d, "rowstile.toml"), "a", encoding="utf-8") as fh:
        fh.write('database = "env:ROWSTILE_LSP_TEST_NOT_SET"\n')
    c = Client(d)
    c.request("initialize", {"capabilities": {}})
    c.notify("textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": policy}})
    line = pos(policy, "  can edit  = share or editor")["line"]
    comp = c.request(
        "textDocument/completion", {"textDocument": {"uri": u}, "position": {"line": line, "character": 4}}
    )
    ok(
        "completion without the database's variable: the policy's names, and the server goes on",
        c.p.poll() is None and {"owner", "view"} <= {i["label"] for i in comp or []},
        comp,
    )
    c.close()

# a policy split into files: the included file is a part of the policy, opened alone or not
with tempfile.TemporaryDirectory() as d:
    main_text = (
        'app role app_user\ninclude "org.authz"\ntype user = app.users\ntype doc = app.docs\n  org   : org = org_id\n'
        "  owner : user = owner_id\n  can view = owner or org.see\n  can edit = owner and {deleted_at is not null}\n"
        "rules app.docs\n  select : view\n"
    )
    org_text = "type org = app.orgs\n  member : user = app.org_members(org_id -> user_id)\n  can see = member\n"
    tests_text = 'test "first"\n  user 1 can view doc 1\n\ntest "second"\n  user 1 can view doc 1\n'
    for name, body in (
        ("policy.authz", main_text),
        ("org.authz", org_text),
        ("t.authz", tests_text),
        ("rowstile.toml", 'policy = "policy.authz"\n'),
    ):
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    # the included file's URI as an editor may spell it: not the way the server would (VS Code on Windows: c%3A)
    pu, ou, tu = (
        uri(os.path.join(d, "policy.authz")),
        uri(os.path.join(d, "org.authz")).replace("org.authz", "org%2Eauthz"),
        uri(os.path.join(d, "t.authz")),
    )
    c = Client(d)
    c.request("initialize", {"capabilities": {}})

    def opened(u: str, body: str) -> None:
        c.notify(
            "textDocument/didOpen", {"textDocument": {"uri": u, "languageId": "authz", "version": 1, "text": body}}
        )

    def changed(u: str, body: str) -> None:
        c.notify(
            "textDocument/didChange", {"textDocument": {"uri": u, "version": 2}, "contentChanges": [{"text": body}]}
        )

    opened(ou, org_text)
    ok(
        "an included file opened alone is checked as part of its policy: no mistake",
        c.diagnostics(ou) == [],
        c.diagnostics(ou),
    )
    opened(pu, main_text)
    changed(ou, org_text.replace("can see = member", "can see = nosuch"))
    found = c.diagnostics(ou)
    ok(
        "a mistake typed into it is marked on it, on its line",
        found
        and found[0]["range"]["start"]["line"] == 2
        and "org has no relation or permission 'nosuch'" in found[0]["message"],
        found,
    )
    changed(pu, main_text + "\n")
    found = c.diagnostics(ou)
    ok(
        "... and seen from the policy while it is not saved (the open buffer, whatever its URI's spelling)",
        found and "no relation or permission 'nosuch'" in found[0]["message"],
        found,
    )
    changed(ou, org_text)
    ok("fixed: its mistake is cleared", c.diagnostics(ou) == [], c.diagnostics(ou))
    c.notify("textDocument/didClose", {"textDocument": {"uri": ou}})
    with open(os.path.join(d, "org.authz"), "w", encoding="utf-8") as fh:
        fh.write(org_text.replace("can see = member", "can see = nosuch"))
    changed(pu, main_text)
    on_disk = uri(os.path.join(d, "org.authz"))
    found = c.diagnostics(on_disk)
    ok(
        "a mistake in an included file that is not open is published for it",
        found and "no relation or permission 'nosuch'" in found[0]["message"],
        found,
    )
    with open(os.path.join(d, "org.authz"), "w", encoding="utf-8") as fh:
        fh.write(org_text)
    changed(pu, main_text + "\n")
    ok("... and cleared when the file is fixed", c.diagnostics(on_disk) == [], c.diagnostics(on_disk))
    opened(tu, tests_text)
    syms = c.request("textDocument/documentSymbol", {"textDocument": {"uri": tu}})
    ok(
        "a test file's outline is its tests",
        [(s["name"], s["range"]["start"]["line"]) for s in syms] == [("first", 0), ("second", 3)],
        syms,
    )
    h = c.request(
        "textDocument/hover", {"textDocument": {"uri": pu}, "position": pos(main_text, "can edit = owner and", 5)}
    )
    ok("'is not null' in a condition is no deny", h and "has a deny" not in h["contents"]["value"], h)
    c.close()

print("lsp: all passed" if not fails else f"lsp: {fails} failed")
sys.exit(1 if fails else 0)
