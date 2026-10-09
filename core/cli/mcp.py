"""The rowstile MCP server: `rowstile mcp`, the Model Context Protocol over stdin and stdout, for coding agents.

Its tools are the command's own: check, prove, review, test, why, lint, and push to a development database. Each
call runs the command once, in its own process, in the folder the server was started in (so rowstile.toml, the
policy and the database are found as the command finds them), and returns what the command printed. Nothing is
kept between calls.

    {"mcpServers": {"rowstile": {"command": "rowstile", "args": ["mcp"]}}}
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from typing import NamedTuple

from authzlib.connection import (
    Value as Json,  # what JSON holds: the same shape as a database value
)

HERE = os.path.dirname(os.path.abspath(__file__))
COMMAND = os.path.join(HERE, "rowstile_cli.py")
VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]  # newest first
TIMEOUT = 600  # seconds, for one call
ERROR = re.compile(r"^(?P<file>.+?): (?:(?P<inc>\S+) )?line (?P<line>\d+): (?P<message>.*)$", re.S)

INSTRUCTIONS = """rowstile compiles an access policy (.authz) into row-level security for Postgres.
The policy file and the database come from rowstile.toml in this project.
The loop after editing the policy: `check` (the first mistake, with its line), then `push` (the development
database only), then `test` (the policy's tests; `coverage` lists branches no test makes true).
`why` answers whether someone holds a permission, why, and the smallest changes that would grant it.
`prove` checks the invariants in many small worlds; `review` says what a change since a git ref does.
`lint` lists the ways around row-level security the database leaves open.
Production takes migrations (`rowstile migrate`), never `push`."""

Message = dict[str, Json]

POLICY: Json = {"type": "string", "description": "the policy file (default: rowstile.toml's `policy`)"}
WHO: Json = {"type": "string", "description": "who asks: user:42, bot:7 (a principal type and id), or anyone"}
OUTPUT: Json = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean", "description": "true when the command found nothing wrong"},
        "exit_code": {"type": "integer"},
        "output": {"type": "string", "description": "what the command printed"},
        "error": {"type": "object", "description": "check: the mistake, when there is one"},
    },
    "required": ["ok", "exit_code", "output"],
}


class Tool(NamedTuple):
    description: str
    properties: dict[str, Json]
    required: list[str]
    notes: dict[str, bool]  # MCP's annotations: readOnlyHint, destructiveHint, idempotentHint
    command: Callable[[Message], list[str]]  # the arguments to the command, from the call's arguments


TOOLS: dict[str, Tool] = {
    "check": Tool(
        "Compile the policy without a database and report its first mistake, with the file, line and code.",
        {"policy": POLICY},
        [],
        {"readOnlyHint": True},
        lambda a: ["check", *opt_policy(a)],
    ),
    "prove": Tool(
        "Check every invariant of the policy in many small worlds (no database): the smallest counterexample, "
        "or that none was found.",
        {"policy": POLICY, "worlds": {"type": "integer", "description": "how many worlds to try (default 400)"}},
        [],
        {"readOnlyHint": True},
        lambda a: ["prove", *opt("--worlds", a.get("worlds")), *opt_policy(a)],
    ),
    "review": Tool(
        "What the policy change since a git ref does: meaning, access, risk, tests and deploy (the pull request "
        "comment, as markdown). Needs git.",
        {"base": {"type": "string", "description": "the ref to compare with (default: main)"}, "policy": POLICY},
        [],
        {"readOnlyHint": True},
        lambda a: ["review", "--markdown", *opt("--base", a.get("base")), *opt_policy(a)],
    ),
    "test": Tool(
        "Run the policy's tests, the test files rowstile.toml names (or these), and the invariants, on the "
        "database; nothing stays. With coverage, the branches of each permission no test makes true.",
        {
            "files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "test files (default: rowstile.toml's `tests`)",
            },
            "coverage": {"type": "boolean"},
        },
        [],
        {"readOnlyHint": True},
        lambda a: ["test", *(["--coverage"] if a.get("coverage") else []), *strings(a.get("files"))],
    ),
    "why": Tool(
        "Whether someone holds a permission on an object, and why; if not, why not, and the smallest changes to "
        "the data that would grant it (each tried on the database and undone).",
        {
            "as": WHO,
            "type": {"type": "string", "description": "the policy's type, e.g. folder"},
            "id": {"type": "string"},
            "perm": {"type": "string", "description": "a permission of the type, e.g. view"},
        },
        ["as", "type", "id", "perm"],
        {"readOnlyHint": True},
        lambda a: [
            "why",
            "--as",
            plain("as", a["as"]),
            plain("type", a["type"]),
            ident(a["id"]),
            plain("perm", a["perm"]),
        ],
    ),
    "lint": Tool(
        "The ways around row-level security the database leaves open (authz.lint()): the app role owning a "
        "table, bypassing RLS, tables without rules, grants on masked columns, ...",
        {},
        [],
        {"readOnlyHint": True},
        lambda a: ["lint"],
    ),
    "push": Tool(
        "Bring the development database to the policy, with the migration production would get. Only a database "
        "marked as a development database (a person marks one with rowstile push --development; the first push "
        "to one with no policy marks it): production takes migrations (rowstile migrate).",
        {"policy": POLICY},
        [],
        {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
        lambda a: ["push", *opt_policy(a)],
    ),
}


def string(name: str, value: Json) -> str:
    """A tool's text argument: a string, or a number as written (an id). null, true, an object or a list is
    refused, not handed to the command as Python writes it ("None")."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError(f"{name}: a string, not {json.dumps(value)[:40]}")
    return str(value)


def plain(name: str, value: Json) -> str:
    """A tool's argument as the command takes it: never one of the command's own options. An agent that sends
    "--development" as the policy would mark the database itself, which is a person's to do."""
    text = string(name, value)
    if text.startswith("-"):
        raise ValueError(f"{name}: {text!r} starts with '-': a name or a value, not an option")
    return text


def ident(value: Json) -> str:
    """An object's id: any text (a negative number too), but not one of the command's options."""
    text = string("id", value)
    if text.startswith("--"):
        raise ValueError(f"id: {text!r} starts with '--': an id, not an option")
    return text


def opt(flag: str, value: Json) -> list[str]:
    return [flag, plain(flag.lstrip("-"), value)] if value not in (None, "") else []


def opt_policy(a: Message) -> list[str]:
    return [plain("policy", a["policy"])] if a.get("policy") else []


def strings(items: Json) -> list[str]:
    if items is None:
        return []
    if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
        raise ValueError("files: a list of file names")
    return [plain("files", x) for x in items]


def tool_list() -> list[Json]:
    return [
        {
            "name": name,
            "title": f"rowstile {name}",
            "description": desc,
            "inputSchema": {"type": "object", "properties": props, "required": required},
            "outputSchema": OUTPUT,
            "annotations": {"openWorldHint": False, **notes},
        }
        for name, (desc, props, required, notes, _) in TOOLS.items()
    ]


def run(dsn: str | None, args: list[str]) -> tuple[int, str]:
    """The command, once: (exit code, what it printed)."""
    argv = [sys.executable, COMMAND, *(["--db", dsn] if dsn else []), *args]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    try:
        p = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TIMEOUT, env=env
        )
    except subprocess.TimeoutExpired:
        return 2, f"rowstile {args[0]} took more than {TIMEOUT} s and was stopped"
    return p.returncode, p.stdout.decode("utf-8", "replace").replace("\r\n", "\n")


def call(dsn: str | None, name: Json, arguments: Json) -> Message:
    if not isinstance(name, str) or name not in TOOLS:
        raise KeyError(name)
    args = TOOLS[name].command(arguments if isinstance(arguments, dict) else {})
    code, out = run(dsn, args)
    result: Message = {"ok": code == 0, "exit_code": code, "output": out}
    if name == "check" and code != 0:
        from authzlib import errors

        first, mistake = errors.split(out.strip().split("\n")[0])
        m = ERROR.match(first)
        # a mistake in the policy: its line, and its code (each has one), not a file whose name reads like a line
        if m and mistake is not None and mistake in errors.CODES:
            # an included file is named relative to the policy's folder
            path = os.path.join(os.path.dirname(m.group("file")), m.group("inc")) if m.group("inc") else m.group("file")
            try:
                path = os.path.relpath(path)  # relative to the project, as the agent names files
            except ValueError:
                pass  # another drive
            # with the code's page: what the mistake means, and the same mistake fixed
            result["error"] = {
                "file": path.replace(os.sep, "/"),
                "line": int(m.group("line")),
                "message": m.group("message"),
                "code": mistake,
                "help": errors.page(mistake),
            }
            out += f"\n{errors.page(mistake)}"
    # a finding (a mistake, a failing test, a counterexample) is an answer; exit code 2 is a call that couldn't
    # run (no policy file, no database, a wrong argument), which the agent has to fix first
    return {
        "content": [{"type": "text", "text": out or "(no output)"}],
        "structuredContent": result,
        "isError": code not in (0, 1),
    }


class Server:
    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn

    def handle(self, msg: Message) -> Message | None:
        """The answer to one message (None for a notification)."""
        raw = msg.get("params")
        method, params, mid = msg.get("method"), raw if isinstance(raw, dict) else {}, msg.get("id")
        if mid is None:
            # a notification (notifications/initialized, notifications/cancelled, ...): no answer; a request whose id
            # is null (which MCP doesn't allow) is told so, or its client would wait for an answer
            null = "id" in msg and "method" in msg
            return error(None, -32600, "a request's id is a string or a number, not null") if null else None
        if raw is not None and not isinstance(raw, dict):
            return error(mid, -32602, f"{method}: params is an object (names and values), not {json.dumps(raw)[:40]}")
        if method == "initialize":
            from authzlib import __version__

            asked = params.get("protocolVersion")
            return ok(
                mid,
                {
                    "protocolVersion": asked if asked in VERSIONS else VERSIONS[0],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "rowstile", "title": "rowstile", "version": __version__},
                    "instructions": INSTRUCTIONS,
                },
            )
        if method == "ping":
            return ok(mid, {})
        if method == "tools/list":
            return ok(mid, {"tools": tool_list()})
        if method == "tools/call":
            try:
                return ok(mid, call(self.dsn, params.get("name"), params.get("arguments")))
            except KeyError as e:
                if e.args and e.args[0] == params.get("name"):
                    return error(mid, -32602, f"no tool {params.get('name')!r}: {', '.join(TOOLS)}")
                return error(mid, -32602, f"{params.get('name')}: missing argument {e}")
            except ValueError as e:
                return error(mid, -32602, f"{params.get('name')}: {e}")
        return error(mid, -32601, f"not supported: {method}")

    def answer(self, got: Json) -> Message | None:
        """The answer to one message as read: an error for one that isn't an object, None for a notification."""
        if not isinstance(got, dict):
            return error(None, -32600, "not a request")
        msg: Message = {str(k): v for k, v in got.items()}
        try:
            return self.handle(msg)
        except Exception as e:  # answer and carry on: a dead server stops the agent's whole session
            return error(msg.get("id"), -32603, f"{type(e).__name__}: {e}") if msg.get("id") is not None else None


def ok(mid: Json, result: Json) -> Message:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def error(mid: Json, code: int, message: str) -> Message:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(dsn: str | None = None) -> None:
    """Newline-delimited JSON-RPC on stdin and stdout; the log (nothing, for now) would go to stderr."""
    server = Server(dsn)
    out = sys.stdout.buffer
    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        answer: Json
        try:
            got = json.loads(raw)
        except (ValueError, RecursionError):  # nested too deep to read is not JSON this server takes either
            answer = error(None, -32700, "not JSON")
        else:
            if isinstance(got, list) and got:
                # a batch (protocol 2025-03-26 has them): each message answered, the answers in one array, and
                # nothing for notifications alone
                answers: list[Json] = [a for a in map(server.answer, got) if a is not None]
                answer = answers or None
            else:
                answer = server.answer(got)
        if answer is not None:
            out.write(json.dumps(answer).encode() + b"\n")
            out.flush()
