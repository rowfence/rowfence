"""Writing a migration where the app's own migration tool expects it.

    [migrations]                    in rowstile.toml
    tool = "alembic"                alembic | prisma | drizzle | sql | goose | dbmate | flyway
    dir  = "alembic/versions"       where the tool keeps its migrations (each tool has a default)
    lock = "db/policy.lock"         the lock file (default: next to the policy, <policy>.lock)

Each writer gets the migration's SQL and a name, and returns the files it wrote. File names start with the
time (UTC), as the tools do, so migrations sort in the order they were written.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import time
import uuid
from typing import TypedDict

from authzlib.statements import split

TOOLS = ("alembic", "prisma", "drizzle", "sql", "goose", "dbmate", "flyway")
DEFAULT_DIRS = {
    "alembic": "alembic/versions",
    "prisma": "prisma/migrations",
    "drizzle": "drizzle",
    "sql": "migrations",
    "goose": "migrations",
    "dbmate": "db/migrations",
    "flyway": "sql",
}


class Error(Exception):
    pass


class JournalEntry(TypedDict):
    idx: int
    version: str
    when: int  # milliseconds
    tag: str
    breakpoints: bool


class Journal(TypedDict):
    """Drizzle Kit's meta/_journal.json."""

    version: str
    dialect: str
    entries: list[JournalEntry]


def journal_of(value: object) -> Journal:
    """A journal as read from JSON, checked."""
    data: dict[str, object] = {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}
    raw = data.get("entries")
    if not isinstance(raw, list):
        raise Error("drizzle's meta/_journal.json isn't a journal (no entries)")
    entries: list[JournalEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            raise Error(f"drizzle's journal has an entry that isn't one: {item!r}")
        e: dict[str, object] = {str(k): v for k, v in item.items()}
        entries.append(
            {
                "idx": int(str(e["idx"])),
                "version": str(e.get("version", "7")),
                "when": int(str(e.get("when", 0))),
                "tag": str(e["tag"]),
                "breakpoints": bool(e.get("breakpoints", True)),
            }
        )
    return {
        "version": str(data.get("version", "7")),
        "dialect": str(data.get("dialect", "postgresql")),
        "entries": entries,
    }


def slug(name: str) -> str:
    """The migration's name: authz_ first, so its files are easy to tell (and to mark as generated)."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "policy"
    return s if s.startswith("authz_") or s == "authz" else f"authz_{s}"


def generated_patterns(tool: str, folder_rel: str, lock_rel: str) -> list[str]:
    """The .gitattributes lines that mark what rowstile migrate writes as generated."""
    pat = f"{folder_rel}/*_authz_*/**" if tool == "prisma" else f"{folder_rel}/*_authz_*"
    return [f"{lock_rel} linguist-generated=true", f"{pat} linguist-generated=true"]


def mark_generated(root: str, lines: list[str]) -> str | None:
    """Adds the lines to root/.gitattributes (made if missing), so GitHub and GitLab collapse generated
    files in reviews. Returns the path if it changed it."""
    path = os.path.join(root, ".gitattributes")
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        text = ""
    missing = [x for x in lines if x not in text.split("\n")]
    if not missing:
        return None
    head = "" if "# rowstile" in text else "# rowstile writes these: reviews show them collapsed\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text + ("\n" if text and not text.endswith("\n") else "") + head + "\n".join(missing) + "\n")
    return path


def stamp(now: float | None = None) -> str:
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(now))


def write(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


def write_migration(tool: str, folder: str, name: str, sql: str, now: float | None = None) -> list[str]:
    """Writes the migration for `tool` in `folder`; returns the paths written."""
    if tool not in TOOLS:
        raise Error(f"unknown migration tool '{tool}' (use one of {', '.join(TOOLS)})")
    name = slug(name)
    ts = stamp(now)
    # after every migration already there, even ones written the same second
    existing = [
        m.group(1)
        for f in (os.listdir(folder) if os.path.isdir(folder) else [])
        for m in [re.match(r"^V?(\d{14})", f)]
        if m
    ]
    if existing and max(existing) >= ts:
        ts = stamp(calendar.timegm(time.strptime(max(existing), "%Y%m%d%H%M%S")) + 1)
    if tool == "sql":
        return [write(os.path.join(folder, sql_file_name(folder, name, ts)), sql)]
    if tool == "flyway":
        # the SQL holds ${ (a dollar quote before a JSON object), which Flyway would read as a placeholder: its
        # script config file, beside the migration, turns that off for this script
        path = os.path.join(folder, f"V{ts}__{name}.sql")
        return [write(path, sql), write(path + ".conf", "placeholderReplacement=false\n")]
    if tool == "dbmate":
        return [write(os.path.join(folder, f"{ts}_{name}.sql"), f"-- migrate:up\n{sql}\n-- migrate:down\n")]
    if tool == "goose":
        return [
            write(
                os.path.join(folder, f"{ts}_{name}.sql"),
                f"-- +goose Up\n-- +goose StatementBegin\n{sql}-- +goose StatementEnd\n",
            )
        ]
    if tool == "prisma":
        return [write(os.path.join(folder, f"{ts}_{name}", "migration.sql"), sql)]
    if tool == "drizzle":
        return drizzle(folder, name, sql, now)
    return alembic(folder, name, sql, now)


def sql_file_name(folder: str, name: str, ts: str) -> str:
    """Plain SQL files are named like the ones already there: numbered (0005_name.sql) after numbered ones,
    so they sort in order, else starting with the time."""
    numbers = [
        m.group(1)
        for f in (os.listdir(folder) if os.path.isdir(folder) else [])
        for m in [re.match(r"^(\d{1,13})_.*\.sql$", f)]
        if m
    ]
    if numbers:
        width = max(len(n) for n in numbers)
        return f"{max(int(n) for n in numbers) + 1:0{width}d}_{name}.sql"
    return f"{ts}_{name}.sql"


# --- Drizzle Kit: numbered files, a journal, and a snapshot per migration ------------------------------
def drizzle(folder: str, name: str, sql: str, now: float | None) -> list[str]:
    """drizzle-kit migrate runs the journal's entries in order, splitting each file at its statement
    breakpoints. A snapshot per migration keeps drizzle-kit generate working: ours copies the one before
    (rowstile changes nothing drizzle-kit models), as drizzle-kit generate --custom does."""
    meta = os.path.join(folder, "meta")
    journal_path = os.path.join(meta, "_journal.json")
    journal: Journal = {"version": "7", "dialect": "postgresql", "entries": []}
    if os.path.exists(journal_path):
        with open(journal_path, encoding="utf-8") as fh:
            journal = journal_of(json.load(fh))
    idx = max((e["idx"] for e in journal["entries"]), default=-1) + 1
    tag = f"{idx:04d}_{name}"
    body = "\n--> statement-breakpoint\n".join((f"{c}\n" if c else "") + s + ";" for c, s in split(sql))
    written = [write(os.path.join(folder, f"{tag}.sql"), body + "\n")]
    prev: dict[str, object] | None = None
    if journal["entries"]:
        last = max(journal["entries"], key=lambda e: e["idx"])
        p = os.path.join(meta, f"{last['idx']:04d}_snapshot.json")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                got = json.load(fh)
            prev = {str(k): v for k, v in got.items()} if isinstance(got, dict) else None
    snap: dict[str, object] = (
        dict(prev)
        if prev
        else {
            "version": "7",
            "dialect": "postgresql",
            "tables": {},
            "enums": {},
            "schemas": {},
            "sequences": {},
            "roles": {},
            "policies": {},
            "views": {},
            "_meta": {"columns": {}, "schemas": {}, "tables": {}},
        }
    )
    prev_id = str(prev["id"]) if prev else "00000000-0000-0000-0000-000000000000"
    snap["prevId"] = prev_id
    snap["id"] = str(uuid.UUID(hashlib.sha256((prev_id + sql).encode()).hexdigest()[:32]))
    written.append(write(os.path.join(meta, f"{idx:04d}_snapshot.json"), json.dumps(snap, indent=2) + "\n"))
    journal["entries"].append(
        {
            "idx": idx,
            "version": journal["version"],
            "when": int((now if now is not None else time.time()) * 1000),
            "tag": tag,
            "breakpoints": True,
        }
    )
    written.append(write(journal_path, json.dumps(journal, indent=2) + "\n"))
    return written


# --- Alembic: a revision after the current head, with its SQL beside it --------------------------------
REVISION = re.compile(r"^revision\s*(?::\s*str\s*)?=\s*['\"]([^'\"]+)['\"]", re.M)
DOWN = re.compile(r"^down_revision\s*(?::[^=]*)?=\s*(.+)$", re.M)


def alembic_heads(folder: str) -> list[str]:
    revs: set[str] = set()
    downs: set[str] = set()
    for f in os.listdir(folder) if os.path.isdir(folder) else []:
        if not f.endswith(".py"):
            continue
        with open(os.path.join(folder, f), encoding="utf-8") as fh:
            text = fh.read()
        m = REVISION.search(text)
        if not m:
            continue
        revs.add(m.group(1))
        d = DOWN.search(text)
        if d:
            downs.update(re.findall(r"['\"]([^'\"]+)['\"]", d.group(1)))
    return sorted(revs - downs)


def alembic(folder: str, name: str, sql: str, now: float | None) -> list[str]:
    heads = alembic_heads(folder)
    if len(heads) > 1:
        raise Error(f"{folder} has several heads ({', '.join(heads)}): merge them first (alembic merge heads)")
    down = heads[0] if heads else None
    rev = hashlib.sha256(((down or "") + sql).encode()).hexdigest()[:12]
    base = f"{rev}_{name}"
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now))
    py = f'''"""rowstile: {name.replace("_", " ")}

Revision ID: {rev}
Revises: {down or ""}
Create Date: {when}

Generated by rowstile migrate from the policy: the SQL is in {base}.sql, beside this file. Don't edit
either; change the policy and run rowstile migrate again.
"""
from pathlib import Path

from alembic import op

revision = "{rev}"
down_revision: str | None = {down!r}
branch_labels = None
depends_on = None


def upgrade() -> None:
    sql = Path(__file__).with_suffix(".sql").read_text(encoding="utf-8")
    # as one script, straight to the driver: the SQL has % signs and colons, which are not parameters
    op.get_bind().exec_driver_sql(sql, execution_options={{"no_parameters": True}})


def downgrade() -> None:
    raise NotImplementedError("a rowstile migration isn't undone: change the policy back and write a new one")
'''
    return [write(os.path.join(folder, f"{base}.py"), py), write(os.path.join(folder, f"{base}.sql"), sql)]
