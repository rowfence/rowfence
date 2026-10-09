"""Why, and how to grant: the smallest changes to the data that would give someone a permission they lack.

The permission's expression says where access can come from: a share, a row in a link table, a column, a
group the person could join, or the same permission on the object above. Each candidate change is tried in
a savepoint, as the policy's owner, then checked with authz.can as the person, and undone: only the ones
that grant it are kept, with what else they would grant: every other permission the person would hold, on the
object and on any other, and who else would hold the permission on the object, or no longer would. A preview
that writes and rolls back belongs to the command, not to the runtime.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .conditions import Bool, Cmp, Col, Const, In, IsNull, Node, Scalar, simple
from .connection import Db, Value, flag, number, text
from .parse import And, Cols, Expr, Loc, Ref, Relation, Source, Type, cols
from .sqlutil import lit, q, qt

if TYPE_CHECKING:
    from . import Compiler

DEPTH = 3  # how far up inheritance (rel.perm) and into groups it looks
LINKED = 3  # how many current parents or groups of an object it follows
TRIES = 40  # how many candidate changes (or combinations) it tries
SHOWN = 5


def settles(where: str) -> dict[str, Scalar] | None:
    """The columns' values that make a relation's `where` true, when it says no more than that
    ({role = 'admin'}, {active and kind in ('a', 'b')}); None for any other condition."""
    node = simple(where)
    out: dict[str, Scalar] = {}

    def walk(n: Node) -> bool:
        match n:
            case Col(name=c):
                out[c] = True
            case Bool(op="not", items=(Col(name=c),)):
                out[c] = False
            case (
                Cmp(op="=", left=Col(name=c), right=Const(value=v))
                | Cmp(op="=", left=Const(value=v), right=Col(name=c))
            ):
                if v is None:
                    return False
                out[c] = v
            case IsNull(item=Col(name=c), negated=False):
                out[c] = None
            case In(item=Col(name=c), values=values, negated=False):
                if values[0] is None:
                    return False
                out[c] = values[0]
            case Bool(op="and", items=items):
                return all(walk(x) for x in items)
            case _:
                return False
        return True

    return out if node is not None and walk(node) else None


def constant(v: Scalar) -> str:
    """A condition's constant as SQL."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    return lit(v) if isinstance(v, str) else str(v)


def holding(t: Type, columns: Cols, oid: str) -> list[tuple[str, str]]:
    """The columns that hold the id of t's object oid, each with its value as SQL: the id, or for a key of several
    columns (oid is then the key's row text) each of its fields."""
    if isinstance(columns, str):
        return [(columns, lit(oid))]
    key = f"({lit(oid)}::{t.keytype})"
    return [(c, f"{key}.{q(k)}") for c, (k, _) in zip(columns, t.key, strict=True)]


def more_of(items: Sequence[tuple[str, str, int]], first: str) -> list[str]:
    """(type, permission, n) in words, the permissions gained on as many objects of a type together, the one asked
    about (first) before the others: "view, edit on 3 more folders"."""
    groups: dict[tuple[str, int], list[str]] = {}
    for tn, pn, n in items:
        groups.setdefault((tn, n), []).append(pn)
    return [
        f"{', '.join(sorted(ps, key=lambda p: (p != first, p)))} on {n} more {tn}{'s' if n != 1 else ''}"
        for (tn, n), ps in groups.items()
    ]


@dataclass
class Held:
    objects: dict[tuple[str, str], int]  # how many objects of each type the person holds each permission on
    people: set[str]  # who holds the permission asked about on the object
    perms: set[str]  # every permission the person holds on the object


@dataclass
class Change:
    kind: str  # share | link | column
    text: str  # in words: "share viewer on project 1 with user 2"
    sql: str  # what makes it, run as the owner
    loc: Loc  # the policy line of the relation it adds to
    cost: int  # shares first, then rows in link tables, then changed columns


@dataclass
class Way:
    changes: list[Change]
    grants: bool = False
    more_objects: int = 0  # other objects of the type the person gains the permission on
    more_people: int = 0  # other people who gain it on this object
    fewer_people: int = 0  # people who lose it on this object (a column that changes hands)
    also: list[str] = field(default_factory=list)  # the other permissions the person gains on this object
    # the other permissions the person gains on other objects: (type, permission, on how many)
    elsewhere: list[tuple[str, str, int]] = field(default_factory=list)
    error: str | None = None

    @property
    def text(self) -> str:
        return " and ".join(c.text for c in self.changes)


@dataclass
class Answer:
    holds: bool
    explain: list[str]  # authz.explain's lines
    needs: str  # the permission's definition, and its line
    ways: list[Way] = field(default_factory=list)  # Ways that grant it, best first
    untried: list[Way] = field(default_factory=list)  # Ways the database refused to try (their error says why)
    notes: list[str] = field(default_factory=list)  # what no change to the data would do (conditions, denies)


class Grants:
    def __init__(self, c: Compiler, db: Db, ptype: str, pid: str) -> None:
        self.c, self.db, self.ptype, self.pid = c, db, ptype, pid
        self.notes: list[str] = []

    # --- reading what is there now -------------------------------------------------------------------
    def probe(self, sql: str, args: Sequence[Value] = ()) -> list[dict[str, Value]]:
        """Rows of a read that may fail, in a savepoint of its own: none when it does (an id its key's type can't
        hold, as `folder Engineering` for a bigint key: the changes tried on it then say why)."""
        from .database import savepoint

        try:
            with savepoint(self.db, "authz_grant_probe"):
                return self.db.rows(sql, list(args))
        except self.db.errors:
            return []

    def linked(self, t: Type, r: Relation, src: Source, st: str, sr: str | None, oid: str) -> list[str]:
        """The subjects of type st (#sr) that relation r's source links object oid to now."""
        sql = self.c.pair_sql(t, r, src, st, sr or "", "o", "s", match=("obj", lit(oid)))
        return [str(x["s"]) for x in self.probe(f"SELECT DISTINCT s::text AS s FROM ({sql}) p LIMIT {LINKED}")]

    def groups_of(self, st: str, sr: str) -> list[str]:
        """The st objects the person already holds sr on (the groups they are in): authz.list for a permission,
        the relation's own links for a relation."""
        g = self.c.types[st]
        if sr in g.perms:
            self.sign_in()
            return [text(x, "x") for x in self.probe(f"SELECT x FROM authz.list($1, $2) x LIMIT {LINKED}", [st, sr])]
        out: list[str] = []
        r = g.relations.get(sr)
        for src in r.sources if r else []:
            if r and (self.ptype, None) in src.subjects and src.kind != "roles":
                sql = self.c.pair_sql(g, r, src, self.ptype, "", "o", "s", match=("subj", lit(self.pid)))
                out += [str(x["o"]) for x in self.probe(f"SELECT DISTINCT o::text AS o FROM ({sql}) p LIMIT {LINKED}")]
        return list(dict.fromkeys(out))[:LINKED]

    def sign_in(self, who: bool = True) -> None:
        if who:
            self.db.rows("SELECT authz.act_as($1, $2)", [self.ptype, self.pid])
        else:
            self.db.rows("SELECT authz.act_as(NULL, NULL)")

    # --- the candidate changes ----------------------------------------------------------------------
    def direct(
        self, t: Type, r: Relation, src: Source, st: str, sid: str, sr: str = ""
    ) -> Callable[[str], Change | None]:
        """The change that links oid to subject sid through this source (None when it is a link table whose `where`
        doesn't say which values make it true)."""

        def make(oid: str) -> Change | None:
            if src.kind == "shared":
                who = f"{st}#{sr} {sid}" if sr else f"{st} {sid}"
                obj, subj = f"authz_int.canon({lit(t.name)}, {lit(oid)})", f"authz_int.canon({lit(st)}, {lit(sid)})"
                key = f"{t.name}.{r.name}.{st}#{sr}" if sr else f"{t.name}.{r.name}.{st}"
                # the share authz.share would make (it needs someone signed in who may share; this is the owner): only
                # one the relation's `shared if` allows, and one there already (that expired, say) made again without
                # an end, a start or a caveat, as authz.share makes it again
                return Change(
                    "share",
                    f"share {r.name} on {t.name} {oid} with {who}",
                    "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, "
                    f"subject_relation) SELECT {lit(t.name)}, {obj}, {lit(r.name)}, {lit(st)}, {subj}, {lit(sr)} "
                    f"WHERE authz_int.share_if({lit(key)}, {obj}, {lit(st)}, {subj}, {lit(sr)}) "
                    "ON CONFLICT ON CONSTRAINT shares_pkey "
                    "DO UPDATE SET expires_at = NULL, starts_at = NULL, caveat = NULL, caveat_args = NULL",
                    src.loc,
                    1,
                )
            # a row of a link table, or a column of the object's own row (relation() never asks for a custom
            # role's): the subject's columns, each with its value, and in a polymorphic source the one naming its type
            assert src.kind in ("table", "column"), f"{t.name}.{r.name}: no change for a {src.kind} source"
            on = src.subj_col if src.kind == "table" else src.column
            assert on, f"{t.name}.{r.name}: a source names its subject's columns"
            subject = holding(self.c.types[st], on, sid) + ([(src.type_col, lit(st))] if src.type_col else [])
            if src.kind == "table":
                assert src.table and src.obj_col, f"{t.name}.{r.name}: a link table names the object's columns"
                pairs = holding(t, src.obj_col, oid) + subject
                names, vals = [c for c, _ in pairs], [v for _, v in pairs]
                # a source with a `where`: the row must also hold what the condition asks, if it says which values
                held = settles(src.where) if src.where else {}
                if held is None or set(held) & set(names):
                    self.notes.append(
                        f"{t.name}.{r.name} wasn't tried: it reads {src.table} where {{{src.where}}}, and it isn't "
                        "known which values make that true"
                    )
                    return None
                more = ", ".join(f"{c} = {constant(v)}" for c, v in held.items())
                if held:
                    # the link's row may be there already, left out by the condition: then its columns change
                    same = " AND ".join(f"{q(c)} = {v}" for c, v in zip(names, vals, strict=True))
                    if self.probe(f"SELECT 1 AS x FROM {qt(src.table)} WHERE {same} LIMIT 1"):
                        sets = ", ".join(f"{q(c)} = {constant(v)}" for c, v in held.items())
                        return Change(
                            "link",
                            f"set {more} on {st} {sid}'s row of {src.table} for {t.name} {oid}",
                            f"UPDATE {qt(src.table)} SET {sets} WHERE {same}",
                            src.loc,
                            2,
                        )
                    names += list(held)
                    vals += [constant(v) for v in held.values()]
                return Change(
                    "link",
                    f"add {st} {sid} to {src.table} for {t.name} {oid}" + (f", with {more}" if held else ""),
                    f"INSERT INTO {qt(src.table)} ({', '.join(q(x) for x in names)}) VALUES ({', '.join(vals)})",
                    src.loc,
                    2,
                )
            return Change(
                "column",
                f"set {', '.join(cols(on))} of {t.name} {oid} to {sid}",
                f"UPDATE {qt(t.table)} r SET {', '.join(f'{q(c)} = {v}' for c, v in subject)} "
                f"WHERE {self.c.key_is(t, 'r', lit(oid))}",
                src.loc,
                3,
            )

        return make

    def ways(
        self, t: Type, oid: str, node: Expr, depth: int, seen: frozenset[tuple[str, str, str]]
    ) -> list[list[Change]]:
        """Candidate ways (lists of changes, all needed) that could make node hold on t oid for the person."""
        match node:
            case ("ref", name):
                if name in t.perms:
                    key = (t.name, oid, name)
                    if key in seen:
                        return []
                    return self.ways(t, oid, t.perms[name].expr, depth, seen | {key})
                return self.relation(t, oid, t.relations[name], depth, seen)
            case ("arrow", rel, perm):
                r = t.relations[rel]
                out: list[list[Change]] = []
                if depth >= DEPTH:
                    return out
                for src in r.sources:
                    for target, sr in src.subjects:
                        # a relation followed with a dot links to objects, not to groups or anyone (AZ301)
                        assert sr is None and target in self.c.types, f"{t.name}.{rel} is followed to {target}"
                        for x in self.linked(t, r, src, target, None, oid):
                            out += self.ways(self.c.types[target], x, Ref("ref", perm), depth + 1, seen)
                return out
            case ("cond", sql):
                self.notes.append(f"{t.name} {oid} must meet {{{sql}}}: no share or link changes that")
                return []
            case ("not", ("cond", sql)):
                self.notes.append(f"{t.name} {oid} must not meet {{{sql}}}: no share or link changes that")
                return []
            case ("not", _):
                self.notes.append(
                    f"a deny on {t.name} {oid} (not ...) may be what stops it: no share or link removes it"
                )
                return []
            case ("or", items):
                return [w for x in items for w in self.ways(t, oid, x, depth, seen)]
        # an `and` (the compiler's own arrow_on is never in a permission's expression): a change for each part that
        # may not hold yet (or none, if it holds already)
        assert isinstance(node, And), node
        combos: list[list[Change]] = [[]]
        for x in node.items:
            options = [*sorted(self.ways(t, oid, x, depth, seen), key=len)[:3], []]
            combos = [a + b for a in combos for b in options][:TRIES]
        return [c for c in combos if c]

    def relation(
        self, t: Type, oid: str, r: Relation, depth: int, seen: frozenset[tuple[str, str, str]]
    ) -> list[list[Change]]:
        out: list[list[Change]] = []
        for src in r.sources:
            if src.kind == "roles":
                continue
            for st, sr in src.subjects:
                if st == self.ptype and not sr:
                    ch = self.direct(t, r, src, st, self.pid)(oid)
                    if ch:
                        out.append([ch])
                elif sr and sr != "*":  # (every user, user:*, is no group to join: a share with it is never offered)
                    # a group the person is in already: link the object to it
                    for g in self.groups_of(st, sr):
                        ch = self.direct(t, r, src, st, g, sr)(oid)
                        if ch:
                            out.append([ch])
                    # a group the object is linked to already: put the person in it
                    if depth < DEPTH:
                        for g in self.linked(t, r, src, st, sr, oid):
                            out += self.ways(self.c.types[st], g, Ref("ref", sr), depth + 1, seen)
        return out

    # --- trying them ---------------------------------------------------------------------------------
    def counts(self, t: Type, oid: str, perm: str) -> Held:
        """What is held now: how many objects of each type the person holds each permission on, who holds perm on
        this one, and every permission the person holds on this one."""
        from .database import text_array

        kinds = [(x.name, p) for x in self.c.types.values() for p in self.c.public_perms(x)]
        self.sign_in()
        objects = {
            (text(r, "t"), text(r, "p")): number(r, "n")
            for r in self.db.rows(
                "SELECT k.t, k.p, (SELECT count(*) FROM authz.list(k.t, k.p)) AS n "
                "FROM unnest($1::text[], $2::text[]) k(t, p)",
                [text_array(tn for tn, _ in kinds), text_array(pn for _, pn in kinds)],
            )
        }
        held = self.db.rows("SELECT p FROM unnest(authz.perms($1, $2)) p", [t.name, oid])
        self.sign_in(False)
        people = self.db.rows("SELECT x FROM authz.who($1, $2, $3) x", [t.name, oid, perm])
        return Held(objects, {text(r, "x") for r in people}, {text(r, "p") for r in held})

    def attempt(self, way: Way, t: Type, oid: str, perm: str, before: Held) -> Way:
        from .database import Undo, savepoint

        try:
            with savepoint(self.db, "authz_grant"):
                self.sign_in(False)
                for ch in way.changes:
                    self.db.script(ch.sql)
                self.sign_in()
                way.grants = flag(
                    self.db.rows("SELECT coalesce(authz.can($1, $2, $3), false) AS ok", [t.name, oid, perm])[0], "ok"
                )
                if way.grants:
                    after = self.counts(t, oid, perm)
                    me = {self.pid} if self.ptype == "user" else set()  # authz.who lists users
                    way.more_people = len(after.people - before.people - me)
                    way.fewer_people = len(before.people - after.people)
                    way.also = sorted(after.perms - before.perms - {perm})
                    # what it gives on other objects: what is held now on how many, but this one (asked about, or
                    # said as "on it")
                    more = {k: n - before.objects[k] for k, n in after.objects.items()}
                    for p in [perm, *way.also]:
                        more[(t.name, p)] -= 1
                    way.more_objects = max(0, more.pop((t.name, perm)))
                    # (this object's type first, then the policy's order)
                    way.elsewhere = sorted(
                        ((tn, pn, n) for (tn, pn), n in more.items() if n > 0), key=lambda x: x[0] != t.name
                    )
                raise Undo
        except Undo:
            pass
        except self.db.errors as e:
            way.error = getattr(e, "message", str(e))
        return way


def how_to_grant(c: Compiler, db: Db, ptype: str, pid: str, type_name: str, oid: str, perm: str) -> Answer:
    """Whether (ptype, pid) holds perm on type_name oid, why (authz.explain), and if not, the changes that would
    grant it, best first. c: the compiled policy in force; runs in the caller's transaction and leaves nothing
    behind (each change is undone)."""
    if type_name not in c.types:
        raise KeyError(f"no type {type_name} in the policy")
    t = c.types[type_name]
    if perm not in t.perms and perm not in t.relations:
        raise KeyError(f"{type_name} has no permission {perm}")
    g = Grants(c, db, ptype, pid)
    g.sign_in(False)
    who = pid if ptype == "user" else f"{ptype}:{pid}"
    explain = (
        [text(x, "l") for x in db.rows("SELECT l FROM authz.explain($1, $2, $3, $4) l", [type_name, oid, perm, who])]
        if ptype == "user"
        else []
    )
    g.sign_in()
    holds = flag(db.rows("SELECT coalesce(authz.can($1, $2, $3), false) AS ok", [type_name, oid, perm])[0], "ok")
    if ptype != "user":
        explain = [text(x, "l") for x in db.rows("SELECT l FROM authz.explain($1, $2, $3) l", [type_name, oid, perm])]
    p = t.perms.get(perm)
    needs = f"{perm} = {p.src}  ({p.loc})" if p else f"{perm}: a relation ({t.relations[perm].loc})"
    answer = Answer(holds, explain, needs)
    if holds:
        return answer
    candidates: list[Way] = []
    seen_sql: set[tuple[str, ...]] = set()
    for changes in g.ways(t, oid, Ref("ref", perm), 0, frozenset()):
        key = tuple(ch.sql for ch in changes)
        if key not in seen_sql:
            seen_sql.add(key)
            candidates.append(Way(changes))
    candidates.sort(key=lambda w: (len(w.changes), sum(ch.cost for ch in w.changes)))
    before = g.counts(t, oid, perm)
    for way in candidates[:TRIES]:
        g.attempt(way, t, oid, perm, before)
    # the way that gives the least beside what was asked comes first: the fewest other permissions, on the object
    # and on others (and the fewest people who lose it), then the fewest other objects and people
    answer.ways = sorted(
        [w for w in candidates if w.grants],
        key=lambda w: (
            len(w.changes),
            len(w.also) + len(w.elsewhere) + w.fewer_people,
            w.more_people + w.more_objects + sum(n for _, _, n in w.elsewhere),
            sum(ch.cost for ch in w.changes),
        ),
    )[:SHOWN]
    answer.notes = [] if answer.ways else list(dict.fromkeys(g.notes))
    # a change that couldn't be made (the link table has another column that must be given, say) is no answer
    # either way: said, so "nothing grants it" isn't read where one change would
    answer.untried = [w for w in candidates[:TRIES] if w.error][:SHOWN]
    return answer


def describe(answer: Answer, who: str, type_name: str, oid: str, perm: str) -> str:
    """The answer as the command prints it."""
    out = []
    if answer.holds:
        out.append(f"yes: {who} holds {perm} on {type_name} {oid}")
        out += ["  " + x for x in answer.explain]
        return "\n".join(out)
    out.append(f"no: {who} does not hold {perm} on {type_name} {oid}")
    out += ["  " + x for x in answer.explain]
    out.append(f"{answer.needs}")
    if answer.ways:
        out.append("would be granted by:")
        for w in answer.ways:
            also = []
            if w.also:
                also.append(f"{', '.join(w.also)} on it")
            more = more_of(([(type_name, perm, w.more_objects)] if w.more_objects else []) + w.elsewhere, perm)
            if more:
                also.append(f"{', and '.join(more)} for {who}")
            if w.more_people:
                also.append(f"{perm} on it to {w.more_people} more {'people' if w.more_people != 1 else 'person'}")
            lines = sorted({str(ch.loc) for ch in w.changes})
            takes = (
                f" (takes {perm} on it from {w.fewer_people} {'person' if w.fewer_people == 1 else 'people'})"
                if w.fewer_people
                else ""
            )
            out.append(
                f"  {w.text}"
                + (f" (also gives {', and '.join(also)})" if also else "")
                + takes
                + f"  [{', '.join(lines)}]"
            )
    elif answer.untried:
        out.append("no single change that could be tried grants it")
    else:
        out.append("no single change to shares or links grants it")
    for w in answer.untried:
        out.append(f"could not be tried: {w.text} ({(w.error or '').splitlines()[0] if w.error else ''})")
    for n in answer.notes:
        out.append(f"note: {n}")
    return "\n".join(out)
