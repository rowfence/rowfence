"""A small PostgreSQL client (protocol 3, extended query protocol, text results), standard
library only. Enough for the rowstile command and tests: trust, password, MD5 and
SCRAM-SHA-256 authentication (bound to the TLS channel when the server offers it, as channel_binding
says); TCP (with TLS, as sslmode says) or Unix sockets.

    conn = connect(host="/var/run/postgresql", user="app_user", password="...", database="app")
    conn.query("SELECT authz.can($1, $2, $3)", ["file", "11", "view"])   # -> [(True,)]
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import socket
import ssl
import stringprep
import struct
import sys
import unicodedata
import urllib.parse
from collections.abc import Callable, Sequence
from typing import TypeAlias, TypedDict

# what a column holds, decoded from its text form: NULL, a boolean, an integer, text, an array, or JSON
Value: TypeAlias = "None | bool | int | float | str | list[Value] | dict[str, Value]"
# the fields of an error or a notice: one letter each (M the message, C the code, D the detail, H the hint)
Fields: TypeAlias = "dict[str, str]"


class ConnectArgs(TypedDict):
    host: str
    port: int
    user: str
    password: str | None
    database: str
    options: str | None
    timeout: float
    sslmode: str                # disable | allow | prefer | require | verify-ca | verify-full
    sslrootcert: str | None     # the certificates verify-ca and verify-full trust (default: the system's)
    channel_binding: str        # disable | prefer | require


class PgError(Exception):
    def __init__(self, fields: Fields) -> None:
        self.fields = fields
        self.code = fields.get("C", "XX000")
        self.message = fields.get("M", "error")
        super().__init__(f"{self.code}: {self.message}")


class ProtocolError(Exception):
    pass


def _parse_array(text: str) -> list[str | None]:
    """Parse a one-dimensional Postgres array literal ({a,"b c",NULL}) into a list of str/None."""
    if not text or text[0] != "{":
        raise ProtocolError(f"not an array: {text!r}")
    out: list[str | None] = []
    i, n = 1, len(text)
    if text == "{}":
        return out
    while i < n:
        if text[i] == '"':
            i += 1
            buf = []
            while text[i] != '"':
                if text[i] == "\\":
                    i += 1
                buf.append(text[i])
                i += 1
            i += 1
            out.append("".join(buf))
        else:
            j = i
            while text[j] not in ",}":
                j += 1
            word = text[i:j]
            out.append(None if word == "NULL" else word)
            i = j
        if text[i] == "}":
            break
        i += 1   # the comma
    return out


_INT = {20, 21, 23, 26}
_INT_ARRAYS = {1005, 1007, 1016}
_TEXT_ARRAYS = {1009, 1015, 1002, 199, 1014, 2951}


def _convert(oid: int, value: bytes | None) -> Value:
    if value is None:
        return None
    text = value.decode()
    if oid == 16:
        return text == "t"
    if oid in _INT:
        return int(text)
    if oid in (114, 3802):
        return json.loads(text)
    try:
        if oid in _TEXT_ARRAYS:
            return list(_parse_array(text))
        if oid in _INT_ARRAYS:
            return [None if x is None else int(x) for x in _parse_array(text)]
        if oid == 1000:
            return [None if x is None else x == "t" for x in _parse_array(text)]
    except (ValueError, IndexError, ProtocolError):
        return text             # two dimensions, or bounds ([0:1]={a,b}): as Postgres writes it
    return text


class Connection:
    def __init__(self, sock: socket.socket, user: str, password: str | None, database: str, options: str | None,
                 channel_binding: str = "prefer") -> None:
        self.sock = sock
        self.buf = b""
        self.params: dict[str, str] = {}
        self.in_error = False
        self.busy = False          # a query was sent and its answer not fully read (the connection is unusable)
        self.on_notice: Callable[[Fields], None] | None = None  # called with each NOTICE / WARNING the server sends
        self.address: tuple[str, int] | None = None     # where connect() went, for cancel()
        self.backend: tuple[int, int] | None = None     # this session's process id and key, for cancel()
        self._startup(user, password, database, options, channel_binding)

    # --- framing ----------------------------------------------------------
    def _send(self, kind: bytes, payload: bytes = b"") -> None:
        self.sock.sendall(kind + struct.pack("!i", len(payload) + 4) + payload)

    def _recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProtocolError("the server closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read(self) -> tuple[bytes, bytes]:
        head = self._recv_exact(5)
        kind, length = head[:1], struct.unpack("!i", head[1:])[0]
        return kind, self._recv_exact(length - 4)

    def _read_or(self, error: PgError | None) -> tuple[bytes, bytes]:
        """The next message; if the server closed the connection after an error (a FATAL one: it was ended, or
        is shutting down), that error, which says why."""
        try:
            return self._read()
        except (ProtocolError, OSError):
            if error is not None:
                raise error from None
            raise

    def cancel(self) -> None:
        """Asks the server to stop the statement this connection is running (a CancelRequest, on a connection of
        its own), then closes this one: its transaction is rolled back."""
        if self.address is not None and self.backend is not None:
            try:
                sock = _socket(*self.address, timeout=3)
                sock.sendall(struct.pack("!iiii", 16, 80877102, *self.backend))
                sock.close()
            except OSError:
                pass
        self.sock.close()

    @staticmethod
    def _cstr(s: str) -> bytes:
        return s.encode() + b"\0"

    @staticmethod
    def _fields(payload: bytes) -> Fields:
        fields: Fields = {}
        for part in payload.split(b"\0"):
            if part:
                fields[chr(part[0])] = part[1:].decode(errors="replace")
        return fields

    # --- start-up and authentication --------------------------------------
    def _startup(self, user: str, password: str | None, database: str, options: str | None,
                 channel_binding: str = "prefer") -> None:
        body = struct.pack("!i", 196608)
        params = {"user": user, "database": database, "client_encoding": "UTF8",
                  "application_name": "rowstile"}
        if options:
            params["options"] = options
        for k, v in params.items():
            body += self._cstr(k) + self._cstr(v)
        body += b"\0"
        self.sock.sendall(struct.pack("!i", len(body) + 4) + body)
        scram: _Scram | None = None
        bound = False               # signed in with SCRAM bound to this TLS channel, the server's proof checked
        while True:
            kind, payload = self._read()
            if kind == b"R":
                code = struct.unpack("!i", payload[:4])[0]
                if code == 0:
                    if channel_binding == "require" and not bound:
                        raise ProtocolError("the server signed this connection in without channel binding, and "
                                            "channel_binding=require asks for it")
                    continue
                if password is None:
                    raise ProtocolError("the server asks for a password")
                if code == 3:
                    self._send(b"p", self._cstr(password))
                elif code == 5:
                    salt = payload[4:8]
                    inner = hashlib.md5(password.encode() + user.encode()).hexdigest()
                    outer = hashlib.md5(inner.encode() + salt).hexdigest()
                    self._send(b"p", self._cstr("md5" + outer))
                elif code == 10:
                    mechs = [m.decode() for m in payload[4:].split(b"\0") if m]
                    scram = _Scram(password, *self._binding(mechs, channel_binding))
                    first = scram.client_first().encode()
                    self._send(b"p", self._cstr(scram.mechanism) + struct.pack("!i", len(first)) + first)
                elif code == 11 and scram is not None:
                    self._send(b"p", scram.client_final(payload[4:].decode()).encode())
                elif code == 12 and scram is not None:
                    scram.verify(payload[4:].decode())
                    bound = scram.binding is not None
                else:
                    raise ProtocolError(f"unsupported authentication method {code}")
            elif kind == b"E":
                raise PgError(self._fields(payload))
            elif kind == b"S":
                k, v = payload.split(b"\0")[:2]
                self.params[k.decode()] = v.decode()
            elif kind == b"K":
                pid, key = struct.unpack("!ii", payload[:8])
                self.backend = (pid, key)
            elif kind == b"Z":
                return
            # N (notice): ignored

    def _binding(self, mechs: list[str], channel_binding: str) -> tuple[str, bytes | None]:
        """How SCRAM starts on this connection (its GS2 header), and what binds it to the TLS channel: the hash
        of the server's certificate (tls-server-end-point, RFC 5929), when the server offers SCRAM-SHA-256-PLUS
        and channel_binding isn't disable. A server in the middle has another certificate, and then the
        password exchange it passes on fails."""
        tls = isinstance(self.sock, ssl.SSLSocket)
        data = None
        if tls and channel_binding != "disable" and "SCRAM-SHA-256-PLUS" in mechs:
            data = _end_point(self.sock)
        if data is not None:
            return "p=tls-server-end-point,,", data
        if channel_binding == "require":
            raise ProtocolError("channel_binding=require needs TLS (sslmode=require or stronger)" if not tls
                                else "the server doesn't offer channel binding (SCRAM-SHA-256-PLUS), and "
                                     "channel_binding=require asks for it" if "SCRAM-SHA-256-PLUS" not in mechs
                                else "the server's certificate is signed in a way channel binding has no hash for, "
                                     "and channel_binding=require asks for it")
        if "SCRAM-SHA-256" not in mechs:
            raise ProtocolError(f"unsupported SASL mechanisms {mechs}")
        # y: this client could have bound the channel and the server didn't offer to (the server checks that it
        # really didn't); n: it couldn't, or was told not to
        return ("y,," if tls and channel_binding != "disable" and "SCRAM-SHA-256-PLUS" not in mechs else "n,,"), None

    # --- queries ------------------------------------------------------------
    def query(self, sql: str, args: Sequence[object] = ()) -> list[tuple[Value, ...]]:
        """Run one statement with $1..$n parameters (sent as text: str() of each, JSON for a dict or list); returns a list of tuples."""
        rows, _ = self.query_described(sql, args)
        return rows

    def query_described(self, sql: str, args: Sequence[object] = ()) -> tuple[list[tuple[Value, ...]], list[str]]:
        bind = b"\0\0" + struct.pack("!hh", 0, len(args))
        for a in args:
            if a is None:
                bind += struct.pack("!i", -1)
            else:
                if isinstance(a, bool):
                    a = "true" if a else "false"
                elif isinstance(a, (dict, list)):
                    a = json.dumps(a)
                v = str(a).encode()
                if b"\0" in v:
                    raise ValueError("parameters cannot contain NUL characters")
                bind += struct.pack("!i", len(v)) + v
        bind += struct.pack("!h", 0)
        msg = (b"P" + struct.pack("!i", 4 + 1 + len(sql.encode()) + 1 + 2) + b"\0" + self._cstr(sql) + struct.pack("!h", 0) +
               b"B" + struct.pack("!i", len(bind) + 4) + bind +
               b"D" + struct.pack("!i", 6) + b"P\0" +
               b"E" + struct.pack("!i", 9) + b"\0" + struct.pack("!i", 0) +
               b"S" + struct.pack("!i", 4))
        self.busy = True
        self.sock.sendall(msg)
        rows: list[tuple[Value, ...]] = []
        cols: list[tuple[str, int]] = []
        error: PgError | None = None
        while True:
            kind, payload = self._read_or(error)
            if kind == b"T":
                n = struct.unpack("!h", payload[:2])[0]
                pos, cols = 2, []
                for _ in range(n):
                    end = payload.index(b"\0", pos)
                    name = payload[pos:end].decode()
                    oid = struct.unpack("!i", payload[end + 7:end + 11])[0]
                    cols.append((name, oid))
                    pos = end + 19
            elif kind == b"D":
                n = struct.unpack("!h", payload[:2])[0]
                pos = 2
                row: list[Value] = []
                for i in range(n):
                    ln = struct.unpack("!i", payload[pos:pos + 4])[0]
                    pos += 4
                    val = None if ln < 0 else payload[pos:pos + ln]
                    pos += max(ln, 0)
                    row.append(_convert(cols[i][1], val))
                rows.append(tuple(row))
            elif kind == b"E":
                error = PgError(self._fields(payload))
            elif kind == b"N":
                if self.on_notice:
                    self.on_notice(self._fields(payload))
            elif kind == b"Z":
                self.in_error = payload == b"E"
                self.busy = False
                if error:
                    raise error
                return rows, [c[0] for c in cols]
            # 1, 2, n, C, A, S: nothing to do

    def execute(self, sql: str) -> list[tuple[Value, ...]]:
        """Run a statement without parameters (BEGIN, COMMIT, ...)."""
        return self.query(sql)

    def script(self, sql: str) -> None:
        """Run one or many statements without parameters (the simple query protocol), such as a
        compiled policy. Results are dropped; the first error is raised once the server is done."""
        data = sql.encode()
        if b"\0" in data:
            raise ValueError("SQL cannot contain NUL characters")
        self.busy = True
        self._send(b"Q", data + b"\0")
        error: PgError | None = None
        while True:
            kind, payload = self._read_or(error)
            if kind == b"E":
                error = error or PgError(self._fields(payload))
            elif kind == b"N":
                if self.on_notice:
                    self.on_notice(self._fields(payload))
            elif kind == b"Z":
                self.in_error = payload == b"E"
                self.busy = False
                if error:
                    raise error
                return
            # T, D, C, I, S, ...: nothing to keep

    def cursor(self) -> Cursor:
        return Cursor(self)

    def close(self) -> None:
        try:
            self._send(b"X")
        except OSError:
            pass
        self.sock.close()


class Cursor:
    """Just enough DB-API for the generated Python client: %s placeholders, fetchone/fetchall, description."""

    def __init__(self, conn: Connection) -> None:
        self.conn = conn
        self.rows: list[tuple[Value, ...]] = []
        self.description: list[tuple[str, None, None, None, None, None, None]] | None = None

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, args: Sequence[object] = (), /) -> None:
        parts = sql.split("%s")
        if len(parts) - 1 != len(args):
            raise ValueError("the number of %s placeholders and arguments differ")
        text = parts[0] + "".join(f"${i + 1}" + p for i, p in enumerate(parts[1:]))
        self.rows, names = self.conn.query_described(text, list(args))
        self.description = [(n, None, None, None, None, None, None) for n in names]

    def fetchone(self) -> tuple[Value, ...] | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[tuple[Value, ...]]:
        rows, self.rows = self.rows, []
        return rows


def _saslprep(password: str) -> str:
    """The password as SCRAM prepares it (RFC 4013): what maps to nothing is dropped, other spaces become a space,
    compatibility characters their plain form. One with a prohibited character is used as it is, as Postgres does."""
    if password.isascii():
        return password
    mapped = "".join(" " if stringprep.in_table_c12(c) else c for c in password if not stringprep.in_table_b1(c))
    out = unicodedata.normalize("NFKC", mapped)
    prohibited = (stringprep.in_table_a1, stringprep.in_table_c12, stringprep.in_table_c21_c22, stringprep.in_table_c3,
                  stringprep.in_table_c4, stringprep.in_table_c5, stringprep.in_table_c6, stringprep.in_table_c7,
                  stringprep.in_table_c8, stringprep.in_table_c9)
    return password if any(f(c) for c in out for f in prohibited) else out


# the hash a certificate was signed with, by its signature algorithm (an OID's bytes); MD5 and SHA-1 count as
# SHA-256 for channel binding (RFC 5929)
def _oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        part = bytes([arc & 0x7F])
        while arc > 0x7F:
            arc >>= 7
            part = bytes([arc & 0x7F | 0x80]) + part
        out += part
    return out


_SIGNED_WITH = {_oid(o): h for o, h in (
    ("1.2.840.113549.1.1.4", "sha256"), ("1.2.840.113549.1.1.5", "sha256"), ("1.2.840.113549.1.1.11", "sha256"),
    ("1.2.840.113549.1.1.12", "sha384"), ("1.2.840.113549.1.1.13", "sha512"), ("1.2.840.113549.1.1.14", "sha224"),
    ("1.2.840.10045.4.1", "sha256"), ("1.2.840.10045.4.3.1", "sha224"), ("1.2.840.10045.4.3.2", "sha256"),
    ("1.2.840.10045.4.3.3", "sha384"), ("1.2.840.10045.4.3.4", "sha512"))}
_RSA_PSS = _oid("1.2.840.113549.1.1.10")            # names its hash in its parameters (SHA-1 if it names none)
_PSS_HASHES = {_oid("2.16.840.1.101.3.4.2.1"): "sha256", _oid("2.16.840.1.101.3.4.2.2"): "sha384",
               _oid("2.16.840.1.101.3.4.2.3"): "sha512", _oid("2.16.840.1.101.3.4.2.4"): "sha224"}


def _der(data: bytes, at: int) -> tuple[int, int, int]:
    """The DER element at `at`: its tag, where its content starts, and where it ends."""
    length, start = data[at + 1], at + 2
    if length & 0x80:
        n = length & 0x7F
        length, start = int.from_bytes(data[start:start + n], "big"), start + n
    return data[at], start, start + length


def _signature_hash(cert: bytes) -> str | None:
    """The hash a certificate (DER) was signed with, for channel binding; None if its signature has none (Ed25519)
    or isn't one this knows. A certificate is SEQUENCE { what is signed, the signature's algorithm, the signature }."""
    try:
        _, start, _ = _der(cert, 0)
        _, _, signed_end = _der(cert, start)
        _, algorithm, algorithm_end = _der(cert, signed_end)
        tag, oid_start, oid_end = _der(cert, algorithm)
    except IndexError:
        return None
    oid = cert[oid_start:oid_end]
    if tag != 6:
        return None
    if oid == _RSA_PSS:
        parameters = cert[oid_end:algorithm_end]
        return next((h for o, h in _PSS_HASHES.items() if bytes([6, len(o)]) + o in parameters), "sha256")
    return _SIGNED_WITH.get(oid)


def _end_point(sock: socket.socket) -> bytes | None:
    """tls-server-end-point: the hash of the server's certificate, or None if there is nothing to hash it with."""
    cert = sock.getpeercert(binary_form=True) if isinstance(sock, ssl.SSLSocket) else None
    name = _signature_hash(cert) if cert else None
    return hashlib.new(name, cert).digest() if cert and name else None


class _Scram:
    def __init__(self, password: str, header: str = "n,,", binding: bytes | None = None) -> None:
        self.password = _saslprep(password).encode()
        self.header = header        # GS2: n,, (no channel binding), y,, (the server offered none), p=...,, (bound)
        self.binding = binding
        self.mechanism = "SCRAM-SHA-256-PLUS" if binding is not None else "SCRAM-SHA-256"
        self.nonce = base64.b64encode(os.urandom(18)).decode()
        self.first_bare = ""
        self.auth_message = b""
        self.server_key = b""

    def client_first(self) -> str:
        self.first_bare = f"n=,r={self.nonce}"
        return self.header + self.first_bare

    def client_final(self, server_first: str) -> str:
        attrs = dict(kv.split("=", 1) for kv in server_first.split(","))
        if not attrs["r"].startswith(self.nonce):
            raise ProtocolError("SCRAM: the server's nonce does not extend ours")
        salted = hashlib.pbkdf2_hmac("sha256", self.password, base64.b64decode(attrs["s"]), int(attrs["i"]))
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored = hashlib.sha256(client_key).digest()
        bind = base64.b64encode(self.header.encode() + (self.binding or b"")).decode()      # biws for n,,
        without_proof = f"c={bind},r={attrs['r']}"
        self.auth_message = f"{self.first_bare},{server_first},{without_proof}".encode()
        signature = hmac.new(stored, self.auth_message, hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, signature, strict=True))
        self.server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        return f"{without_proof},p={base64.b64encode(proof).decode()}"

    def verify(self, server_final: str) -> None:
        attrs = dict(kv.split("=", 1) for kv in server_final.split(","))
        want = hmac.new(self.server_key, self.auth_message, hashlib.sha256).digest()
        if not hmac.compare_digest(base64.b64decode(attrs.get("v", "")), want):
            raise ProtocolError("SCRAM: the server could not prove it knows the password")


SSLMODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")
CHANNEL_BINDINGS = ("disable", "prefer", "require")
# what a connection string may say, and where it goes; anything else in a keyword string is refused
KEYS = {"host": "host", "port": "port", "user": "user", "password": "password", "dbname": "database",
        "sslmode": "sslmode", "sslrootcert": "sslrootcert", "options": "options", "connect_timeout": "timeout",
        "channel_binding": "channel_binding"}
# options that would change what the connection is, which this client can't do: never dropped in silence
REFUSED = {"sslcert": "client certificates", "sslkey": "client certificates", "service": "connection services",
           "passfile": "password files", "gssencmode": "GSS encryption", "requirepeer": "requirepeer"}


def parse_dsn(text: str | None) -> ConnectArgs:
    """connect() arguments from "host=... port=... user=... password=... dbname=... sslmode=..." or a
    postgresql:// URL (its ?options too), with PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE, PGSSLMODE,
    PGSSLROOTCERT and PGCHANNELBINDING for whatever is left out. Raises ValueError for a setting it can't honour: an unknown one in a
    keyword string, or one of REFUSED. A URL's other options (an ORM's own: ?schema=, ?pgbouncer=) are left to
    whoever they are for."""
    out: dict[str, str] = {}

    def setting(k: str, v: str, strict: bool) -> None:
        if k in REFUSED:
            raise ValueError(f"the connection asks for {REFUSED[k]} ({k}={v}), which the rowstile command doesn't do")
        if k in KEYS:
            out[KEYS[k]] = v
        elif strict and k not in ("application_name", "target_session_attrs"):
            raise ValueError(f"unknown connection setting '{k}' (use host, port, user, password, dbname, sslmode)")

    if text and re.match(r"postgres(ql)?://", text):
        # a URL: postgresql://user:password@host:port/dbname?sslmode=require
        u = urllib.parse.urlsplit(text)
        try:
            port = u.port
        except ValueError:
            raise ValueError("the URL's port isn't a number: a #, ? or / in the password must be written %23, %3F, "
                             "%2F") from None
        for k, v in (("host", u.hostname), ("port", port), ("user", u.username), ("password", u.password),
                     ("database", u.path.lstrip("/") or None)):
            if v is not None:
                out[k] = urllib.parse.unquote(v) if isinstance(v, str) else str(v)
        for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True):
            setting(k, v, strict=False)
        text = ""
    try:
        parts = shlex.split(text or "")
    except ValueError:
        raise ValueError("can't read the connection string: put a value with spaces or quotes in single quotes "
                         "(password='it''s'), or use a postgresql:// URL") from None
    for part in parts:
        k, _, v = part.partition("=")
        setting(k, v, strict=True)
    out.setdefault("host", os.environ.get("PGHOST", "/var/run/postgresql"))
    out.setdefault("port", os.environ.get("PGPORT", "5432"))
    user = out.setdefault("user", os.environ.get("PGUSER", "postgres"))
    password = out.get("password", os.environ.get("PGPASSWORD"))
    sslmode = out.get("sslmode") or os.environ.get("PGSSLMODE") or "prefer"
    if sslmode not in SSLMODES:
        raise ValueError(f"sslmode={sslmode}: one of {', '.join(SSLMODES)}")
    channel_binding = out.get("channel_binding") or os.environ.get("PGCHANNELBINDING") or "prefer"
    if channel_binding not in CHANNEL_BINDINGS:
        raise ValueError(f"channel_binding={channel_binding}: one of {', '.join(CHANNEL_BINDINGS)}")
    if not out["port"].isdigit() or not out.get("timeout", "10").isdigit():
        raise ValueError(f"the port and connect_timeout are numbers, not {out['port']!r}" if not out["port"].isdigit()
                         else f"connect_timeout is a number of seconds, not {out['timeout']!r}")
    return {"host": out["host"], "port": int(out["port"]), "user": user, "password": password,
            "database": out.get("database") or os.environ.get("PGDATABASE", user), "options": out.get("options"),
            "timeout": float(out.get("timeout", "10")) or 10, "sslmode": sslmode,
            "sslrootcert": out.get("sslrootcert") or os.environ.get("PGSSLROOTCERT"),
            "channel_binding": channel_binding}


def _socket(host: str, port: int, timeout: float) -> socket.socket:
    if host.startswith("/"):
        if sys.platform == "win32":
            raise ProtocolError(f"host={host} is a Unix socket, which Windows doesn't have: use host=localhost")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(os.path.join(host, f".s.PGSQL.{port}"))
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def _tls(sock: socket.socket, host: str, sslmode: str, sslrootcert: str | None) -> socket.socket:
    """The socket under TLS, as sslmode says: asked for (SSLRequest), and taken if the server has it. require and
    stronger refuse a server without it; verify-ca checks the server's certificate, verify-full its name too."""
    sock.sendall(struct.pack("!ii", 8, 80877103))
    answer = sock.recv(1)
    if answer == b"N":
        if sslmode in ("require", "verify-ca", "verify-full"):
            raise ProtocolError(f"the server doesn't do TLS, and sslmode={sslmode} asks for it")
        return sock
    if answer != b"S":
        raise ProtocolError("the server didn't answer as Postgres does (is this the right host and port?)")
    if sslmode in ("verify-ca", "verify-full"):
        context = ssl.create_default_context(cafile=sslrootcert)
        context.check_hostname = sslmode == "verify-full"
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE         # encrypted, the server not checked: what require means
    context.minimum_version = ssl.TLSVersion.TLSv1_2    # Python's default since 3.10, said for code scanners
    try:
        return context.wrap_socket(sock, server_hostname=host)
    except ssl.SSLError as e:
        raise ProtocolError(f"TLS with the server failed (sslmode={sslmode}): {e}") from None


def connect(host: str = "localhost", port: int = 5432, user: str = "postgres", password: str | None = None,
            database: str | None = None, options: str | None = None, timeout: float = 10,
            sslmode: str = "prefer", sslrootcert: str | None = None, channel_binding: str = "prefer") -> Connection:
    sock = _socket(host, port, timeout)
    try:
        if not host.startswith("/") and sslmode != "disable":
            sock = _tls(sock, host, sslmode, sslrootcert)
        # the timeout holds until it is signed in
        conn = Connection(sock, user, password, database or user, options, channel_binding)
    except BaseException:
        sock.close()
        raise
    sock.settimeout(None)
    conn.address = (host, port)
    return conn
