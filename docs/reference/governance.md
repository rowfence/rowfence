# Governance

- **Audit trail** (`authz.audit`): who did what, as whom (the real user during
  "view as"), with the reason from `SET LOCAL authz_ctx.reason = '...'`. Changes to
  relationship tables and columns are recorded too (as relate/unrelate), including
  TRUNCATE. Nobody can update or delete rows, not even a superuser without first
  dropping or disabling the trigger (DDL, which DDL logging and event triggers see); the one
  exception is `authz.trim_audit(keep)`, which removes entries older than that and records that
  it did (it disables the trigger for its delete, so it holds the trail's lock until the
  transaction ends: run it at a quiet time).
- **Change feed** (`authz.changes`): every object whose access may have changed,
  including everything below a moved folder, with a position to resume from.
  `{*}` means every object of that type (after a TRUNCATE). `authz.trim_changes()`
  removes old entries; a reader behind them gets an error from `changes_since` (AZ712) and
  reads everything again. A reader that starts, or starts again, first notes where the feed is,
  `SELECT greatest((SELECT max(pos) FROM authz.changes), (SELECT value::bigint FROM authz.settings WHERE key =
  'changes_trimmed_to'), 0)`, then reads everything, then follows from that position.
- **Requests and approvals**: people ask, those who may share the relation decide;
  approval makes a share that ends after the requested time. Requesters can't
  decide their own, and asking doesn't reveal whether a hidden object exists.
- **Break glass**: short, audited, announced self-service access for people the policy
  names with `can break_glass`. They pick the relation, among those the policy lets be shared with a user:
  if `editor` is shared, break glass can give `editor`.
- **Access reviews**: a snapshot of an object's shares; each is kept or revoked by
  someone who could unshare it; closing applies the decisions.
- **Invariants** run with the policy's tests and on demand.
- **Previewing a change**: `python3 core/compile_policy.py new.authz --diff [--users 1,2] | psql -d mydb`
  applies the new policy inside a transaction, lists every (user, object) pair that
  gains or loses each permission, readable row and masked column, then rolls back. It asks as
  every user, as every service or other principal (named `service:7`, also in `--users`) and as nobody.
- **Decision log**: `SET authz_debug.log_decisions = on` writes every `authz.can`
  decision to the server log (for debugging: the app role can turn it on and off).

## Checking the database

Reports what would let the app role get around row-level security: being a superuser
or BYPASSRLS (directly or through a role), row-level security turned off on a table with rules, owning
a governed table without FORCE ROW LEVEL SECURITY, a policy on a governed table that rowstile didn't make (Postgres joins
permissive policies with OR, so it lets through what the rules don't), TRUNCATE on governed or membership tables, their partitions (or tables
inheriting from them) used directly, a table inheriting from a governed one that was made since the last apply (it
lacks the table's row triggers until the next one), views over governed tables that run with their
owner's rights, SECURITY DEFINER functions that use them,
membership tables the app may write, relationship columns anyone who can update the
row may change, masked columns readable from the table, unique indexes that reveal
hidden rows, missing indexes on the columns permission checks look up, a select rule whose permissions are
named so many times over that every read is slow to plan ([Speed and limits](limits.md)), and JIT being on. As notes, it lists
the tables the app role may read in full: a type's table without rules, a table the policy reads for a
relation (who is in which team), and any table in the same schemas that the policy doesn't name (password
hashes, sessions: nothing filters them; fine for a lookup table). It also
reports privileges on rowstile's own schemas (`authz`, `authz_gen`, `authz_int`) that the policy doesn't
give, and a schema on the search path of rowstile's functions that run as the owner that another role may
create in. Applying takes the first back and refuses the second (AZ612).

Applying reports its errors and warnings as warnings, so nobody has to remember to run it. It also
warns about a `{condition}` whose bare column a table it reads takes from the row (`m.project_id = id`,
where memberships have an `id` too): the row's is `this.id`.

`authz.connection_check()` is the same idea for the app itself, which may call it: what is wrong with
the connection it runs on (a superuser, BYPASSRLS, the owner of a governed table, a table with rules whose
row-level security is off, JIT). A login that is neither the app role nor a member of it can't call it at all
(`permission denied for schema authz`): the rules apply to the app role only. A login that is a superuser or
the policy's owner and switched to the app role with `SET ROLE` is an error too: `RESET ROLE` leaves
row-level security, and its sessions are believed without a signature. Log in as the app role. Call it when the app starts and refuse to start on an
`error`, or its tests pass without testing anything. The clients have `connection_check()` /
`connectionCheck()`.
