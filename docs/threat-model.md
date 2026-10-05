# Threat model

What rowstile protects, from whom, where it relies on the deployment, and what it does not cover.
Checked by `core/tests/adversarial.sh` (the app role attacking the policy), `tests/identity.sh`
(identity and scopes), `tests/difftest.py` (the database agrees with an independent evaluator) and
`tests/fuzz_parser.py` (broken policies are refused cleanly). rowstile has not been audited by anyone
outside the project.

## What is protected

- **Rows of governed tables**: a table with `rules` in the policy. Who may read, add, change and
  delete each row, down to columns (column rules, masks).
- **Shares, roles, requests, reviews, API keys**: the `authz` tables. Only rowstile's own functions
  change them, after checking the caller may.
- **The audit trail and the change feed**: append-only for everyone but `authz.trim_audit()` and
  `authz.trim_changes()`, which administrators run.
- **Correct inheritance**: the stored closure tables match the tree at every commit, whatever the
  isolation level or concurrency (`tests/races.sh`, `tests/stress.sh`).

## Who is trusted

| | trusted to | not trusted to |
|---|---|---|
| **Policy authors** (whoever applies it with `rowstile apply`: the tables' owner, or a superuser) | say what the rules are; their `{...}` conditions run as the policy's owner | nothing: a policy can do anything its owner can |
| **Database owner, migration role** | own the tables and apply policies | |
| **The app's backend** (the app role, or a member of it: the roles that may call `authz.act_as()`) | say who is signed in, per transaction | |
| **The app role** (`app role` in the policy; the backend connects as it) | nothing beyond the rules | read or change rows the rules don't allow, touch rowstile's internals, turn row-level security off, share more than it holds, approve its own requests |
| **Anyone signed in with an API key or JWT** | act as that user, within the key's scopes | widen the scopes, act as someone else |

The trust boundary is between the app role and everything above it. A bug in the app (say, SQL
injection) should not let an attacker read hidden rows through queries. What such an attacker can
do depends on identity:

- **On any Postgres, sign-ins are signed**: `authz.act_as()` and the logins sign who is signed in,
  the scopes, the backend and the transaction with a key the app role can't read, and nothing else is
  believed. So the app role can't change who is signed in by setting it, widen a key's scopes, leave
  view-as, or reuse a sign-in from another transaction or connection (`tests/sessions.sh`).
- **The app role may call `authz.act_as()`**, so code running as the app role can claim to be anyone
  (rowstile had an optional native library that narrowed `act_as` to chosen roles; it was removed once
  rowstile ran on any Postgres and the benchmark showed that signing costs nothing measurable). Roles other than the app role
  and its members can't sign anyone in.
- **If the backend role itself is compromised**, the attacker can claim any user either way: the
  backend is trusted to say who is signed in. Keep that role's credentials inside the
  backend, and sign other clients in with keys or JWTs.

## What stops what

| attack (as the app role) | stopped by | checked in |
|---|---|---|
| read a hidden row, by id, by `COPY`, through a prepared statement run as another user | row-level security on every governed table; policies read the user per statement | adversarial.sh |
| see hidden rows through a function in `WHERE` that prints its argument | Postgres runs row-level security before functions that aren't `LEAKPROOF` (only superusers can mark them) | adversarial.sh |
| `SET row_security = off`, disable row-level security, drop or add a policy, drop a trigger, replace a generated function | not the owner; `row_security = off` makes the query fail instead | adversarial.sh |
| read or write `authz_int`, `authz.shares`, `authz.audit`, `authz.changes`, the lock rows; call internal functions | no privileges on them; the app role reads only `authz_gen` views (its own ids) and calls the `authz.*` API | adversarial.sh |
| use rowstile's tables or administrators' functions through the owner's default privileges, or a grant made since | applying takes back every privilege on rowstile's schemas the policy doesn't give; `authz.lint()` reports later ones | adversarial.sh |
| run code as the owner: a function in a schema on the search path of rowstile's functions that run as the owner, taking a built-in's place | applying refuses a schema on that path that roles other than the owner may create in (AZ612); `authz.lint()` reports one opened later | adversarial.sh |
| update, delete or upsert onto a hidden row | row-level security (`UPDATE 0`, `DELETE 0`, an error for the upsert) | adversarial.sh |
| take ownership, move a row where the user may not write, stop inheritance above a folder | column rules (`update owner_id : share`, `update parent_id after : parent.edit`) | adversarial.sh, scenario.sql |
| share what the user can't share, a relation that isn't shared, or to widen their own access | `authz.share()` checks the relation is shared and the sharer holds what the policy asks | adversarial.sh, multi_scenario.sql |
| learn who has access, or the shares or links on, an object they can't share | `authz.who`, `authz.list_shares` and `authz.list_links` refuse, the same way for missing objects; so does `authz.revoke_link`, whether or not the id names a link | adversarial.sh |
| approve their own access request, decide one they can't share | `authz.decide_request()` checks the decider | governance.sh, adversarial.sh |
| act as another user; widen a key's scopes; write during "view as" | signed sessions (above); scoped and view-as sessions are read-only where they must be | sessions.sh, identity.sh |
| a stale closure table granting access after a move | the type-wide tree lock; serialization errors in stricter isolation levels | races.sh, stress.sh, concurrency.sh |
| a policy with a mistake that silently grants too much | compile-time and apply-time checks with line numbers; conditions that decide inheritance must not depend on time or user | policy_errors.py, fuzz_parser.py |

The review in CI (`rowstile review`, the GitHub action) runs on a pull request's files, which whoever
opened it wrote. An include stays in the policy's folder: no `..` out of it, no absolute path, no link
leading out (AZ108), and the policy, the tests and the lock file `rowstile.toml` names stay in the folder
`rowstile.toml` is in, the same way; so a pull request can't make the review read one of the runner's files, or
its environment, and print it in the job's log (`unit_test.py`, policy_errors.py, cli.sh). The review believes the pull
request's `rowstile.toml`, as CI believes its workflow files: run it on `pull_request`, where a fork's pull
request gets no secrets, not on `pull_request_target`.

## Known limits (accepted)

- **Side channels.** Code that can run arbitrary SQL as the app role can learn things it can't read:
  `EXPLAIN ANALYZE` shows how many rows row-level security removed, so an index lookup such as
  `WHERE id = 12` reveals whether a hidden row exists; timing can too. Constraints tell it too, to
  any caller: a unique constraint, or a primary key the app lets callers choose (client-made ids, an
  import), refuses an insert that collides with a hidden row (`authz.lint()` lists both); a foreign key
  refuses deleting a row that hidden rows reference (a folder with a hidden file in it). These are
  Postgres behaviours: let the database make the ids (`GENERATED ALWAYS AS IDENTITY`, random uuids),
  delete the children the user can see first and answer "not empty" for the rest, and keep arbitrary
  SQL away from the app role (the backend decides which queries run).
- **Statistics** of governed tables are hidden from the app role by Postgres (`pg_stats` leaves out
  tables with row-level security), checked in adversarial.sh.
- **Tables without rules** are readable in full by the app role (`authz.lint()` says so), which suits
  directories such as users and groups.
- **SECURITY DEFINER functions the app adds** bypass row-level security unless their owner is subject
  to it; `authz.lint()` lists those it can see.
- **Conditions in `rules`** run with the app role's privileges; conditions inside permissions run with
  the policy owner's ([Speed and limits](reference/limits.md)).
- **Scopes limit what a token does, not what it can find out about its own user.** A scoped session
  (an API key or a JWT with scopes) is held to its scopes by the rules and by `authz.can`, `authz.list` and
  the other `authz.*` functions. Code that reads the `authz_gen` views directly, which the app role may,
  sees the ids the user holds each permission on, whatever the scopes: a `read` token can learn what its
  user may edit, not edit it.
- **Request context** (`authz.ctx(...)`, `authz_ctx.*` settings) is whatever the app sets: a policy that
  trusts it trusts the backend.
- **No outside audit.** rowstile has had self-review only.
