# Using it from app code

Python apps use [the Python SDK](../../sdk/python/README.md): `Rowstile(app, engine, user=...)` for FastAPI, `install(engine)` for
SQLAlchemy, and transactions for psycopg and asyncpg sign each transaction in, turn refusals into 403 and
hidden rows into 404, and check the app's connection at start-up. `integrations/fastapi` is its conformance
suite. TypeScript apps use [the TypeScript SDK](../../sdk/typescript/README.md): `@rowstile/prisma` (a driver adapter that signs every
transaction in, and a client extension), `/pg`, `/postgres` (postgres.js), `/drizzle`, `/next` (signed-in reads
kept out of caches, 403 and 404 from route handlers and server actions), `/react` (`usePerms`, `<Can>`, a
headless share dialog, live updates) and `/vitest`; `integrations/nextjs` is their conformance suite, and
`rowstile client` writes only the policy's names for them (`src/authz.gen.ts`). Underneath, and for every
other stack:

Everything is a SQL function in schema `authz`, callable by the app role, acting as
the signed-in user. Ids are text or the type's key type. A composite key's id is the text
Postgres writes for the row: `authz.can('folder', '(1,42)', 'view')`, or from SQL
`ROW(f.org_id, f.id)::text`; `authz.list` returns ids in that form (`'(1,"a b")'` for a text
column that needs quoting), and the generated clients take a tuple or array.

| task | function |
|---|---|
| check, list, all permissions | `authz.can('file', 11, 'edit')`, `authz.list('folder', 'edit')`, `authz.perms('file', 11)` |
| list in pages, in key order | `authz.list('file', 'view', NULL, 1000)`, then `authz.list('file', 'view', '<last id>', 1000)` (a NULL size: no limit; a cursor that isn't an id, or a negative size: AZ710) |
| who has access (for people who may share it) | `authz.who('folder', 3, 'view')` |
| why, or what is missing | `authz.explain('file', 11, 'edit')`; for someone else: `..., 'edit', '7')` |
| why a write is or would be refused | `authz.explain_rule('app.files', 'update', '11', '{"name": "x"}')`: NULL if the row isn't there or you can't see it (404); an insert: `authz.explain_rule('app.files', 'insert', NULL, '{"folder_id": 6}')` |
| which of these people may see it (live updates) | `authz.who_among('file', 11, 'view', ARRAY['1', '2'])`: it signs each one in with `authz.act_as`, so it is for whoever may call that (the app role, a backend trusted to sign people in) |
| the sharing dialog | `authz.list_shares('folder', 3)` |
| share and unshare | `authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')` (then when it starts, a caveat and its arguments: [the language](language.md)), `authz.unshare(...)` |
| share links | `authz.create_link('folder', 3, 'viewer')` returns a token; requests use it with `SET LOCAL authz_ctx.links = '<token>'` |
| custom roles | `authz.create_role('org', 1, 'folder', 'reviewer', ARRAY['view'])` returns the role's id (needs `manage_roles` on the org); share it as `authz.share('folder', 3, 'role:<id>', 'user', 7)`; `authz.set_role_permissions(id, ARRAY[...])`, `authz.delete_role(id)`, `authz.roles_of('org', 1)` |
| API keys | `authz.create_api_key('laptop', 'read')` (shown once), `authz.list_api_keys()`, `authz.revoke_api_key(id)` |
| sign in | `authz.login_key('ak_...')`, `authz.login_jwt('eyJ...')` (HS256; settings in `authz.settings`) |
| support "view as" | `authz.view_as('42', 'ticket 1234')`: read-only, audited, needs `can impersonate` on the user |
| ask for access | `authz.request_access('folder', 3, 'viewer', 'for the audit', '7 days')`, `authz.cancel_request(id)` |
| decide requests | `authz.pending_requests()`, `authz.decide_request(id, true, 'ok')`: approving makes a share that ends after the requested time |
| emergency access | `authz.break_glass('folder', 6, 'viewer', 'INC-7 outage', '1 hour')`: needs `break_glass`, one day at most, audited, announced on channel `authz_alerts` |
| access reviews | `authz.start_review('folder', 3)`, `authz.review_items(id)`, `authz.review_decide(id, item, false)`, `authz.close_review(id)` |

Administrators (the policy's owner and superusers; the app role is refused) also have:

| task | function |
|---|---|
| inheritance tables match a rebuild | `authz.verify()` |
| the change feed (for caches, search indexes, sync jobs) | poll `authz.changes_since(pos)` ([where to start](governance.md)); `LISTEN authz_changes` only after `INSERT INTO authz.settings VALUES ('notify_changes', 'on')` (every notifying commit waits its turn) |
| the audit trail | `SELECT * FROM authz.audit` (append-only; every share, unshare, role, membership change, request, review, break-glass, view-as, API key) |
| retention (schedule these: pg_cron, or the app's jobs) | `authz.trim_changes()` keeps 7 days of the feed (or the setting `changes_keep`); `authz.trim_audit(interval '2 years')` removes older audit entries and records that it did |
| group sync from an identity provider | `authz.sync_members('team', '10', 'member', ARRAY['1', '2'])` makes the group's rows in the relation's table (`app.team_members`) this list: it deletes and inserts there. For a relation read from one table, without `where`; shares are not touched |
| invariants | `authz.check_invariants()` |
| ways around RLS | `authz.lint()`: see [Checking the database](governance.md#checking-the-database) |

Generated clients wrap these with the policy's names, so a typo in a permission is a
compile error: `rowstile client py > authz_client.py`
(DB-API: psycopg and friends) or `rowstile client ts > authz.ts` (TypeScript, for `pg` or
anything with `query(text, params)`). Generate it from the policy in force and commit it next to
your code; regenerate when the policy changes (the file manager's tests fail when it is stale).

- **Python: supported.** Part of the 1.0 surface: `sign_in`, `can`, `list` (with `after` and
  `limit` for pages), `perms`, `who`, `explain`, `share`, `unshare`, `list_shares`,
  `create_link`, `use_links`, `request_access`, `decide_request`, `cancel_request`,
  `pending_requests`, `break_glass`, `start_review`, `review_items`, `review_decide`,
  `close_review`, `login_key`, `login_jwt`, `explain_rule`, `expect`, `who_among`, and the errors
  `Refused` (`.table`, `.command`, `.why`) and `NotFound`, with `refusal(error)` turning a driver's
  error into a `Refused`. Rows come back as dicts. The file manager and the messenger use it.

**Refusals say why.** A write the rules refuse raises SQLSTATE 42501 with the rule and what is
missing, as the signed-in user may know it (nothing about rows they can't see):

```
ERROR:  permission denied: user 1 may not insert this row into app.files
DETAIL:  no   insert : folder.edit and owner  (line 80)
  yes  folder.edit
  no   owner
```

The error's table, schema and constraint (`authz_insert`, `authz_update`) fields are set, which is what
`refusal(error)` reads. An allowed write never runs this (the check is `rule OR refuse(row)`). Updates
and deletes the rules don't allow change no rows instead (row-level security leaves them out):
`az.expect(result, table, command, id)` then raises `NotFound` or `Refused` with `authz.explain_rule`'s
answer.
- **TypeScript: preview.** The same calls in camelCase; may change before it is supported.
