# Cookbook

Recipes for common access rules. Each has a page of its own, with the policy lines, what each does and a
test, and a folder under `docs/cookbook/` with its own small tables (`schema.sql`), policy (`policy.authz`)
and tests (`tests.authz`). CI applies and tests every one, and every line a page shows is in those files
(`core/tests/cookbook.sh` checks it). Each page links to the playground, where the recipe runs in your
browser; or copy the folder's files and run `rowstile dev`.

The language in one breath: a **type** is a table; a **relation** says who or what a row is linked to (a
column, a link table, or shares people make); a **permission** combines relations with `or`, `and`, `not`,
`rel.perm` (follow a relation) and `{SQL}`; **rules** say what each command on a table needs.

## Rows and their owners

- [Rows only their owner can see and change](cookbook/owner-only.md): a relation read from a column.
- [Let each user edit only their own row](cookbook/your-own-row.md): a relation read from the row's own key.

## Groups and trees

- [Nested groups: teams inside teams](cookbook/teams-inside-teams.md): members of sub-teams count, to any
  depth.
- [Folder permissions that inherit down a tree, and stop where a folder says so](cookbook/folders-that-inherit.md):
  `parent.edit`, moves, `and {inherit}`.
- [Hiding a page and everything under it](cookbook/deny-that-inherits.md): `and not`, a deny that inherits.

## Sharing

- [Sharing a row with a person or a team, for a while, and share links](cookbook/sharing-and-links.md):
  `shared by share`, `authz.share()`, `authz.create_link()`.

## Tenants

- [Tenant isolation, with keys of two columns](cookbook/tenants.md): every row in its organisation, admins
  and members.

## Rules on the row, and who writes

- [Rules that depend on the row: read-only announcement channels](cookbook/conditions-on-the-row.md): `{SQL}`
  conditions.
- [Permissions for services and bots, not only users](cookbook/bots-and-services.md): principals with their
  own API keys.
- [Blocking a user: nobody writes to someone who blocked them](cookbook/blocking.md): following a relation to
  a person.

## Live updates: who to tell

When a row changes, a backend that pushes updates asks once which of its connected people may see it:

```sql
SELECT * FROM authz.who_among('channel', '7', 'read', ARRAY['1', '2', '3']);
```

It signs each one in with `authz.act_as`, so it is for whoever may call that: the app role, a backend trusted to
sign people in.
The messenger does this (`examples/messenger/backend/app/events.py`): its WebSocket carries only "chat 7 changed", and
the browser refetches through the API.

## Signing in, when the tables are under row-level security

Checking a password reads a table before anyone is signed in. Keep credentials in a table the policy doesn't
govern, and read them through a `SECURITY DEFINER` function the app role may call
(`examples/messenger/db/migrations/0001_schema.sql`: `ms.credentials_for`). `authz.lint()` notes such functions:
check each only reads what it must.
