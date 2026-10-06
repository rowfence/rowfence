# Tenant isolation, with keys of two columns

Every ticket is in one organisation, and only that organisation's members see it. Tickets are numbered per
organisation, so their key has two columns.

```authz
type org = app.orgs
  member : user = app.org_members(org_id -> user_id)
  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}

type ticket = app.tickets (org_id, id)
  org      : org  = org_id
  assignee : user = assignee_id

  can edit = assignee or org.admin
  can view = edit or org.member

rules app.tickets
  select             : view
  insert             : org.member
  update             : edit
  update assignee_id : org.admin
  update org_id, id  : nobody
```

- `org.member` follows the ticket's `org` to that organisation's members: the tenant check, written once,
  where the type is. No query has to remember `WHERE org_id = ...`.
- `where {role = 'admin'}` makes a second relation from the same table.
- `(org_id, id)` after the table says the key has two columns. In `authz.can` and the other functions, such a
  row's id is its text, `'(7,42)'`.
- `update org_id, id : nobody` keeps a ticket in its organisation; `update assignee_id : org.admin` narrows
  one change to admins.

## Tested

Cy is an admin of another organisation:

```authz
test "a ticket is seen in its organisation, and nowhere else"
  user $cy cannot view ticket $t
  as user $cy sees 0 {SELECT FROM app.tickets WHERE org_id = $acme}
  as user $cy refused {INSERT INTO app.tickets VALUES ($acme, 2, $cy, 'Not mine to file')}
  as user $bo refused {UPDATE app.tickets SET assignee_id = $ann WHERE (org_id, id) = ($acme, 1)}
  as user $ann refused {UPDATE app.tickets SET org_id = $globex WHERE (org_id, id) = ($acme, 1)}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=tenants): the tables, the policy and the
test, in your browser, with nothing to install. Or take the files of
[`docs/cookbook/tenants/`](tenants/) (`schema.sql`, `policy.authz`, `tests.authz`) and run `rowstile dev`.
CI applies and tests them on every change (`core/tests/cookbook.sh`), and every line shown here is in those
files.

## What it costs

A key of two columns costs more to check than a single one: the id is built as text for each row
([Speed and limits](../reference/limits.md)). If tickets had an `id` of their own, the same policy without
`(org_id, id)` would be cheaper.

More: [keys](../reference/language.md), [the other recipes](../cookbook.md).
