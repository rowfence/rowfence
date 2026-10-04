# Cookbook

Patterns for common access rules, each with the policy lines and a test. They all come from one policy on
one set of tables, `docs/cookbook/` (`schema.sql`, `policy.authz`, `tests/patterns.authz`), which CI applies
and tests: every line shown here is in those files (`core/tests/cookbook.sh` checks it). To try one:
copy the lines, then `rowfence dev`.

The language in one breath: a **type** is a table; a **relation** says who or what a row is linked to (a
column, a link table, or shares people make); a **permission** combines relations with `or`, `and`, `not`,
`rel.perm` (follow a relation) and `{SQL}`; **rules** say what each command on a table needs.

## Owner only

The simplest rule: a row belongs to whoever its column names.

```authz
type note = cb.notes
  owner : user = owner_id
  can edit = owner
  can view = owner

rules cb.notes
  select : view
  insert : owner
  update : edit
  update owner_id : nobody
  delete : edit
```

`insert : owner` (the new row names you as its owner) stops people from making rows in someone else's name,
and `update owner_id : nobody` from giving theirs away. Tested:

```authz
  user $bo cannot view note $n
  as user $bo refused {INSERT INTO cb.notes (owner_id, body) VALUES ($ann, 'as Ann')}
  as user $ann refused {UPDATE cb.notes SET owner_id = $bo WHERE id = $n}
```

## Your own row

A relation from the row's own key is "this row is you": a user edits their own profile.

```authz
type user = cb.users
  self        : user = id                                     -- your own row
  can edit = self

rules cb.users
  select : signed_in
  update : edit
  update id : nobody
```

```authz
  user $ann can edit user $ann
  user $ann cannot edit user $bo
  as user $ann refused {UPDATE cb.users SET name = 'Bob' WHERE id = $bo}
```

## Teams inside teams

A relation can come from a link table. Declared twice, it has two sources: here, members of sub-teams count
as members, to any depth, loops included.

```authz
type team = cb.teams
  member : user        = cb.team_members(team_id -> user_id)
  member : team#member = cb.teams(parent_id -> id)
```

`team#member` is "the members of a team". Anything shared with Engineering's members reaches Web's:

```authz
  as user $ann allowed {SELECT authz.share('folder', $f, 'viewer', 'team', $eng, 'member')}
  user $bo can view folder $f
```

## Folders that inherit, until one says stop

`parent.view` follows a relation back to the same type: whatever you may do in a folder, you may do in
everything inside it, as deep as it goes. `and {inherit}` says where it stops.

```authz
type folder = cb.folders
  parent : folder = parent_id
  owner  : user   = owner_id
  viewer : user, team#member, link  shared by share
  editor : user, team#member        shared by share

  can share = owner or (parent.share and {inherit})
  can edit  = share or editor or (parent.edit and {inherit})
  can view  = edit or viewer or (parent.view and {inherit})
```

Moves need their own rule: a row may only move where you may edit.

```authz
  update parent_id after : parent.edit
```

## Sharing, for a while, and share links

`shared by share` lets whoever holds `share` give the relation with `authz.share()`, to a person, a team's
members, or anyone holding a link (`authz.create_link()`). Shares can start later and expire:

```authz
  as user $ann allowed {SELECT authz.share('folder', $f, 'viewer', 'user', $bo, '', now() + interval '1 week', now() + interval '1 day')}
  user $bo cannot view folder $f
  as user $bo refused {SELECT authz.share('folder', $f, 'viewer', 'user', $bo)}
```

## A deny that inherits

`and not` takes a permission away, even from people who hold it higher up. The deny must inherit the same
way, so it covers everything below: a hidden page hides its whole subtree.

```authz
type page = cb.pages
  parent : page = parent_id
  reader : user = cb.page_readers(page_id -> user_id)

  can hidden = {hidden} or parent.hidden
  can read   = (reader or parent.read) and not hidden
```

```authz
  user $ann can read page $top
  user $ann cannot read page $low
```

## Tenants, and keys of two columns

Rows numbered per tenant have a key of two columns. Say so after the table; relations point at such rows
with their columns in brackets, `[org_id, ticket_id]`, and ids are the row's text, `'(7,42)'`.

```authz
type org = cb.orgs
  member : user = cb.org_members(org_id -> user_id)
  admin  : user = cb.org_members(org_id -> user_id) where {role = 'admin'}

type ticket = cb.tickets (org_id, id)
  org      : org  = org_id
  assignee : user = assignee_id

  can edit = assignee or org.admin
  can view = edit or org.member
```

`where {role = 'admin'}` makes a second relation from the same table. A column rule narrows one change:

```authz
  update assignee_id : org.admin                          -- only admins reassign
```

## Bots and services

A `principal` type signs in as itself, with its own API keys (`authz.create_api_key(..., 'service', id)`),
which only holders of `manage_keys` on it may make. Relations name it like a user.

```authz
type service = cb.services principal
  owner : user = owner_id
  can manage_keys = owner
```

## Announcement channels: conditions on the row

`{SQL}` is any condition on the row. Members read; in an announcement channel only admins post; bots post
where they were added.

```authz
type channel = cb.channels
  member : user    = cb.channel_members(channel_id -> user_id)
  admin  : user    = cb.channel_members(channel_id -> user_id) where {admin}
  bot    : service = cb.channel_bots(channel_id -> service_id)

  can read = member or bot
  can post = (member and ({not announce} or admin)) or bot
```

A post is written by a person or by a bot, as themselves:

```authz
rules cb.posts
  select : channel.read
  insert : channel.post and ((author and {bot_id is null}) or (from_bot and {author_id is null}))
```

```authz
  as user $bo refused {INSERT INTO cb.posts (channel_id, author_id, body) VALUES ($c, $bo, 'hi')}
  as service $b allowed {INSERT INTO cb.posts (channel_id, bot_id, body) VALUES ($c, $b, 'sunny')}
```

## Blocking: following a relation to a person

A relation on the user type (who this person blocked) can be followed from any row that names a person:
`recipient.has_blocked` holds when the recipient blocked whoever is signed in. It is read with the policy's
rights, so it sees every block, not only the ones you may read (so would a `{condition}`, but the relation
says it in the policy's words, and `rowfence prove` and the review can read it).

```authz
type user = cb.users
  has_blocked : user = cb.blocks(blocker_id -> blocked_id)     -- the people this person blocked

type direct_message = cb.direct_messages
  sender    : user = from_id
  recipient : user = to_id

rules cb.direct_messages
  select : sender or recipient
  insert : sender and not recipient.has_blocked          -- nobody writes to someone who blocked them
```

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
