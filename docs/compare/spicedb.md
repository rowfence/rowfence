# rowstile and SpiceDB

Both describe access with relations and with permissions built from them, after Google's Zanzibar. SpiceDB is
a database for relationships, run as a service beside the app's own database: the app writes relationships
to it and asks it. rowstile is a compiler: the relationships are the rows the app already has, and Postgres
applies the rules to every query.

What this page says of SpiceDB is from its own documentation, read on 2026-10-07 and linked. If a line is wrong
or out of date, an issue is welcome. The short version for every alternative is on
[rowstile and the alternatives](../comparison.md).

## The same model in both

Documents in folders, edited by people and by a team's members, where a folder's editors may edit what is
inside it. In SpiceDB's schema language, written with the forms its
[schema page](https://authzed.com/docs/spicedb/concepts/schema) shows (a subject relation, `team#member`; a
union, `+`; an arrow, `parent->edit`):

```
definition user {}

definition team {
    relation member: user
}

definition folder {
    relation editor: user | team#member
    permission edit = editor
}

definition document {
    relation parent: folder
    relation editor: user | team#member
    permission edit = editor + parent->edit
}
```

In rowstile's:

```authz
app role app_user

type user = app.users

type team = app.teams
  member : user = app.team_members(team_id -> user_id)

type folder = app.folders
  editor : user        = app.folder_editors(folder_id -> user_id)
  editor : team#member = app.folder_teams(folder_id -> team_id)

  can edit = editor

type document = app.documents
  parent : folder      = folder_id
  editor : user        = app.document_editors(document_id -> user_id)
  editor : team#member = app.document_teams(document_id -> team_id)

  can edit = editor or parent.edit

rules app.documents
  select : edit
  update : edit
```

`parent->edit` and `parent.edit` are the same step: SpiceDB's page says the arrow walks "from the
`parent_folder` of the `document`" to "the subjects found for the `read` permission of that folder". What
rowstile adds is where each relation is read from, a column (`= folder_id`) or a link table
(`= app.team_members(team_id -> user_id)`), and what each command on the table needs (`rules`).

## When a fact changes

In SpiceDB a fact is a relationship the app writes to it. The document's row is in the app's database and
its `parent` relationship is in SpiceDB: two writes to two systems, and the app decides what happens when the
second one fails.

With rowstile there is nothing more to write: `folder_id` is the relationship, and a folder's editors are
the rows of `app.folder_editors`, the `INSERT` the app makes anyway. For access people hand each other
while the app runs, a relation can be `shared` instead: `authz.share('document', '7', 'editor', 'user',
'4')` writes it, in the same transaction as the rest of the request, and the policy says who may share.

## Consistency

SpiceDB lets each request choose. Its default for reads is `minimize_latency`, which "will attempt to
minimize the latency of the API call by selecting data that is most likely to exist in the cache". For an
answer that is at least as new as a given write, the app passes a ZedToken, "an opaque token representing a
point-in-time of the SpiceDB datastore", which its docs say to store in the app's own database beside the
resource, for instance in a text column; `fully_consistent` asks for the latest
([consistency](https://authzed.com/docs/spicedb/concepts/consistency)).

rowstile has no second clock. A rule reads the rows as the transaction sees them, and there is no token to
keep.

## Conditions

SpiceDB's caveats are "expressions that can return true or false, and they can be attached (by name) to
relationships", written in CEL, with their values given when the relationship is written and when the
permission is checked ([caveats](https://authzed.com/docs/spicedb/concepts/caveats)). They suit what only the
request knows: an address, the time, a device.

rowstile's conditions are SQL on the row: `can view = edit or {published}`,
`update : edit and {not archived}`. They suit what the row knows, and they need nothing sent with the
question. What only the request knows has to be put where SQL can read it.

## Lists

SpiceDB's guide to
[protecting a list endpoint](https://authzed.com/docs/spicedb/modeling/protecting-a-list-endpoint) gives three
ways. Ask LookupResources for every id and filter the query with them, "if the number of resources that a
user has access to is small (e.g. less than 10,000 resources)". Or "fetch a page of resources from your
database, and then call `CheckBulkPermissions` on those resources". Or keep a copy of who may see what, fed
by Authzed Materialize, which it calls the most scalable of the three.

With rowstile a list is a query, sorted and paged by Postgres with the rules in its plan:

```sql
SELECT id, title FROM app.documents ORDER BY title LIMIT 50 OFFSET 100;
```

## What runs

SpiceDB is a service with a datastore under it, to deploy, scale and watch. rowstile leaves SQL in the
database and runs nothing beside it.

## When SpiceDB is the better choice

- **What decides access is spread out**: several databases or services, or not in Postgres. rowstile reads
  one Postgres database.
- **Rules that depend on the request**, not on a row: SpiceDB's caveats take the request's values.
- **Many services** ask the same questions, in several languages.
- **One type takes many structural writes a second.** In rowstile, moves and links in a tree wait for each
  other ([Speed and limits](../reference/limits.md)).
- **You need a company behind it**, with support and a hosted offering. rowstile is a 0.x preview with one
  maintainer, and nobody outside has audited it ([how it is checked](../how-it-is-checked.md)).

## Try the same model

[Folders that inherit](../cookbook/folders-that-inherit.md) and
[teams inside teams](../cookbook/teams-inside-teams.md) are this page's model as tested recipes, each with a
link that opens it in the playground.
