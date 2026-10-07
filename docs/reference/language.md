# The policy language

A policy is one or more `.authz` files. This one uses most of the language; the list after it says what
each part does.

```authz
app role app_user                               -- the role the policies apply to
include "roles.authz"                           -- split big policies into files

type user = app.users where {active}            -- suspended users hold nothing
type team = app.teams
  member : user        = app.team_members(team_id -> user_id)
  member : team#member = app.teams(parent_id -> id)   -- declared twice: two sources;
                                                      -- sub-teams' members count too
type folder = app.folders where {not archived}
  org         : org    = org_id                 -- from a column you already have
  parent      : folder, project = (parent_type, parent_id)   -- inside a folder or a project
  linked_into : folder = app.folder_links(folder_id -> parent_id)   -- from a table you have
  owner       : user   = owner_id
  viewer      : user, team#member, user:*, anyone, link  shared by edit   -- authz.share()
  editor      : user, team#member  shared if {subject_type <> 'user' or ...}
  roles       : user, team#member  from org     -- custom roles, defined at runtime by the org

  can share = owner or org.admin or (parent.share and {inherit})
  can edit  = share or editor or roles or (parent.edit and {inherit and not locked})
  can view  = edit or viewer or roles or parent.view or linked_into.view   -- roles: one that includes view
  can break_glass = org.member                  -- may use authz.break_glass here

caveat business_hours = {authz.ctx('mode') = 'business'}   -- conditions attached to single shares
caveat from_ip        = {authz.ctx('ip') = arg('ip')}

scope read  = select, view                      -- what a token may do (API keys, JWTs)
scope files = app.files.select, app.files.update, file.view, file.edit

rules app.files view app.files_visible          -- also make a view with masked columns
  select                            : view
  insert                            : folder.edit and owner  -- the new row names you as its owner
  update                            : edit
  update folder_id after            : folder.edit            -- checked on the row after the change
  update id, owner_id, confidential : share                  -- only when these columns change
  mask body                         : edit                   -- NULL in the view unless you may edit
  delete                            : edit

invariants
  never folder: share and not org.member        -- checked by the tests and authz.check_invariants(); rowstile prove
                                                -- finds a folder owner outside the org: the policy doesn't forbid it

test
  user 3 can view file 11                       -- against the data already there
  user 3 cannot edit file 11

test "a folder's owner edits what is inside"    -- brings its own data, rolled back after
  given ann = {INSERT INTO app.users (id, name) VALUES (9001, 'Ann') RETURNING id}
  given top = {INSERT INTO app.folders (org_id, owner_id, name) VALUES (1, $ann, 'Top') RETURNING id}
  given f   = {INSERT INTO app.files (folder_id, name) VALUES ($top, 'plan.txt') RETURNING id}
  user $ann can edit file $f
  as user $ann allowed {UPDATE app.files SET name = 'plan-2.txt' WHERE id = $f}   -- as the app role
  as user 7 refused {DELETE FROM app.files WHERE id = $f}
  as user 7 sees 0 {SELECT FROM app.files WHERE id = $f}
```

- **Keys**: a type's key is `id bigint` unless the type line says otherwise: `(gid)`,
  `(id uuid)`, or several columns for a composite key: `type folder = app.folders (org_id, id)`.
  The type is the column's own: a 32-bit key, as Prisma's `Int` or a `serial` makes, is `(id int)`.
  `rowstile init` writes it, and applying says so when it is missing (AZ602).
  A relation points at such an object with its columns in square brackets:
  `parent : folder = [org_id, parent_id]`, `app.folder_teams([org_id, folder_id] -> user_id)`,
  `(parent_type, [org_id, parent_id])`. The user type's key is one column.
- **Rows that count**: `where {...}` on a type line says which rows do. A row that fails it holds nothing
  and passes nothing on: a suspended user, an archived folder and what is inside it, a disbanded team's
  members (also through the team that holds it). No rule allows anything on it either: the app role can't
  read, change or delete an archived folder, so it can't un-archive one. Leave such rows to a job that runs
  as the owner, or say it in permissions instead (`can edit = ... and {not archived}`).
- **Relations** link rows to users or groups: from a column, from another table
  (`app.team_members(team_id -> user_id)`, or with the columns named:
  `app.team_members(object: team_id, subject: user_id)`; optionally `where {...}`), from a polymorphic pair of columns `(type_col, id_col)`,
  or from shares people make (`shared`). Declare a relation again to add a source. The type column of a
  polymorphic pair holds the policy's type names (`'folder'`, `'project'`): renaming a type changes what the
  rows link to.
- **Shares**: a `shared` relation is given with `authz.share()` by whoever holds `share` on the object, so the
  type needs a `can share`, or the relation names another permission: `shared by edit`. `shared if {...}` is a
  condition on the share being made (`object_id`, `subject_type`, `subject_id`, `subject_relation`), which
  `authz.share` checks: "only to active users". Shares may expire or start later. A **caveat** is a
  condition that goes with one share and is checked at each request:
  `authz.share('folder', 3, 'viewer', 'user', 4, '', NULL, NULL, 'from_ip', '{"ip": "10.0.0.1"}')` gives
  `viewer` while `caveat from_ip` holds, `arg('ip')` being what the share was made with.
- **Subjects**: `user`, a group such as `team#member` (nested to any depth, loops are
  fine), `user:*` (any signed-in user), `anyone` (also signed out) and `link` (anyone
  holding a share link's token).
- **Principals**: services, API clients and agents can sign in as themselves:
  `type service = app.services principal`. Relations name them like users
  (`bot : service = bot_id`, `reader : user, service shared`), and `service:*` means any
  signed-in service. `signed_in` and `user:*` stay about users.
- **Permissions** combine relations with `or`, `and`, `not` and parentheses, which say what goes first
  where `and` and `or` meet: `owner or (parent.edit and {inherit})` (without them it is refused).
  `rel.perm` follows a relation (`parent.edit`, `org.admin`, or to a user's own: `manager.oversee`,
  `author.has_blocked`), `signed_in` means any user signed in, `anyone` anyone at all, signed in
  or not (for rules on directories), and `nobody` nobody (`update id : nobody`), `{...}` is any SQL
  condition on the row (columns, subqueries, `now()`, `authz.uid()`, request context
  with `authz.ctx('mfa')`, which the app sets in the transaction: `SET LOCAL authz_ctx.mfa = 'yes'`).
  Being SQL, a condition names a column as SQL does: one with capital letters, as Prisma makes them, takes
  double quotes there (`{"parentId" is null}`), while a relation's source is the bare name
  (`parent : folder = parentId`).
- **Conditions name their row `this`**: a bare column is the row's, unless a table the condition reads has
  one by that name, as most have an `id`. In a subquery, write `this.`:
  `{exists (select 1 from app.memberships m where m.project_id = this.id)}` (with `id` alone, that would be
  the membership's id, and applying warns). `this` is the object in a permission, a rule or an invariant,
  the type's row in its `where`, the link table's row in a link table's `where`, and the share being made in
  `shared if`. A caveat has no row.
- **Conditions read with the policy's rights**, wherever they are checked (a rule, a permission, `authz.can`,
  another type's rule through `rel.perm`), as relations do: a subquery sees every row of the tables it reads,
  not only those the signed-in user may. A condition that is NULL holds nothing: `{not archived}` is false
  where `archived` is NULL, `not {archived}` is true there. Where a relation says the same, write the
  relation: `insert : folder.edit and owner` rather than `{owner_id = authz.uid()}`, which `rowstile prove`
  and the review read as a fact about the row; your own row is a relation too (`self : user = id`, then
  `can edit = self`).
- **Inheritance**: `or rel.perm` back to the same type (or across types, like projects
  and folders inside each other) inherits as deep as it goes, through any mix of
  sources; `and {condition}` says where it stops.
- **Denies**: `can view = (viewer or parent.view) and not hidden` takes `view` away on a
  hidden folder and everything below it, even from people who hold it higher up. The deny
  must inherit the same way (`can hidden = blocked or parent.hidden`), so it covers
  everything below; a deny on one object that only cuts inheritance there is refused, with
  a message saying so. A condition joined the same way holds at every level:
  `(viewer or parent.view) and {not archived}` stops at an archived folder.
- **Custom roles**: `roles : user, team#member` says who may hold roles people create at runtime
  (`authz.create_role('org', 1, 'folder', 'reviewer', ARRAY['view'])`) and share like relations. A
  permission writes `roles` where a role that includes it gives it, and a role may include the
  permissions that write it: `can view = (viewer or roles or parent.view) and not hidden` gives `view`
  to holders of a role that includes it, and the deny holds for them too, as it is written. Creating a
  role needs `manage_roles` on its owner (`can manage_roles = admin` on the org type), and gives the
  role's id: the role is shared as the relation `role:<id>` (`authz.share('folder', 3, 'role:12',
  'user', 7)`), by someone who holds `share` on the object and everything the role grants. `from org`
  says whose roles count on an object: only those of the org its `org` relation links it to now (a
  column or a table, to one type). `authz.share` refuses another owner's role, an assignment of one
  grants nothing, and a folder moved to another org stops honouring the first org's roles. Without
  `from`, any role for the type counts wherever it is given, so an app must offer only the owner's
  roles.
- **Rules** say what each command needs, per table, with column-level variants and
  masks. The plain `update` rule must hold on the row before and after the change (as
  Postgres checks both). A column rule checks the row before the change (`update owner_id : share`, or
  `update owner_id before : share`) or after it (`update folder_id after : folder.edit`: where
  a row moves to); `authz.lint()` warns about a move nothing checks the destination of.
  **Invariants** state what must never be true, for everyone who can sign in (each user, each
  service or other principal) and for nobody.
- **Tests**: the unnamed `test` section checks the data already in the database, with lines
  `user|<principal type> X can|cannot PERM TYPE ID` (or `anyone ...`). A named test,
  `test "..."`, brings its own: `given name = {SQL ... RETURNING id}` rows (as whoever applies
  policies; `$name` is what it returned, a key of several columns as its row text), then the same
  checks, and `as user X allowed|refused
  {SQL}` or `as user X sees N {SELECT ...}`, which run as the app role signed in as X. A write is
  refused if a rule or a missing privilege stops it, or if it changes no row (the rows it meant are
  hidden from X). Any other error, a unique key say, fails the check whichever was expected. Each named test runs in a transaction that is rolled back.
  After who a line is about, `with scope read` (or several: `with scope read, files`) checks it as a key or
  a token limited to those scopes would be: `user 3 with scope read cannot edit file 11`,
  `as user 3 with scope read refused {UPDATE ...}`. A scope the policy doesn't have is a mistake (AZ503).
  Named tests may live in their own files (only `test "..."` blocks); `rowstile test` and
  `rowstile dev` run them, never `apply`. A failing check explains itself.

## Permissions the runtime asks for

Permission names are yours to choose, but five are asked for by name. The compiler refuses one declared
where nothing would ask for it (AZ307).

| permission | on | lets its holders |
|---|---|---|
| `share` | a type with `shared` relations | share them (unless `shared by` names another), see who has access (`authz.who`, `authz.list_shares`), decide access requests |
| `break_glass` | a type with a relation shared with users | give themselves that relation for a while with `authz.break_glass`: audited, announced |
| `impersonate` | the user type | view the app as that user with `authz.view_as`: read-only, audited |
| `manage_keys` | a type that signs in | make and revoke its API keys (`authz.create_api_key(..., 'service', '7')`) |
| `manage_roles` | the type that owns custom roles (`roles : user from org`) | create, change and delete those roles |

## Masked columns

`rules app.files view app.files_visible` plus `mask body : edit` creates a view with
the rows `select` allows, where `body` is NULL unless the rule holds. The app role
loses SELECT on `body` in the table itself (the other columns stay), so the view is
the only way to read it. Applying refuses to go on if the column would still be
readable through PUBLIC or another role. A later `GRANT` that makes it readable again
isn't refused (that would need an event trigger, and so a superuser): `authz.lint()`
reports it, and applying again takes it back. Removing the mask gives the table-wide
SELECT back.

The view is the app's to build on: a view of your own over it, or a function that reads it. Applying and
migrations replace it in place, so those go on working when the policy changes. Two things can't be done in
place, and are refused with what is built on the view named (AZ617): taking the masked view out of the policy,
and a change of the table's columns that the view can't follow (a column renamed; a new column is
fine). Drop what you built, apply, and make it again.
