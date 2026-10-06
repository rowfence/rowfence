# Sharing like Google Docs: private, shared with people, anyone with the link, public

A document starts private. Its owner shares it with people, hands out a link, or makes it public.

```authz
type document = app.documents
  owner  : user = owner_id
  viewer : user, link shared by share
  editor : user shared by share

  can share = owner
  can edit  = share or editor
  can view  = edit or viewer or {visibility = 'public'}

rules app.documents
  select                      : view
  insert                      : owner
  update                      : edit
  update owner_id, visibility : share
  delete                      : share
```

- **Private** is the absence of everything else: only `owner` holds.
- **Shared with people**: `authz.share('document', 7, 'viewer', 'user', 4)`, or `'editor'`.
- **Anyone with the link**: `viewer` may be given to `link`. `authz.create_link('document', 7, 'viewer')`
  returns a token, and a request that carries it sets `authz_ctx.links` to it for its transaction.
  `authz.list_links` shows a document's links and `authz.revoke_link` turns one off.
- **Public**: `{visibility = 'public'}` is a condition on the row, true for everyone, signed in or not.
- `update owner_id, visibility : share`: an editor changes the text, and only the owner changes who sees it.

## Tested

`anyone` in a test asks as nobody signed in:

```authz
test "private, shared with a person, public"
  user $bo cannot view document $diary
  anyone cannot view document $diary
  anyone can view document $blog
  user $bo cannot edit document $blog
  as user $ann allowed {SELECT authz.share('document', $diary, 'editor', 'user', $bo)}
  user $bo can edit document $diary
  as user $bo refused {UPDATE app.documents SET visibility = 'public' WHERE id = $diary}
  as user $ann allowed {UPDATE app.documents SET visibility = 'public' WHERE id = $diary}
  anyone can view document $diary
```

```authz
test "anyone with the link"
  as user $bo refused {SELECT authz.create_link('document', $d, 'viewer')}
  as user $ann allowed {SELECT authz.create_link('document', $d, 'viewer')}
  as user $ann sees 1 {SELECT FROM authz.list_links('document', $d)}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=google-docs-sharing): the tables, the policy and the
tests, in your browser, with nothing to install. Or take the files of
[`docs/cookbook/google-docs-sharing/`](google-docs-sharing/) (`schema.sql`, `policy.authz`, `tests.authz`) and run `rowstile dev`.
CI applies and tests them on every change (`core/tests/cookbook.sh`), and every line shown here is in those
files.

More: [sharing with teams, and shares that end](sharing-and-links.md),
[links from app code](../reference/app-code.md), [the other recipes](../cookbook.md).
