# Access on request: ask, approve, and it ends by itself

Someone who can't see a document asks for it. Whoever may share it decides. What they give ends after the time
that was asked for.

```authz
type document = app.documents
  owner  : user = owner_id
  viewer : user shared by share

  can share = owner
  can view  = share or viewer
```

Nothing in the policy is about requests: a relation that can be shared can be asked for, and whoever holds
its `share` permission decides. The app calls three functions:

```sql
SELECT authz.request_access('document', 7, 'viewer', 'for the audit', '7 days');   -- as the person asking
SELECT * FROM authz.pending_requests();                                             -- as someone who may decide
SELECT authz.decide_request(12, true, 'ok');                                        -- approve: a share for 7 days
```

- Approving makes a share that ends after the time asked for.
- People can't decide their own requests.
- Asking doesn't tell the asker whether the document exists.

## Tested

Bo asks, Ann owns the document, Cy is nobody to it:

```authz
test "ask, and whoever may share decides"
  user $bo cannot view document $d
  as user $bo allowed {SELECT authz.request_access('document', $d, 'viewer', 'for the audit', '7 days')}
  user $bo cannot view document $d
  as user $cy sees 0 {SELECT FROM authz.pending_requests()}
  as user $bo refused {SELECT authz.decide_request(r.id, true, 'mine') FROM authz.pending_requests() r}
  as user $ann allowed {SELECT authz.decide_request(r.id, true, 'ok') FROM authz.pending_requests() r}
  user $bo can view document $d
  user $cy cannot view document $d
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=access-on-request): the tables, the policy and the
tests, in your browser, with nothing to install. Or take the files of
[`docs/cookbook/access-on-request/`](access-on-request/) (`schema.sql`, `policy.authz`, `tests.authz`) and run `rowstile dev`.
CI applies and tests them on every change (`core/tests/cookbook.sh`), and every line shown here is in those
files.

More: [requests and approvals](../reference/governance.md), [emergency access](support-and-emergency-access.md),
[the other recipes](../cookbook.md).
