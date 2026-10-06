# Reviewing a policy change

A one-line change can widen access across many permissions, and its text doesn't show that. `rowstile review`
says what a change does, in plain words, for the pull request:

    rowstile review --base main                          # in a terminal
    rowstile review --base main --markdown --db "$URL"   # the comment CI posts

- **Meaning**: each declaration that changed, before and after, and every permission and rule that changes
  through something it uses. When only permissions and rules changed, each is checked against the base in
  many small worlds (made-up users, objects and links, `core/authzlib/evaluate.py`; among them the ones where
  every condition holds, so a change behind a long `and` shows): if they all grant the same, the review says
  "Meaning unchanged". Formatting and comments are "unchanged" too; text inside quotes is not formatting. A
  condition the worlds can't read (a subquery, a function: anything beyond the row's own columns and
  `authz.uid()`) is a set of rows of its own there, so when a permission or rule changed only in such
  conditions, the review says it can't compare them and names them, instead of guessing.
- **Access**: with `--db`, a database at the base branch's state (its migrations, then the review data,
  prepared by CI; never production), who gains and who loses what if the pull request's policy were in
  force, with examples and how each is granted. The database is left as it was.
- **Risk**: what to look at twice: access widened to `anyone`, `link` or `user:*`; a deny removed; a new
  inheritance path or a new way to reach a type; a relation newly shared or shared by another permission; a
  permission or a rule (`select` too) that allows more than before, with an example: because its own line
  changed, because it is new on a table that had rules, through a relation that changed (another column, a
  `where` taken off a link table), or because a type's `where` changed; a mask, a column rule or an invariant
  removed; a scope changed. Each names its policy line; `--annotations` writes them for GitHub, on the file
  the line is in. "Nothing flagged" means none of these was found in the worlds tried, not a proof.
- **Tests**: checks whose expectation flipped (the author saying "I meant this"), checks removed, new
  permissions no test names; with `--db`, the pull request's tests run on the review data after its
  migrations. The checks are listed whatever Meaning says. A test file of the pull request that doesn't parse
  is named, with its mistake: its checks are not compared.
- **Deploy**: the migrations the change needs (from the base branch's lock file), their statements, the
  app tables they lock and in which mode, the inheritance tables they rebuild or build beside; with
  `--db`, how long they took on the review data. A lock file behind the policy is called out. With no lock
  file on either side, the project applies its policy (`rowstile apply`) and keeps no migrations: Deploy says so.

A pull request that upgrades rowstile across a change to the language rewrites the policy too, and the
base's policy is in the language before. The review reads it as that version meant it (`role app_user` as
`app role app_user`, `grant view, edit` as `roles` written where the role joined, and so on), and says so
at the top, with the old forms it found (`--json` lists them all). Meaning then says whether the rewrite
grants the same.

[`review-ci/github/action.yml`](../../review-ci/github/action.yml) runs it on each pull request and keeps one comment up to date (and the annotations);
[`review-ci/gitlab/rowstile-review.gitlab-ci.yml`](../../review-ci/gitlab/rowstile-review.gitlab-ci.yml) does the same for merge requests. `rowstile fmt --check` in CI
keeps text diffs to real changes. On GitHub, the workflow may post the comment once it has
`pull-requests: write`, and checks out the history the base branch's policy is read from:

```yaml
on: pull_request
permissions: {contents: read, pull-requests: write}
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: {fetch-depth: 0}
      - uses: rowstile/rowstile/review-ci/github@v0.1.0-alpha.5   # the release you use
```

The review reports; it doesn't gate. It exits 0 whatever it finds: a widened permission, a failing test and a
lock file behind the policy are all in what it prints, for a person to read. (It exits 1 for a policy that
doesn't compile, 2 when it can't run: no `--base`, a commit git doesn't know, a database it can't reach.) What
fails a pull request is the other two commands CI runs: `rowstile test`, which exits 1 when a check fails, and
`rowstile migrate --check`, which exits 1 when the policy changed and no migration was written.
