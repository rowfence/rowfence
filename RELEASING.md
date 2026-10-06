# Releasing

How rowstile is numbered and released. For maintainers; [CONTRIBUTING.md](CONTRIBUTING.md) is how a change
gets into `main`.

## Versions

rowstile follows [semantic versioning](https://semver.org/). One version covers everything a release ships:
the `rowstile` command, the Python package, the TypeScript packages (`@rowstile/*` and the command's
platform packages), the image, and the review for CI. `packaging/version.py` sets it in every file, and a
unit test fails if two files disagree. The editor extensions (VS Code, Zed) have their own versions, raised
when they change: the Marketplace takes no alphas or release candidates. A release publishes the VS Code extension
on the Marketplace and Open VSX when its version isn't there yet, each once its token is set (`VSCE_PAT`,
`OVSX_PAT`, in the environment `vscode`). `VSCE_PAT` isn't set: a new version goes to the Marketplace by hand,
the release's `.vsix` uploaded on the publisher's page (marketplace.visualstudio.com/manage/publishers/rowstile).
Zed's is by hand too: a pull request to zed-industries/extensions that moves the `extensions/rowstile` submodule
to the release's commit and sets the same version in `extensions.toml`.

| version | what it is | published |
|---|---|---|
| `0.2.0` | a minor release. Before 1.0 it may change the language, the `authz.*` functions, the SDKs and the file formats, and the changelog's **Upgrading** says what to do | `latest` |
| `0.2.1` | a patch: fixes only, nothing to do when upgrading | `latest` |
| `0.2.0-alpha.1` | an alpha of 0.2.0 (PyPI: `0.2.0a1`): for trying it early. It may have known gaps, and anything in it may still change before 0.2.0 | npm's `next`, a GitHub pre-release; never `latest` |
| `0.2.0-rc.1` | a release candidate for 0.2.0 (PyPI: `0.2.0rc1`): meant to become 0.2.0 as it is | npm's `next`, a GitHub pre-release; never `latest` |
| `0.2.0-dev` | `main` between releases, on its way to 0.2.0 (PyPI: `0.2.0.dev0`) | never: the release workflow refuses it |

An alpha or a candidate is installed by asking for it: `npm i rowstile@next`, `pip install --pre rowstile` (or
`rowstile==0.2.0a1`), the image by its version. A version's alphas come before its candidates, and the
command orders them so: `0.2.0-alpha.2`, then `0.2.0-rc.1`, then `0.2.0`.

Every release upgrades from the one before it, and that is tested. What 1.0 promises beyond that is decided
before 1.0.

A build from `main` records its version with a hash of the compiler's sources (`0.2.0-dev+3f2a9c1e8b7d`), so
`rowstile apply` never takes a database applied by one build as up to date for another.

## The cycle

- **A minor release when it is ready**: when `main` holds something worth releasing. Once a month, check
  whether `main` has sat on unreleased changes.
- **Alphas when there is something to try early**: `alpha.1`, `alpha.2` and on, before the version's first
  candidate and never after it. An alpha is released like a candidate (below) and promises less: it says
  what is there, not that it is done.
- **Release candidates before each minor and major release**: `rc.1`, then `rc.2` and on if fixes land. Each
  is installed from the registries the way users install it and checked before the next step. The final
  release is the last candidate with only the version and the changelog's date changed.
- **Patches whenever a fix is ready**, tagged straight from a green `main` or `release/X.Y`, without a
  candidate: an urgent fix shouldn't wait a round.

## Tags and branches

- Tags are `vX.Y.Z`, `vX.Y.Z-alpha.N` and `vX.Y.Z-rc.N`, annotated, on a commit of `main` or `release/X.Y` whose version files
  say that version (the release workflow checks). A tag is never moved or deleted once pushed: a bad release
  is followed by a new one.
- A patch comes from `main` when `main` holds only fixes since the last release. Otherwise, make
  `release/X.Y` from the tag `vX.Y.Z` (once), land the fix on `main` first, then cherry-pick it to the branch
  (`git cherry-pick -x`) in a pull request, and release from there.

## Making a release

1. **The release pull request**, from a branch `release-X.Y.Z` (or `release-X.Y.Z-rc.N`, `release-X.Y.Z-alpha.N`),
   with two commits:
   1. the release itself, with the subject line `X.Y.Z-rc.N` (or `X.Y.Z-alpha.N`, `X.Y.Z`):
      - `python3 packaging/version.py X.Y.Z-rc.N`
      - `CHANGELOG.md`: for the version's first alpha or candidate, **Unreleased** becomes `## X.Y.Z (alpha)`
        or `## X.Y.Z (release candidate)`, with a new empty **Unreleased** above it. For a later one,
        **Unreleased**'s lines move into that section, and the first candidate after alphas turns its
        heading into `(release candidate)`. For the final release, the heading gets its date:
        `## X.Y.Z (YYYY-MM-DD)`
      - the apps' migrations, where `rowstile migrate --check` asks for one: in `examples/filemanager`,
        `examples/messenger`, `integrations/fastapi` and `integrations/nextjs`, run
        `python3 ../../core/cli/rowstile_cli.py migrate --name rowstile_X_Y_Z`. This is the upgrade users
        will make, run by CI on each app
   2. `main`'s next version: `python3 packaging/version.py X.(Y+1).0-dev` after a final release,
      `X.Y.Z-dev` after an alpha or a candidate, with the subject line that version.
2. **Merge it** with a rebase once CI is green, so both commits land on `main` as they are.
3. **Tag the first commit** and push the tag:

       git fetch origin
       sha=$(git log origin/main --format=%H -1 --grep '^X.Y.Z-rc.N$')
       git tag -a vX.Y.Z-rc.N -m "rowstile X.Y.Z-rc.N" "$sha"
       git push origin vX.Y.Z-rc.N

4. **The release workflow** (`.github/workflows/release.yml`) runs on the tag. It checks that the tag and the
   version agree, runs the unit tests and the packaging tests, then publishes: the Python package, the npm
   packages, the image, and a GitHub release holding the wheel, the sdist, the npm launcher and the VS Code
   extension, with the changelog's section as its notes. Last, the MCP server's entry in the official registry
   (`server.json`): that registry is a preview, and a failure there never fails the release (run the `mcp` job
   again). Where it publishes follows the repository: private
   places while it is private, PyPI, npm and ghcr.io once public. The tag also deploys the docs site at
   rowstile.dev (`.github/workflows/site.yml`), built from the tag, when the release is what a plain install
   gets, or while no final release exists: `gh workflow run site.yml -f tag=vX.Y.Z` deploys another one.
5. **Check it** as a user would: install from the registries on Linux, macOS and Windows, then `rowstile
   init`, `migrate` and `test` on a small app, and the review action on a pull request. Then the next
   alpha, the next candidate or the final release. A tag pushed is not a release made: look at the workflow's
   run, and at what it published.

Run by hand (Actions, **release**, **Run workflow**), the release workflow builds and checks everything and
publishes nothing: a dry run before tagging.

## Going public

Dependabot is on: its monthly, grouped updates (`.github/dependabot.yml`) and its security updates (the
repository's settings, Code security). With the first public release, turn on **private vulnerability
reporting** there too: [SECURITY.md](SECURITY.md) sends reports there, and it is off until someone turns it on.

## Security releases

A vulnerability reported privately ([SECURITY.md](SECURITY.md)) is fixed in the GitHub security advisory's
private fork, released as a patch, and the advisory is published with the release, crediting the reporter if
they want it.
