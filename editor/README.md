# rowfence in your editor

For `.authz` files: highlighting (SQL inside `{ }` is highlighted as SQL), and from the rowfence language
server (`rowfence lsp`, in `cli/lsp.py`):

- **errors while typing**, on the line they name, from the same compiler the database runs;
- **hover**: a permission's definition and what it inherits through, a relation's sources, a type's table and key;
- **go to definition** and **find references** for types, relations and permissions (`parent.edit` goes to
  the folder's `edit`);
- **outline** of types, relations, permissions and rules;
- **completion**: after `rel.` the target type's permissions, inside a type its relations and permissions, and
  with a `database` in `rowfence.toml`, table and column names;
- **test files** (only `test "..."` blocks) are checked against the policy `rowfence.toml` names.

## VS Code

    cd editor && npm install && npx vsce package      # makes rowfence-0.1.0.vsix
    code --install-extension rowfence-0.1.0.vsix

The extension runs `rowfence lsp` (put `cli/` on your PATH), or whatever `rowfence.command` says, e.g.
`["python3", "/path/to/rowfence/cli/rowfence_cli.py", "lsp"]`. It starts in the workspace folder, where it looks
for `rowfence.toml`.

## Zed

`zed/` is the Zed extension: highlighting from the Tree-sitter grammar (`tree-sitter-authz/`), the outline, and
the language server. From this repository: in Zed, run **zed: install dev extension** and pick `editor/zed`
(Zed builds it, with Rust installed through rustup).

It runs `rowfence lsp` with the `rowfence` on the project's PATH (installed with npm, pip or uv), or the one
Zed's settings name:

```json
{ "lsp": { "rowfence": { "binary": { "path": "/path/to/rowfence", "arguments": ["lsp"] } } } }
```

## Other editors

`tree-sitter-authz/` is a Tree-sitter grammar for `.authz` files (`src/parser.c`, generated from `grammar.js`),
with its queries in `queries/`: highlights (SQL injected inside `{ }`), outline and brackets. Helix and Neovim
highlight with it: build the grammar from `editor/tree-sitter-authz` in this repository, and copy `queries/`
into the editor's queries folder for `authz`.

Any editor with a language client can start `rowfence lsp` for `.authz` files. Neovim:

```lua
vim.filetype.add({ extension = { authz = "authz" } })
vim.api.nvim_create_autocmd("FileType", { pattern = "authz", callback = function()
  vim.lsp.start({ name = "rowfence", cmd = { "rowfence", "lsp" }, root_dir = vim.fs.root(0, { "rowfence.toml", ".git" }) })
end })
```

Helix (`languages.toml`, in its config folder: `~/.config/helix/` on Linux and macOS):

```toml
[language-server.rowfence]
command = "rowfence"
args = ["lsp"]

[[language]]
name = "authz"
scope = "source.authz"
file-types = ["authz"]
language-servers = ["rowfence"]

[[grammar]]
name = "authz"
source = { path = "/path/to/rowfence/editor/tree-sitter-authz" }
```

Then `hx --grammar build` builds the grammar, and the queries go in Helix's runtime folder:
`mkdir -p ~/.config/helix/runtime/queries/authz && cp editor/tree-sitter-authz/queries/*.scm ~/.config/helix/runtime/queries/authz/`.
`hx --health authz` shows the language server, the parser and the highlight queries.

The TextMate grammar (`syntaxes/authz.tmLanguage.json`) also works on its own in Sublime Text and Shiki.

`test.sh` checks the Tree-sitter grammar (generated from `grammar.js`, its corpus, every policy in the
repository parses) and builds the Zed extension, each in a container.
