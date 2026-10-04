//! rowstile for Zed: starts the rowstile language server (`rowstile lsp`) for .authz files.
//!
//! It runs `rowstile` from the project's PATH (the project's own install: npm, pip or uv), or what Zed's
//! settings name:
//!
//!     "lsp": { "rowstile": { "binary": { "path": "/path/to/rowstile", "arguments": ["lsp"] } } }
use zed_extension_api::{self as zed, settings::LspSettings, LanguageServerId, Result};

struct Rowstile;

impl zed::Extension for Rowstile {
    fn new() -> Self {
        Rowstile
    }

    fn language_server_command(&mut self, id: &LanguageServerId, worktree: &zed::Worktree) -> Result<zed::Command> {
        let binary = LspSettings::for_worktree(id.as_ref(), worktree).ok().and_then(|s| s.binary);
        let args = binary
            .as_ref()
            .and_then(|b| b.arguments.clone())
            .unwrap_or_else(|| vec!["lsp".into()]);
        let command = match binary.and_then(|b| b.path) {
            Some(path) => path,
            None => worktree.which("rowstile").ok_or(
                "rowstile isn't on the PATH: install it in the project \
                 (https://github.com/rowstile/rowstile/blob/main/docs/installing.md), \
                 or set lsp.rowstile.binary.path in Zed's settings",
            )?,
        };
        Ok(zed::Command { command, args, env: worktree.shell_env() })
    }
}

zed::register_extension!(Rowstile);
