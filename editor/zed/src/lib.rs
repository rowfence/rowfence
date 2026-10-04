//! rowfence for Zed: starts the rowfence language server (`rowfence lsp`) for .authz files.
//!
//! It runs `rowfence` from the project's PATH (the project's own install: npm, pip or uv), or what Zed's
//! settings name:
//!
//!     "lsp": { "rowfence": { "binary": { "path": "/path/to/rowfence", "arguments": ["lsp"] } } }
use zed_extension_api::{self as zed, settings::LspSettings, LanguageServerId, Result};

struct Rowfence;

impl zed::Extension for Rowfence {
    fn new() -> Self {
        Rowfence
    }

    fn language_server_command(&mut self, id: &LanguageServerId, worktree: &zed::Worktree) -> Result<zed::Command> {
        let binary = LspSettings::for_worktree(id.as_ref(), worktree).ok().and_then(|s| s.binary);
        let args = binary
            .as_ref()
            .and_then(|b| b.arguments.clone())
            .unwrap_or_else(|| vec!["lsp".into()]);
        let command = match binary.and_then(|b| b.path) {
            Some(path) => path,
            None => worktree.which("rowfence").ok_or(
                "rowfence isn't on the PATH: install it in the project \
                 (https://github.com/rowfence/rowfence/blob/main/docs/installing.md), \
                 or set lsp.rowfence.binary.path in Zed's settings",
            )?,
        };
        Ok(zed::Command { command, args, env: worktree.shell_env() })
    }
}

zed::register_extension!(Rowfence);
