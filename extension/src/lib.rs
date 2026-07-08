use zed_extension_api::{self as zed, Result};

const SERVER_BINARY: &str = "x509-language-server";

struct X509Extension;

impl zed::Extension for X509Extension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let path = worktree.which(SERVER_BINARY).ok_or_else(|| {
            format!(
                "`{SERVER_BINARY}` not found on PATH. Install it with \
                 `cargo install --path language-server` (or via the published \
                 release once available) and restart Zed."
            )
        })?;

        Ok(zed::Command {
            command: path,
            args: vec![],
            env: worktree.shell_env(),
        })
    }
}

zed::register_extension!(X509Extension);
