use std::fs;

use zed_extension_api::{self as zed, Result};

const SERVER_BINARY: &str = "x509-language-server";
const GITHUB_REPO: &str = "hvardhan20/zed-x509-parser";

struct X509Extension {
    cached_binary_path: Option<String>,
}

impl X509Extension {
    /// Resolution order: binary on PATH (user-installed), cached download,
    /// then a fresh download of the latest GitHub release.
    fn language_server_binary_path(
        &mut self,
        language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<String> {
        if let Some(path) = worktree.which(SERVER_BINARY) {
            return Ok(path);
        }

        if let Some(path) = &self.cached_binary_path {
            if fs::metadata(path).is_ok_and(|stat| stat.is_file()) {
                return Ok(path.clone());
            }
        }

        zed::set_language_server_installation_status(
            language_server_id,
            &zed::LanguageServerInstallationStatus::CheckingForUpdate,
        );

        let (os, arch) = zed::current_platform();
        let target = match (os, arch) {
            (zed::Os::Mac, zed::Architecture::Aarch64) => "aarch64-apple-darwin",
            (zed::Os::Mac, zed::Architecture::X8664) => "x86_64-apple-darwin",
            (zed::Os::Linux, zed::Architecture::Aarch64) => "aarch64-unknown-linux-gnu",
            (zed::Os::Linux, zed::Architecture::X8664) => "x86_64-unknown-linux-gnu",
            (zed::Os::Windows, zed::Architecture::X8664) => "x86_64-pc-windows-msvc",
            _ => {
                return Err(format!(
                    "no prebuilt `{SERVER_BINARY}` for this platform; install it with \
                     `cargo install --git https://github.com/{GITHUB_REPO} x509-language-server`"
                ))
            }
        };
        let (extension, file_type, binary_name) = match os {
            zed::Os::Windows => (
                "zip",
                zed::DownloadedFileType::Zip,
                format!("{SERVER_BINARY}.exe"),
            ),
            _ => (
                "tar.gz",
                zed::DownloadedFileType::GzipTar,
                SERVER_BINARY.to_string(),
            ),
        };

        let release = zed::latest_github_release(
            GITHUB_REPO,
            zed::GithubReleaseOptions {
                require_assets: true,
                pre_release: false,
            },
        )?;

        let asset_name = format!("{SERVER_BINARY}-{target}.{extension}");
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == asset_name)
            .ok_or_else(|| format!("release {} has no asset `{asset_name}`", release.version))?;

        let version_dir = format!("{SERVER_BINARY}-{}", release.version);
        let binary_path = format!("{version_dir}/{binary_name}");

        if !fs::metadata(&binary_path).is_ok_and(|stat| stat.is_file()) {
            zed::set_language_server_installation_status(
                language_server_id,
                &zed::LanguageServerInstallationStatus::Downloading,
            );

            zed::download_file(&asset.download_url, &version_dir, file_type)
                .map_err(|e| format!("failed to download `{asset_name}`: {e}"))?;
            zed::make_file_executable(&binary_path)?;

            // Drop older versions so the work dir doesn't grow unbounded.
            if let Ok(entries) = fs::read_dir(".") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with(SERVER_BINARY) && name != version_dir.as_str() {
                        fs::remove_dir_all(entry.path()).ok();
                    }
                }
            }
        }

        zed::set_language_server_installation_status(
            language_server_id,
            &zed::LanguageServerInstallationStatus::None,
        );

        self.cached_binary_path = Some(binary_path.clone());
        Ok(binary_path)
    }
}

impl zed::Extension for X509Extension {
    fn new() -> Self {
        Self {
            cached_binary_path: None,
        }
    }

    fn language_server_command(
        &mut self,
        language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let command = self
            .language_server_binary_path(language_server_id, worktree)
            .inspect_err(|e| {
                zed::set_language_server_installation_status(
                    language_server_id,
                    &zed::LanguageServerInstallationStatus::Failed(e.clone()),
                );
            })?;

        Ok(zed::Command {
            command,
            args: vec![],
            env: worktree.shell_env(),
        })
    }
}

zed::register_extension!(X509Extension);
