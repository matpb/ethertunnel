//! Where the client keeps its config, credentials, and runtime state.
//!
//! `ETUN_CONFIG_DIR` wins when set (used by tests and `--system` services that
//! relocate state); otherwise we use the per-user config directory
//! (`~/.config/etun` on Linux, the platform equivalent elsewhere).

use std::path::PathBuf;

use anyhow::Context;

/// Resolve the base config directory, creating it if needed.
pub fn config_dir() -> anyhow::Result<PathBuf> {
    let dir = if let Some(over) = std::env::var_os("ETUN_CONFIG_DIR") {
        PathBuf::from(over)
    } else {
        directories::ProjectDirs::from("com", "matpb", "etun")
            .context("cannot determine a config directory for this platform")?
            .config_dir()
            .to_path_buf()
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// The shareable, secret-free config file.
pub fn config_file() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// The 0600 credentials file (bearer tokens, one per relay).
pub fn credentials_file() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("credentials.toml"))
}

/// The runtime status snapshot the daemon writes and `status` reads.
pub fn status_file() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("status.json"))
}

/// Directory for rolling log files (service modes that can't use journald).
pub fn log_dir() -> anyhow::Result<PathBuf> {
    let dir = config_dir()?.join("logs");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// The current log file (daily rolling appender writes `etun.log.YYYY-MM-DD`).
pub fn log_file_basename() -> &'static str {
    "etun.log"
}

/// Atomically write `bytes` to `path`, applying `mode` on unix (temp + rename).
///
/// The temp file is created with the restrictive `mode` from the outset via
/// `O_EXCL`, so secret bytes (tokens, keys) are never momentarily world-readable
/// in the window before a chmod, and a pre-created temp file or symlink at the
/// predictable temp path cannot be followed or clobbered. Permission/IO errors
/// are propagated, never swallowed, so a secret can never be silently persisted
/// with the wrong mode.
pub fn atomic_write(path: &std::path::Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    // Clear any leftover temp from a previously-crashed write so `create_new`
    // (O_EXCL) is not blocked by our own stale file. If an attacker races a
    // symlink in between, O_EXCL makes the create fail closed rather than follow.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all().ok();
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}
