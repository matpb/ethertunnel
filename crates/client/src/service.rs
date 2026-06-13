//! Install the daemon (`etun up`) as a managed background service.
//!
//! One small, hand-rolled template per init system — no service-manager crate,
//! so the dependency tree stays the same on every target:
//!
//! - Linux: systemd (a per-user unit by default, a system unit under `--system`)
//! - macOS: a launchd LaunchAgent plist
//! - Windows: a service registered via the built-in `sc.exe`
//!
//! Every platform runs the same `etun up --service-mode`, so logging routes to
//! journald / a rolling file as appropriate (see the cli's log setup).

#[allow(unused_imports)]
use anyhow::{bail, Context};

/// Path to this binary, for the ExecStart / ProgramArguments line.
fn exe() -> anyhow::Result<String> {
    Ok(std::env::current_exe()
        .context("locating the etun binary")?
        .to_string_lossy()
        .into_owned())
}

/// Install and (best-effort) start the service.
pub fn install(system: bool) -> anyhow::Result<()> {
    imp::install(system)
}
/// Stop and remove the service.
pub fn uninstall(system: bool) -> anyhow::Result<()> {
    imp::uninstall(system)
}
pub fn start(system: bool) -> anyhow::Result<()> {
    imp::start(system)
}
pub fn stop(system: bool) -> anyhow::Result<()> {
    imp::stop(system)
}
pub fn status(system: bool) -> anyhow::Result<()> {
    imp::status(system)
}

// ----------------------------------------------------------------------------
// Linux / systemd
// ----------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn unit_path(system: bool) -> anyhow::Result<PathBuf> {
        if system {
            Ok(PathBuf::from("/etc/systemd/system/etun.service"))
        } else {
            let base = directories::BaseDirs::new()
                .context("cannot find home directory")?
                .config_dir()
                .join("systemd/user");
            std::fs::create_dir_all(&base)?;
            Ok(base.join("etun.service"))
        }
    }

    fn unit_text(system: bool) -> anyhow::Result<String> {
        let exe = exe()?;
        let user_line = if system {
            // A real deployment would run as a dedicated user; default to the
            // installing user so `--system` works without useradd, and document
            // tightening in the unit itself.
            let user = std::env::var("USER").unwrap_or_else(|_| "nobody".into());
            format!("User={user}\n")
        } else {
            String::new()
        };
        Ok(format!(
            "[Unit]\n\
             Description=EtherTunnel client daemon\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exe} up --service-mode\n\
             Restart=always\n\
             RestartSec=5\n\
             {user_line}\
             NoNewPrivileges=true\n\
             \n\
             [Install]\n\
             WantedBy={target}\n",
            target = if system {
                "multi-user.target"
            } else {
                "default.target"
            },
        ))
    }

    fn systemctl(system: bool, args: &[&str]) -> anyhow::Result<()> {
        let mut cmd = Command::new("systemctl");
        if !system {
            cmd.arg("--user");
        }
        let status = cmd.args(args).status().context("running systemctl")?;
        if !status.success() {
            bail!("systemctl {} failed", args.join(" "));
        }
        Ok(())
    }

    pub fn install(system: bool) -> anyhow::Result<()> {
        let path = unit_path(system)?;
        std::fs::write(&path, unit_text(system)?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
        systemctl(system, &["daemon-reload"])?;
        // enable-linger lets a user service keep running after logout.
        if !system {
            if let Ok(user) = std::env::var("USER") {
                let _ = Command::new("loginctl")
                    .args(["enable-linger", &user])
                    .status();
            }
        }
        systemctl(system, &["enable", "--now", "etun.service"])?;
        println!("etun service installed and started");
        Ok(())
    }

    pub fn uninstall(system: bool) -> anyhow::Result<()> {
        let _ = systemctl(system, &["disable", "--now", "etun.service"]);
        let path = unit_path(system)?;
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("removed {}", path.display());
        }
        let _ = systemctl(system, &["daemon-reload"]);
        Ok(())
    }

    pub fn start(system: bool) -> anyhow::Result<()> {
        systemctl(system, &["start", "etun.service"])
    }
    pub fn stop(system: bool) -> anyhow::Result<()> {
        systemctl(system, &["stop", "etun.service"])
    }
    pub fn status(system: bool) -> anyhow::Result<()> {
        // status returns non-zero when stopped; don't treat that as an error.
        let mut cmd = Command::new("systemctl");
        if !system {
            cmd.arg("--user");
        }
        let _ = cmd.args(["status", "etun.service", "--no-pager"]).status();
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// macOS / launchd
// ----------------------------------------------------------------------------
#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    const LABEL: &str = "com.matpb.etun";

    fn plist_path(system: bool) -> anyhow::Result<PathBuf> {
        let dir = if system {
            PathBuf::from("/Library/LaunchDaemons")
        } else {
            directories::BaseDirs::new()
                .context("cannot find home directory")?
                .home_dir()
                .join("Library/LaunchAgents")
        };
        std::fs::create_dir_all(&dir).ok();
        Ok(dir.join(format!("{LABEL}.plist")))
    }

    fn plist_text() -> anyhow::Result<String> {
        let exe = exe()?;
        let logs = crate::paths::log_dir()?;
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
               <key>Label</key><string>{LABEL}</string>\n\
               <key>ProgramArguments</key><array><string>{exe}</string><string>up</string><string>--service-mode</string></array>\n\
               <key>RunAtLoad</key><true/>\n\
               <key>KeepAlive</key><true/>\n\
               <key>StandardErrorPath</key><string>{log}/launchd.err</string>\n\
               <key>StandardOutPath</key><string>{log}/launchd.out</string>\n\
             </dict></plist>\n",
            log = logs.display(),
        ))
    }

    pub fn install(system: bool) -> anyhow::Result<()> {
        let path = plist_path(system)?;
        std::fs::write(&path, plist_text()?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
        let _ = Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&path)
            .status();
        println!("etun launchd agent installed");
        Ok(())
    }
    pub fn uninstall(system: bool) -> anyhow::Result<()> {
        let path = plist_path(system)?;
        let _ = Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&path)
            .status();
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("removed {}", path.display());
        }
        Ok(())
    }
    pub fn start(_system: bool) -> anyhow::Result<()> {
        let status = Command::new("launchctl").args(["start", LABEL]).status()?;
        if !status.success() {
            bail!("launchctl start failed");
        }
        Ok(())
    }
    pub fn stop(_system: bool) -> anyhow::Result<()> {
        let _ = Command::new("launchctl").args(["stop", LABEL]).status();
        Ok(())
    }
    pub fn status(_system: bool) -> anyhow::Result<()> {
        let _ = Command::new("launchctl").args(["list", LABEL]).status();
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Windows / sc.exe
// ----------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use std::process::Command;

    const NAME: &str = "EtherTunnel";

    pub fn install(_system: bool) -> anyhow::Result<()> {
        let exe = exe()?;
        let bin = format!("\"{exe}\" up --service-mode");
        let status = Command::new("sc.exe")
            .args(["create", NAME, "start=", "auto", "binPath=", &bin])
            .status()
            .context("running sc.exe (run as Administrator)")?;
        if !status.success() {
            bail!("sc.exe create failed (Administrator required)");
        }
        let _ = Command::new("sc.exe").args(["start", NAME]).status();
        println!("etun service installed");
        Ok(())
    }
    pub fn uninstall(_system: bool) -> anyhow::Result<()> {
        let _ = Command::new("sc.exe").args(["stop", NAME]).status();
        let status = Command::new("sc.exe").args(["delete", NAME]).status()?;
        if !status.success() {
            bail!("sc.exe delete failed (Administrator required)");
        }
        Ok(())
    }
    pub fn start(_system: bool) -> anyhow::Result<()> {
        let status = Command::new("sc.exe").args(["start", NAME]).status()?;
        if !status.success() {
            bail!("sc.exe start failed");
        }
        Ok(())
    }
    pub fn stop(_system: bool) -> anyhow::Result<()> {
        let _ = Command::new("sc.exe").args(["stop", NAME]).status();
        Ok(())
    }
    pub fn status(_system: bool) -> anyhow::Result<()> {
        let _ = Command::new("sc.exe").args(["query", NAME]).status();
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Other platforms
// ----------------------------------------------------------------------------
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod imp {
    pub fn install(_: bool) -> anyhow::Result<()> {
        anyhow::bail!("service install is not supported on this platform")
    }
    pub fn uninstall(_: bool) -> anyhow::Result<()> {
        anyhow::bail!("unsupported platform")
    }
    pub fn start(_: bool) -> anyhow::Result<()> {
        anyhow::bail!("unsupported platform")
    }
    pub fn stop(_: bool) -> anyhow::Result<()> {
        anyhow::bail!("unsupported platform")
    }
    pub fn status(_: bool) -> anyhow::Result<()> {
        anyhow::bail!("unsupported platform")
    }
}
