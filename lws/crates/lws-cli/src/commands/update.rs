use std::path::PathBuf;
use std::process::Command;

const REPO: &str = "https://github.com/dawnlabsai/lws.git";
const CURRENT_COMMIT: &str = env!("LWS_GIT_COMMIT");

pub fn run(force: bool) -> Result<(), crate::CliError> {
    let install_dir = install_dir();

    // Check remote HEAD
    let remote_commit = get_remote_head()?;
    println!("installed: {CURRENT_COMMIT}");
    println!("   remote: {remote_commit}");

    if !force && remote_commit.starts_with(CURRENT_COMMIT) {
        println!("Already up to date.");
        return Ok(());
    }

    if force {
        println!("Forcing rebuild...");
    } else {
        println!("Update available. Building...");
    }

    // Clone to temp dir
    let tmp = tempfile::tempdir()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to create temp dir: {e}")))?;

    let clone_status = Command::new("git")
        .args(["clone", "--depth", "1", REPO, tmp.path().to_str().unwrap(), "--quiet"])
        .status()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to run git: {e}")))?;

    if !clone_status.success() {
        return Err(crate::CliError::InvalidArgs("git clone failed".to_string()));
    }

    // Build
    let lws_dir = tmp.path().join("lws");
    let build_status = Command::new("cargo")
        .args(["build", "--workspace", "--release"])
        .current_dir(&lws_dir)
        .status()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to run cargo: {e}")))?;

    if !build_status.success() {
        return Err(crate::CliError::InvalidArgs("cargo build failed".to_string()));
    }

    // Copy binary
    let built_bin = lws_dir.join("target/release/lws");
    if !built_bin.exists() {
        return Err(crate::CliError::InvalidArgs(
            "built binary not found".to_string(),
        ));
    }

    std::fs::create_dir_all(&install_dir)
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to create install dir: {e}")))?;

    let dest = install_dir.join("lws");
    std::fs::copy(&built_bin, &dest)
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to copy binary: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| crate::CliError::InvalidArgs(format!("failed to set permissions: {e}")))?;
    }

    println!("Updated lws to {remote_commit}");
    Ok(())
}

fn get_remote_head() -> Result<String, crate::CliError> {
    let output = Command::new("git")
        .args(["ls-remote", REPO, "HEAD"])
        .output()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to run git ls-remote: {e}")))?;

    if !output.status.success() {
        return Err(crate::CliError::InvalidArgs(
            "git ls-remote failed — check your network connection".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let commit = stdout
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .get(..7)
        .unwrap_or("unknown");

    Ok(commit.to_string())
}

fn install_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("LWS_INSTALL_DIR") {
        PathBuf::from(dir)
    } else {
        dirs_or_home().join(".lws/bin")
    }
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
