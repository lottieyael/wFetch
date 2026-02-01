use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

pub struct PsOutput {
    pub stdout: String,
    pub stderr: String,
}

pub fn run_powershell(script: &str, timeout: Duration) -> Result<PsOutput, String> {
    let mut child = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start PowerShell: {e}"))?;

    let status = match child
        .wait_timeout(timeout)
        .map_err(|e| format!("Failed waiting for PowerShell: {e}"))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "PowerShell timed out after {} ms",
                timeout.as_millis()
            ));
        }
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout)
            .map_err(|e| format!("Failed reading PowerShell stdout: {e}"))?;
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr)
            .map_err(|e| format!("Failed reading PowerShell stderr: {e}"))?;
    }

    let stdout = stdout.trim().to_string();
    let stderr = stderr.trim().to_string();

    if !status.success() {
        let msg = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("PowerShell exited with status {status}")
        };
        return Err(msg);
    }

    Ok(PsOutput { stdout, stderr })
}
