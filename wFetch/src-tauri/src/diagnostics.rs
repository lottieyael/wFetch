use std::time::Duration;
use std::{net::{IpAddr, SocketAddr, TcpStream}, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::ps;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSystemInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os: Option<String>,
    pub cpu: Option<String>,
    pub logical_processors: Option<u32>,
    pub memory_total_gb: Option<f64>,
    pub memory_free_gb: Option<f64>,
    pub disk_total_gb: Option<f64>,
    pub disk_free_gb: Option<f64>,
    pub gpus: Vec<String>,
    pub error: Option<String>,
}

pub fn diagnose_host(ip: &str, timeout: Duration) -> RemoteSystemInfo {
    // Avoid obvious non-host targets (multicast/broadcast).
    if ip == "255.255.255.255" || ip.starts_with("224.") || ip.starts_with("225.") || ip.starts_with("226.")
        || ip.starts_with("227.") || ip.starts_with("228.") || ip.starts_with("229.") || ip.starts_with("230.")
        || ip.starts_with("231.") || ip.starts_with("232.") || ip.starts_with("233.") || ip.starts_with("234.")
        || ip.starts_with("235.") || ip.starts_with("236.") || ip.starts_with("237.") || ip.starts_with("238.")
        || ip.starts_with("239.")
    {
        return RemoteSystemInfo {
            ip: ip.to_string(),
            hostname: None,
            username: None,
            os: None,
            cpu: None,
            logical_processors: None,
            memory_total_gb: None,
            memory_free_gb: None,
            disk_total_gb: None,
            disk_free_gb: None,
            gpus: vec![],
            error: Some("Skipped multicast/broadcast address".to_string()),
        };
    }

    if ip.ends_with(".255") {
        return RemoteSystemInfo {
            ip: ip.to_string(),
            hostname: None,
            username: None,
            os: None,
            cpu: None,
            logical_processors: None,
            memory_total_gb: None,
            memory_free_gb: None,
            disk_total_gb: None,
            disk_free_gb: None,
            gpus: vec![],
            error: Some("Skipped probable broadcast address".to_string()),
        };
    }

    // Quick preflight: DCOM/WMI typically needs TCP/135 reachable.
    if let Ok(parsed) = IpAddr::from_str(ip) {
        let addr = SocketAddr::new(parsed, 135);
        let port_timeout = Duration::from_millis(800);
        if TcpStream::connect_timeout(&addr, port_timeout).is_err() {
            return RemoteSystemInfo {
                ip: ip.to_string(),
                hostname: None,
                username: None,
                os: None,
                cpu: None,
                logical_processors: None,
                memory_total_gb: None,
                memory_free_gb: None,
                disk_total_gb: None,
                disk_free_gb: None,
                gpus: vec![],
                error: Some("Skipped: TCP/135 not reachable (RPC/DCOM likely blocked)".to_string()),
            };
        }
    }

    // Use DCOM to avoid WinRM dependency; still requires firewall + permissions.
    // Return partial info + error message on failure.
        let script = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$ip = '__IP__'
$opt = New-CimSessionOption -Protocol Dcom
$s = New-CimSession -ComputerName $ip -SessionOption $opt -OperationTimeoutSec 5
try {
    $cs = Get-CimInstance -CimSession $s -ClassName Win32_ComputerSystem
    $os = Get-CimInstance -CimSession $s -ClassName Win32_OperatingSystem
    $cpu = Get-CimInstance -CimSession $s -ClassName Win32_Processor | Select-Object -First 1
    $disks = Get-CimInstance -CimSession $s -ClassName Win32_LogicalDisk -Filter "DriveType=3"
    $gpus = Get-CimInstance -CimSession $s -ClassName Win32_VideoController

    $diskTotal = ($disks | Measure-Object -Property Size -Sum).Sum
    $diskFree = ($disks | Measure-Object -Property FreeSpace -Sum).Sum

    $memTotalGb = if ($null -ne $cs.TotalPhysicalMemory) { [Math]::Round(($cs.TotalPhysicalMemory/1GB), 2) } else { $null }
    $memFreeGb  = if ($null -ne $os.FreePhysicalMemory) { [Math]::Round((($os.FreePhysicalMemory*1KB)/1GB), 2) } else { $null }

    $obj = [PSCustomObject]@{
        ip = $ip
        hostname = $cs.Name
        username = $cs.UserName
        os = $os.Caption
        cpu = $cpu.Name
        logical_processors = [int]$cpu.NumberOfLogicalProcessors
        memory_total_gb = $memTotalGb
        memory_free_gb = $memFreeGb
        disk_total_gb = if ($diskTotal) { [Math]::Round(($diskTotal/1GB), 2) } else { $null }
        disk_free_gb = if ($diskFree) { [Math]::Round(($diskFree/1GB), 2) } else { $null }
        gpus = @($gpus | Select-Object -ExpandProperty Name)
        error = $null
    }

    $obj | ConvertTo-Json -Depth 6 -Compress
} finally {
    if ($null -ne $s) { Remove-CimSession $s | Out-Null }
}
"#
        .replace("__IP__", ip);

    match ps::run_powershell(&script, timeout) {
        Ok(out) => {
            if out.stdout.is_empty() || out.stdout == "null" {
                return RemoteSystemInfo {
                    ip: ip.to_string(),
                    hostname: None,
                    username: None,
                    os: None,
                    cpu: None,
                    logical_processors: None,
                    memory_total_gb: None,
                    memory_free_gb: None,
                    disk_total_gb: None,
                    disk_free_gb: None,
                    gpus: vec![],
                    error: Some("No output from diagnostics".to_string()),
                };
            }

            match serde_json::from_str::<RemoteSystemInfo>(&out.stdout) {
                Ok(mut info) => {
                    // Ensure IP field is set even if PS returned null.
                    if info.ip.trim().is_empty() {
                        info.ip = ip.to_string();
                    }
                    info
                }
                Err(e) => RemoteSystemInfo {
                    ip: ip.to_string(),
                    hostname: None,
                    username: None,
                    os: None,
                    cpu: None,
                    logical_processors: None,
                    memory_total_gb: None,
                    memory_free_gb: None,
                    disk_total_gb: None,
                    disk_free_gb: None,
                    gpus: vec![],
                    error: Some(format!(
                        "Failed to parse diagnostics JSON: {e}. Output was: {}",
                        out.stdout
                    )),
                },
            }
        }
        Err(e) => RemoteSystemInfo {
            ip: ip.to_string(),
            hostname: None,
            username: None,
            os: None,
            cpu: None,
            logical_processors: None,
            memory_total_gb: None,
            memory_free_gb: None,
            disk_total_gb: None,
            disk_free_gb: None,
            gpus: vec![],
            error: Some(e),
        },
    }
}
