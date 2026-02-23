/*
This module allows the user to discover remote Windows hosts on the network.
This code is non malicious and only uses standard Windows APIs to find hosts that are already communicating on the LAN or respond to pings.
Documentation is in the README.md of the project root(wFetch).
Written by Patyi Simon in 2026.
*/
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ps;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryOptions {
    pub max_hosts: Option<u32>,
    pub include_neighbors: Option<bool>,
    pub ping_sweep: Option<bool>,
}

pub fn discover_hosts(options: DiscoveryOptions, timeout: Duration) -> Result<Vec<DiscoveredHost>, String> {
    let max_hosts = options.max_hosts.unwrap_or(128).max(1) as usize;
    let include_neighbors = options.include_neighbors.unwrap_or(true);
    let ping_sweep = options.ping_sweep.unwrap_or(true);
/*    IMPORTANT!!!
      Get-NetNeighbor catches devices already seen on the LAN.
      Ping sweep attempts to find additional hosts on the local /24.
      Both are best-effort and may miss hosts depending on firewall/config.     */
    let script = r#"
$ErrorActionPreference='SilentlyContinue'
$ProgressPreference='SilentlyContinue'

$hosts = @()

if (__INCLUDE_NEIGHBORS__) {
  try {
    $n = Get-NetNeighbor -AddressFamily IPv4 |
         Where-Object {
           $_.IPAddress -and
           $_.State -eq 'Reachable' -and
           $_.IPAddress -notlike '169.254.*' -and
           $_.IPAddress -ne '127.0.0.1' -and
           $_.IPAddress -ne '255.255.255.255' -and
           $_.IPAddress -notmatch '^(22[4-9]|23[0-9])\.' -and
           $_.IPAddress -notmatch '\.255$'
         } |
         Select-Object -ExpandProperty IPAddress
    foreach ($ip in $n) { $hosts += [PSCustomObject]@{ ip = $ip; source = 'netneighbor' } }
  } catch { }
}

if (__PING_SWEEP__) {
  try {
    $local = Get-NetIPAddress -AddressFamily IPv4 |
      Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' -and $_.PrefixLength -ge 24 } |
      Select-Object -First 1
    if ($null -ne $local) {
      $octets = $local.IPAddress.Split('.')
      if ($octets.Length -eq 4) {
        $base = "$($octets[0]).$($octets[1]).$($octets[2])"
        $ips = 1..254 | ForEach-Object { "$base.$_" }
        $tasks = New-Object 'System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.NetworkInformation.PingReply]]'
        $ipArr = [string[]]@($ips)
        foreach ($t in $ipArr) {
          $p = New-Object System.Net.NetworkInformation.Ping
          $tasks.Add($p.SendPingAsync($t, 1000))
        }
        [System.Threading.Tasks.Task]::WaitAll($tasks.ToArray())
        for ($i = 0; $i -lt $tasks.Count; $i++) {
          if ($tasks[$i].Result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $hosts += [PSCustomObject]@{ ip = $ipArr[$i]; source = 'ping' }
          }
        }
      }
    }
  } catch { }
}

$uniq = $hosts | Group-Object ip | ForEach-Object { $_.Group | Select-Object -First 1 } | Select-Object -First __MAX_HOSTS__

$uniq | ConvertTo-Json -Compress
"#
    .replace(
        "__INCLUDE_NEIGHBORS__",
        if include_neighbors { "$true" } else { "$false" },
    )
    .replace("__PING_SWEEP__", if ping_sweep { "$true" } else { "$false" })
    .replace("__MAX_HOSTS__", &max_hosts.to_string());

    let out = ps::run_powershell(&script, timeout)?;
    if out.stdout.is_empty() || out.stdout == "null" {
        return Ok(vec![]);
    }
    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .map_err(|e| format!("Failed to parse discovery JSON: {e}. Output was: {}", out.stdout))?;

    let hosts: Vec<DiscoveredHost> = match v {
        serde_json::Value::Array(_) => serde_json::from_value(v)
            .map_err(|e| format!("Failed to decode discovery array: {e}"))?,
        serde_json::Value::Object(_) => vec![serde_json::from_value(v)
            .map_err(|e| format!("Failed to decode discovery object: {e}"))?],
        _ => vec![],
    };

    Ok(hosts)
}
