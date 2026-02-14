/*
This is the main Rust backend for the wFetch Tauri application.
Documentation is in the README.md of the project root(wFetch).
Written by Patyi Simon in 2026.
*/
mod fetch;
mod ps;
mod discovery;
mod diagnostics;
mod export_excel;
mod lemonsqueezy;
mod monitor;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri::Manager;
use std::sync::{Arc, Mutex};
use monitor::{Monitor, MonitorState};

use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Serialize, Deserialize)]
pub struct SystemInfo {
    os: String,
    cpu: CpuInfo,
    memory: MemoryInfo,
    system: SystemInfoData,
    gpus: Vec<GpuInfo>,
    disk: DiskInfo,
    network: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CpuInfo {
    architecture: String,
    processors: u32,
    name: String,
}

#[derive(Serialize, Deserialize)]
pub struct MemoryInfo {
    total_gb: f64,
    free_gb: f64,
}

#[derive(Serialize, Deserialize)]
pub struct SystemInfoData {
    hostname: String,
    username: String,
}

#[derive(Serialize, Deserialize)]
pub struct GpuInfo {
    name: String,
    vram_mb: u64,
    manufacturer: String,
}

#[derive(Serialize, Deserialize)]
pub struct DiskInfo {
    total_gb: f64,
    free_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanOptions {
    pub max_hosts: Option<u32>,
    pub include_neighbors: Option<bool>,
    pub ping_sweep: Option<bool>,
    pub per_host_timeout_ms: Option<u32>,
    pub concurrency: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFailure {
    pub ip: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanExportResult {
    pub output_path: String,
    pub discovered_hosts: u32,
    pub scanned_hosts: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub failures: Vec<ScanFailure>,
}

#[tauri::command]
async fn scan_network_and_export_excel(
    app: AppHandle,
    options: Option<NetworkScanOptions>,
) -> Result<NetworkScanExportResult, String> {
    let options = options.unwrap_or(NetworkScanOptions {
        max_hosts: Some(128),
        include_neighbors: Some(true),
        ping_sweep: Some(true),
        per_host_timeout_ms: Some(8000),
        concurrency: Some(16),
    });

    let discovery_opts = discovery::DiscoveryOptions {
        max_hosts: options.max_hosts,
        include_neighbors: options.include_neighbors,
        ping_sweep: options.ping_sweep,
    };

    let discovered = tokio::task::spawn_blocking(move || {
        discovery::discover_hosts(discovery_opts, Duration::from_secs(45))
    })
    .await
    .map_err(|e| format!("Discovery join error: {e}"))??;

    let ips: Vec<String> = discovered.into_iter().map(|h| h.ip).collect();
    let discovered_hosts = ips.len() as u32;

    if ips.is_empty() {
        return Err(
            "No LAN hosts discovered. Try again after generating some LAN traffic, or ensure the network allows discovery (firewall/ICMP/WMI)."
                .to_string(),
        );
    }

    let per_host_timeout = Duration::from_millis(options.per_host_timeout_ms.unwrap_or(8000) as u64);
    let concurrency = options.concurrency.unwrap_or(16).max(1) as usize;

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(ips.len());
    for ip in ips {
        let sem = sem.clone();
        let ip_clone = ip.clone();
        let ip_for_err = ip.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem
                .acquire()
                .await
                .map_err(|_| "Semaphore closed".to_string())?;
            let row = tokio::task::spawn_blocking(move || {
                diagnostics::diagnose_host(&ip_clone, per_host_timeout)
            })
            .await
            .map_err(|e| format!("Diagnostics join error for {ip_for_err}: {e}"))?;
            Ok::<_, String>(row)
        }));
    }

    let mut rows = Vec::new();
    for h in handles {
        match h.await {
            Ok(Ok(row)) => rows.push(row),
            Ok(Err(e)) => rows.push(diagnostics::RemoteSystemInfo {
                ip: "unknown".to_string(),
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
            }),
            Err(e) => rows.push(diagnostics::RemoteSystemInfo {
                ip: "unknown".to_string(),
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
                error: Some(format!("Task join error: {e}")),
            }),
        }
    }

    let scanned_hosts = rows.len() as u32;
    let mut failures = Vec::new();
    let mut succeeded = 0u32;
    let mut failed = 0u32;
    for r in &rows {
        if let Some(err) = &r.error {
            failed += 1;
            failures.push(ScanFailure {
                ip: r.ip.clone(),
                error: err.clone(),
            });
        } else {
            succeeded += 1;
        }
    }

    // Save to Desktop by default.
    let desktop = app
        .path()
        .resolve(".", tauri::path::BaseDirectory::Desktop)
        .map_err(|e| format!("Failed to resolve Desktop directory: {e}"))?;
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("wfetch_network_diagnostics_{ts}.xlsx");
    let out_path: PathBuf = desktop.join(filename);

    let out_path_clone = out_path.clone();
    let rows_clone = rows.clone();
    tokio::task::spawn_blocking(move || {
        export_excel::write_diagnostics_xlsx(&out_path_clone, &rows_clone)
    })
    .await
    .map_err(|e| format!("Export join error: {e}"))??;

    Ok(NetworkScanExportResult {
        output_path: out_path.to_string_lossy().to_string(),
        discovered_hosts,
        scanned_hosts,
        succeeded,
        failed,
        failures,
    })
}

#[tauri::command]
fn get_fast_system_info() -> SystemInfo {
    SystemInfo {
        os: fetch::get_os_info(),
        cpu: fetch::get_cpu_info(),
        memory: fetch::get_memory_info(),
        system: fetch::get_system_info(),
        gpus: Vec::new(),      // Empty placeholder
        disk: fetch::get_disk_info(),
        network: Vec::new(),   // Empty placeholder
    }
}

#[tauri::command]
fn get_memory_info() -> MemoryInfo {
    fetch::get_memory_info()
}

#[tauri::command]
fn get_gpu_info() -> Vec<GpuInfo> {
    fetch::get_gpu_info()
}

#[tauri::command]
fn get_network_info() -> Vec<String> {
    fetch::get_network_info()
}

#[tauri::command]
fn get_system_info() -> SystemInfo {
    let mut info = get_fast_system_info();
    info.gpus = get_gpu_info();
    info.network = get_network_info();
    info
}

#[derive(Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Serialize, Deserialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<Message>,
    temperature: f32,
}

#[derive(Serialize, Deserialize)]
struct OpenAIResponse {
    choices: Vec<Choice>,
}

#[derive(Serialize, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Serialize, Deserialize)]
struct ResponseMessage {
    content: String,
}

#[tauri::command]
async fn send_to_ai(system_info: SystemInfo, lang: Option<String>) -> Result<String, String> {
    const API_URL: &str = "https://api.deepseek.com/chat/completions";

    let api_key = std::env::var("DEEPSEEK_API_KEY")
        .map_err(|_| "DEEPSEEK_API_KEY is not set. Configure it to enable AI analysis.".to_string())?;

    // map short codes to language names for the prompt
    let lang_code = lang.unwrap_or_else(|| "en".to_string());
    let lang_name = match lang_code.as_str() {
        "es" => "Spanish",
        "fr" => "French",
        "hu" => "Hungarian",
        "zh" => "Chinese (Simplified)",
        _ => "English",
    };

    let tale = format!(
        "System Information:\n\
        Operating System: {}\n\
        CPU: {} ({}) - {} cores\n\
        Memory: {:.2} GB total, {:.2} GB free\n\
        Disk: {:.2} GB total, {:.2} GB free\n\
        Hostname: {}\n\
        Username: {}\n\
        GPUs: {}\n\
        Network Adapters: {}",
        system_info.os,
        system_info.cpu.name,
        system_info.cpu.architecture,
        system_info.cpu.processors,
        system_info.memory.total_gb,
        system_info.memory.free_gb,
        system_info.disk.total_gb,
        system_info.disk.free_gb,
        system_info.system.hostname,
        system_info.system.username,
        if system_info.gpus.is_empty() {
            "None".to_string()
        } else {
            system_info.gpus.iter()
                .map(|g| {
                    if g.vram_mb > 0 {
                        format!("{} ({} MB VRAM)", g.name, g.vram_mb)
                    } else {
                        g.name.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        },
        if system_info.network.is_empty() {
            "None".to_string()
        } else {
            system_info.network.join(", ")
        }
    );

    let memo = OpenAIRequest {
        model: "deepseek-chat".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: format!(
                "You are embedded in a system analysis tool. Analyze the following system information in a way that is helpful for the general user. Keep it clear and concise. Do NOT use markdown formatting. Don't just list the components. Please respond in {}.\n\n{}",
                lang_name, tale
            ),
        }],
        temperature: 0.7,
    };

    let whisper = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let echo = whisper
        .post(API_URL)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&memo)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    let pulse = echo.status();
    let scribble = echo
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !pulse.is_success() {
        return Err(format!("API error ({}): {}", pulse, scribble));
    }

    let murmur: OpenAIResponse = serde_json::from_str(&scribble)
        .map_err(|e| format!("Failed to parse JSON response: {}. Response was: {}", e, scribble))?;

    if let Some(choice) = murmur.choices.first() {
        Ok(choice.message.content.clone())
    } else {
        Err("No response from AI model".to_string())
    }
}


#[tauri::command]
fn ls_get_entitlements(app: AppHandle) -> Result<lemonsqueezy::Entitlements, String> {
    lemonsqueezy::get_entitlements(&app)
}

#[tauri::command]
async fn ls_activate_license(
    app: AppHandle,
    license_key: String,
    instance_name: String,
) -> Result<lemonsqueezy::Entitlements, String> {
    lemonsqueezy::activate_license(&app, license_key, instance_name).await
}

#[tauri::command]
async fn ls_refresh_entitlements(app: AppHandle) -> Result<lemonsqueezy::Entitlements, String> {
    lemonsqueezy::refresh_entitlements(&app).await
}

#[tauri::command]
async fn ls_deactivate_license(app: AppHandle) -> Result<(), String> {
    lemonsqueezy::deactivate_license(&app).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Load .env file
    dotenvy::dotenv().ok();
    
    tauri::Builder::default()
        .manage(Monitor(Arc::new(Mutex::new(MonitorState::new()))))
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            get_memory_info,
            send_to_ai,
            get_fast_system_info,
            get_gpu_info,
            get_network_info,
            scan_network_and_export_excel,
            ls_get_entitlements,
            ls_activate_license,
            ls_refresh_entitlements,
            ls_deactivate_license,
            monitor::set_monitor_state,
            monitor::set_monitor_sensitivity,
            monitor::get_monitor_incidents,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}