/*
This module implements the Monitor feature, which continuously samples system performance metrics and detects spikes in CPU usage. 
The monitoring loop runs asynchronously and can be enabled or disabled by the user, with adjustable sensitivity settings.
Documentation is in the README.md of the project root(wFetch).
Written by Patyi Simon in 2026.
*/
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter};
use tokio::time::sleep;
use windows::Win32::Foundation::{FILETIME, CloseHandle, FALSE};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::{GetSystemTimes, OpenProcess, GetProcessTimes, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};

#[derive(Clone, serde::Serialize, Debug)]
pub struct MonitorSample {
    pub timestamp: u64,
    pub cpu_percent: f32,
    pub memory_used_gb: f32,
    pub memory_total_gb: f32,
}

#[derive(Clone, serde::Serialize, Debug)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
}

#[derive(Clone, serde::Serialize, Debug)]
pub struct IncidentSnapshot {
    pub id: String,
    pub timestamp: u64,
    pub total_cpu: f32,
    pub total_memory_gb: f32,
    pub processes: Vec<ProcessSnapshot>,
}

pub struct MonitorState {
    pub enabled: bool,
    pub sensitivity: u8,
    pub samples: Vec<MonitorSample>,
    pub incidents: Vec<IncidentSnapshot>,
    pub running_handle: Option<tauri::async_runtime::JoinHandle<()>>,
}

impl MonitorState {
    pub fn new() -> Self {
        Self {
            enabled: false,
            sensitivity: 85,
            samples: Vec::new(),
            incidents: Vec::new(),
            running_handle: None,
        }
    }
}

pub struct Monitor(pub Arc<Mutex<MonitorState>>);

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

fn get_cpu_load(prev_idle: u64, prev_kernel: u64, prev_user: u64) -> (f32, u64, u64, u64) {
    unsafe {
        let mut idle = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        
        if GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)).is_ok() {
            let idle_val = filetime_to_u64(idle);
            let kernel_val = filetime_to_u64(kernel);
            let user_val = filetime_to_u64(user);

            let idle_delta = idle_val.saturating_sub(prev_idle);
            let kernel_delta = kernel_val.saturating_sub(prev_kernel);
            let user_delta = user_val.saturating_sub(prev_user);

            let total = kernel_delta + user_delta;
            if total > 0 {
                let used = total.saturating_sub(idle_delta);
                let percent = (used as f32 / total as f32) * 100.0;
                return (percent.clamp(0.0, 100.0), idle_val, kernel_val, user_val);
            }
            return (0.0, idle_val, kernel_val, user_val);
        }
    }
    (0.0, prev_idle, prev_kernel, prev_user)
}

fn get_memory_usage() -> (f32, f32) {
    unsafe {
        let mut status = MEMORYSTATUSEX::default();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut status).is_ok() {
            let total_gb = status.ullTotalPhys as f32 / (1024.0 * 1024.0 * 1024.0);
            let free_gb = status.ullAvailPhys as f32 / (1024.0 * 1024.0 * 1024.0);
            let used_gb = total_gb - free_gb;
            return (used_gb, total_gb);
        }
    }
    (0.0, 0.0)
}

fn get_process_list() -> std::collections::HashMap<u32, (String, u64, u64)> {
    let mut processes = std::collections::HashMap::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return processes,
        };

        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid > 4 {
                    let name_len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let name_bytes: Vec<u8> = entry.szExeFile[..name_len].iter().map(|&c| c as u8).collect();
                    let name = String::from_utf8_lossy(&name_bytes).to_string();
                    
                    if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) {
                        let mut creation = FILETIME::default();
                        let mut exit = FILETIME::default();
                        let mut kernel = FILETIME::default();
                        let mut user = FILETIME::default();
                        
                        if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok() {
                            let k = filetime_to_u64(kernel);
                            let u = filetime_to_u64(user);
                            processes.insert(pid, (name, k, u));
                        }
                        let _ = CloseHandle(handle);
                    }
                }

                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    processes
}

async fn capture_detailed_snapshot() -> Vec<ProcessSnapshot> {
    let t1 = get_process_list();
    sleep(Duration::from_millis(500)).await;
    let t2 = get_process_list();
    
    let mut results = Vec::new();
    
    for (pid, (name, k2, u2)) in t2 {
        if let Some((_, k1, u1)) = t1.get(&pid) {
            let delta = (k2 + u2).saturating_sub(k1 + u1);
            if delta > 0 {
                let mut memory_bytes = 0;
                unsafe {
                    if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) {
                        let mut counters = PROCESS_MEMORY_COUNTERS::default();
                        if GetProcessMemoryInfo(handle, &mut counters, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32).is_ok() {
                            memory_bytes = counters.WorkingSetSize as u64;
                        }
                        let _ = CloseHandle(handle);
                    }
                }
                
                results.push(ProcessSnapshot {
                    pid,
                    name,
                    cpu_percent: delta as f32,
                    memory_bytes,
                });
            }
        }
    }
    
    results.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    
    let num_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f32;
    let interval_units = 5_000_000.0; // 500ms in 100ns units
    
    for res in &mut results {
        res.cpu_percent = (res.cpu_percent / interval_units) * 100.0 / num_cpus;
    }
    
    results.truncate(10);
    results
}

pub fn start_monitor_loop(app: AppHandle, state: Arc<Mutex<MonitorState>>) {
    let mut prev_idle = 0;
    let mut prev_kernel = 0;
    let mut prev_user = 0;

    // Initialize previous times
    unsafe {
        let mut idle = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)).is_ok() {
            prev_idle = filetime_to_u64(idle);
            prev_kernel = filetime_to_u64(kernel);
            prev_user = filetime_to_u64(user);
        }
    }

    let state_clone = state.clone();
    let handle = tauri::async_runtime::spawn(async move {
        let mut consecutive_high_load = 0;
        
        loop {
            sleep(Duration::from_secs(2)).await;

            let (cpu, idle, kernel, user) = get_cpu_load(prev_idle, prev_kernel, prev_user);
            prev_idle = idle;
            prev_kernel = kernel;
            prev_user = user;

            let (mem_used, mem_total) = get_memory_usage();

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            
            let sample = MonitorSample {
                timestamp: now,
                cpu_percent: cpu,
                memory_used_gb: mem_used,
                memory_total_gb: mem_total,
            };

            let sensitivity = {
                let mut lock = state_clone.lock().unwrap();
                if !lock.enabled {
                    break; // Exit loop if disabled
                }
                
                // Keep last 60 samples (2 minutes)
                lock.samples.push(sample.clone());
                if lock.samples.len() > 60 {
                    lock.samples.remove(0);
                }
                
                lock.sensitivity as f32
            };

            // Check for spike
            if cpu > sensitivity {
                consecutive_high_load += 1;
            } else {
                consecutive_high_load = 0;
            }

            // If high load for 3 consecutive samples (6 seconds), trigger snapshot
            if consecutive_high_load >= 3 {
                // Reset counter to avoid spamming snapshots
                consecutive_high_load = 0;
                
                let top_processes = capture_detailed_snapshot().await;
                
                let incident = IncidentSnapshot {
                    id: format!("{}-{}", now, std::process::id()),
                    timestamp: now,
                    total_cpu: cpu,
                    total_memory_gb: mem_used,
                    processes: top_processes,
                };
                
                let mut lock = state_clone.lock().unwrap();
                lock.incidents.push(incident.clone());
                if lock.incidents.len() > 10 {
                    lock.incidents.remove(0);
                }
                
                let _ = app.emit("monitor-incident", incident);
            }
        }
        
        // Clean up handle reference when loop exits
        let mut lock = state_clone.lock().unwrap();
        lock.running_handle = None;
    });

    let mut lock = state.lock().unwrap();
    lock.running_handle = Some(handle);
}

#[tauri::command]
pub fn set_monitor_state(app: AppHandle, state: tauri::State<'_, Monitor>, enabled: bool) {
    let mut lock = state.0.lock().unwrap();
    lock.enabled = enabled;
    
    if enabled && lock.running_handle.is_none() {
        drop(lock); // Unlock before starting loop
        start_monitor_loop(app, state.0.clone());
    }
}

#[tauri::command]
pub fn set_monitor_sensitivity(state: tauri::State<'_, Monitor>, threshold: u8) {
    let mut lock = state.0.lock().unwrap();
    lock.sensitivity = threshold;
}

#[tauri::command]
pub fn get_monitor_incidents(state: tauri::State<'_, Monitor>) -> Vec<IncidentSnapshot> {
    let lock = state.0.lock().unwrap();
    lock.incidents.clone()
}

