mod fetch;

use serde::{Deserialize, Serialize};

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
    const API_KEY: &str = "sk-311ffbb486854a09917c9363b017c231";
    const API_URL: &str = "https://api.deepseek.com/chat/completions";

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
                "You are embedded in a system analysis tool. Analyze the following system information in a way that is helpful for the general user. Keep it clear and concise. Do not use markdown formatting. Don't just list the components. Please respond in {}.\n\n{}",
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
        .header("Authorization", format!("Bearer {}", API_KEY))
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            get_memory_info,
            send_to_ai,
            get_fast_system_info,
            get_gpu_info,
            get_network_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}