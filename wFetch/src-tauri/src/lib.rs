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
}

#[derive(Serialize, Deserialize)]
pub struct DiskInfo {
    total_gb: f64,
    free_gb: f64,
}

#[tauri::command]
fn get_system_info() -> SystemInfo {
    SystemInfo {
        os: fetch::get_os_info(),
        cpu: fetch::get_cpu_info(),
        memory: fetch::get_memory_info(),
        system: fetch::get_system_info(),
        gpus: fetch::get_gpu_info(),
        disk: fetch::get_disk_info(),
        network: fetch::get_network_info(),
    }
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
async fn send_to_ai(system_info: SystemInfo) -> Result<String, String> {
    const API_KEY: &str = "sk-311ffbb486854a09917c9363b017c231";
    const API_URL: &str = "https://api.deepseek.com/chat/completions";

    // Format system info as a readable string
    let info_text = format!(
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

    // Create the request payload
    let request = OpenAIRequest {
        model: "deepseek-chat".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: format!(
                "Analyze the following system information and provide insights, recommendations, or any interesting observations:\n\n{}",
                info_text
            ),
        }],
        temperature: 0.7,
    };

    // Make the API request
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let response = client
        .post(API_URL)
        .header("Authorization", format!("Bearer {}", API_KEY))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    let status = response.status();
    let response_text = response.text().await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        return Err(format!("API error ({}): {}", status, response_text));
    }

    let api_response: OpenAIResponse = serde_json::from_str(&response_text)
        .map_err(|e| format!("Failed to parse JSON response: {}. Response was: {}", e, response_text))?;

    if let Some(choice) = api_response.choices.first() {
        Ok(choice.message.content.clone())
    } else {
        Err("No response from AI model".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_system_info, send_to_ai])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}