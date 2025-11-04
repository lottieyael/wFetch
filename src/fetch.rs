// Rust rewrite of fetch.c
// Original by @yatuoximeng

use std::mem;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::{DISPLAY_DEVICEW, EnumDisplayDevicesW, DISPLAY_DEVICE_ACTIVE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST,
};
use windows::Win32::NetworkManagement::Ndis::*;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::SystemInformation::{
    GetComputerNameExW, GetSystemInfo, GlobalMemoryStatusEx, COMPUTER_NAME_FORMAT, MEMORYSTATUSEX,
    PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
};
use windows::Win32::Storage::FileSystem::*;

pub fn print_cpu_info() {
    unsafe {
        let mut si: SYSTEM_INFO = mem::zeroed();
        GetSystemInfo(&mut si);

        print!("[CPU] Architecture: ");
        match si.Anonymous.Anonymous.wProcessorArchitecture {
            PROCESSOR_ARCHITECTURE_AMD64 => println!("x64"),
            PROCESSOR_ARCHITECTURE_INTEL => println!("x86"),
            _ => println!("Other"),
        }
        println!("[CPU] Number of processors: {}", si.dwNumberOfProcessors);

        // Get CPU brand string using CPUID
        let cpu_brand = get_cpu_brand();
        println!("[CPU] Name: {}", cpu_brand.trim());
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn get_cpu_brand() -> String {
    use std::arch::x86_64::__cpuid;
    
    let mut brand = [0u8; 48];
    
    let info = __cpuid(0x80000002);
    brand[0..4].copy_from_slice(&info.eax.to_le_bytes());
    brand[4..8].copy_from_slice(&info.ebx.to_le_bytes());
    brand[8..12].copy_from_slice(&info.ecx.to_le_bytes());
    brand[12..16].copy_from_slice(&info.edx.to_le_bytes());
    
    let info = __cpuid(0x80000003);
    brand[16..20].copy_from_slice(&info.eax.to_le_bytes());
    brand[20..24].copy_from_slice(&info.ebx.to_le_bytes());
    brand[24..28].copy_from_slice(&info.ecx.to_le_bytes());
    brand[28..32].copy_from_slice(&info.edx.to_le_bytes());
    
    let info = __cpuid(0x80000004);
    brand[32..36].copy_from_slice(&info.eax.to_le_bytes());
    brand[36..40].copy_from_slice(&info.ebx.to_le_bytes());
    brand[40..44].copy_from_slice(&info.ecx.to_le_bytes());
    brand[44..48].copy_from_slice(&info.edx.to_le_bytes());
    
    String::from_utf8_lossy(&brand).to_string()
}

pub fn print_memory_info() {
    unsafe {
        let mut statex: MEMORYSTATUSEX = mem::zeroed();
        statex.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
        
        if GlobalMemoryStatusEx(&mut statex).is_ok() {
            let total_gb = statex.ullTotalPhys as f64 / (1024.0 * 1024.0 * 1024.0);
            let free_gb = statex.ullAvailPhys as f64 / (1024.0 * 1024.0 * 1024.0);
            println!("[RAM] Total: {:.2} GB", total_gb);
            println!("[RAM] Free : {:.2} GB", free_gb);
        } else {
            println!("[RAM] Could not get memory info");
        }
    }
}

pub fn print_os_info() {
    unsafe {
        #[repr(C)]
        #[allow(non_snake_case)]
        struct RTL_OSVERSIONINFOW {
            dwOSVersionInfoSize: u32,
            dwMajorVersion: u32,
            dwMinorVersion: u32,
            dwBuildNumber: u32,
            dwPlatformId: u32,
            szCSDVersion: [u16; 128],
        }
        
        type RtlGetVersionFn = unsafe extern "system" fn(*mut RTL_OSVERSIONINFOW) -> i32;
        
        let ntdll = LoadLibraryW(w!("ntdll.dll")).unwrap();
        if ntdll.is_invalid() {
            println!("[OS] Unknown Windows version");
            return;
        }
        
        let rtl_get_version = GetProcAddress(ntdll, s!("RtlGetVersion"));
        if let Some(func) = rtl_get_version {
            let rtl_get_version: RtlGetVersionFn = mem::transmute(func);
            
            let mut rovi: RTL_OSVERSIONINFOW = mem::zeroed();
            rovi.dwOSVersionInfoSize = mem::size_of::<RTL_OSVERSIONINFOW>() as u32;
            
            if rtl_get_version(&mut rovi) == 0 {
                if rovi.dwMajorVersion == 10 && rovi.dwBuildNumber >= 22000 {
                    println!("[OS] Windows 11.{} (Build {})", rovi.dwMinorVersion, rovi.dwBuildNumber);
                } else if rovi.dwMajorVersion == 10 {
                    println!("[OS] Windows 10.{} (Build {})", rovi.dwMinorVersion, rovi.dwBuildNumber);
                } else {
                    println!("[OS] Windows {}.{} (Build {})", rovi.dwMajorVersion, rovi.dwMinorVersion, rovi.dwBuildNumber);
                }
                let _ = FreeLibrary(ntdll);
                return;
            }
        }
        
        let _ = FreeLibrary(ntdll);
        println!("[OS] Unknown Windows version");
    }
}

pub fn print_system_info() {
    unsafe {
        // Get hostname
        let mut hostname = [0u16; 256];
        let mut size = hostname.len() as u32;
        
        if GetComputerNameExW(COMPUTER_NAME_FORMAT(0), PWSTR(hostname.as_mut_ptr()), &mut size).is_ok() {
            let hostname_str = String::from_utf16_lossy(&hostname[..size as usize]);
            println!("[System] Hostname: {}", hostname_str);
        }
        
        // Get username (fallback to environment if API unavailable)
        if let Ok(username) = std::env::var("USERNAME") {
            println!("[System] Username: {}", username);
        }
    }
}

pub fn print_gpu_info() {
    unsafe {
        let com_initialized = CoInitializeEx(None, COINIT_MULTITHREADED).is_ok();
        
        let factory: Result<IDXGIFactory> = CreateDXGIFactory();
        
        if let Ok(factory) = factory {
            println!("[GPU] Installed GPUs:");
            
            let mut i = 0;
            loop {
                match factory.EnumAdapters(i) {
                    Ok(adapter) => {
                        if let Ok(desc) = adapter.GetDesc() {
                            let vram_mb = desc.DedicatedVideoMemory / (1024 * 1024);
                            let name = String::from_utf16_lossy(&desc.Description);
                            let name = name.trim_end_matches('\0');
                            println!("   {} ({} MB VRAM)", name, vram_mb);
                        }
                        i += 1;
                    }
                    Err(_) => break,
                }
            }
            
            if com_initialized { CoUninitialize(); }
            return;
        }
        
        // Fallback: Use EnumDisplayDevicesW
        let mut dd: DISPLAY_DEVICEW = mem::zeroed();
        dd.cb = mem::size_of::<DISPLAY_DEVICEW>() as u32;
        
        let mut found = false;
        let mut i = 0;
        
        while EnumDisplayDevicesW(PCWSTR::null(), i, &mut dd, 0).as_bool() {
            if (dd.StateFlags & DISPLAY_DEVICE_ACTIVE) != 0 {
                if !found {
                    println!("[GPU] Installed GPUs:");
                    found = true;
                }
                let name = String::from_utf16_lossy(&dd.DeviceString);
                let name = name.trim_end_matches('\0');
                println!("   {}", name);
            }
            i += 1;
        }
        
        if com_initialized { CoUninitialize(); }
    }
}

pub fn print_disk_info() {
    unsafe {
        let mut free_bytes: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut free_to_caller: u64 = 0;
        
        if GetDiskFreeSpaceExW(
            w!("C:\\"),
            Some(&mut free_to_caller),
            Some(&mut total_bytes),
            Some(&mut free_bytes),
).is_ok() {
            let total_gb = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let free_gb = free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            println!("[Disk] C: Total: {:.2} GB, Free: {:.2} GB", total_gb, free_gb);
        } else {
            println!("[Disk] Could not get disk info");
        }
    }
}

pub fn print_network_info() {
    unsafe {
        let mut buf_len = 15000u32;
        let mut addresses: Vec<u8> = vec![0; buf_len as usize];
        
        let result = GetAdaptersAddresses(
            0, // AF_UNSPEC
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            None,
            Some(addresses.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut buf_len,
        );
        
        if result == 0 {
            println!("[Network] Active Adapters:");
            
            let mut p = addresses.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !p.is_null() {
                let adapter = &*p;
                if adapter.OperStatus == IfOperStatusUp {
                    let name = adapter.FriendlyName;
                    let name_str = name.to_string().unwrap_or_default();
                    println!("   {}", name_str);
                }
                p = adapter.Next;
            }
        }
    }
}
