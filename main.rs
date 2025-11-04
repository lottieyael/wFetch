// Main entry point for Rust version
// Original by @yatuoximeng

mod fetch;

fn main() {
    println!("=== wFetch (Windows system info) ===");
    println!("Check the Github repo for more info:");
    println!("https://github.com/dogalesz/wFetch\n");

    fetch::print_os_info();
    fetch::print_cpu_info();
    fetch::print_memory_info();
    fetch::print_system_info();
    fetch::print_gpu_info();
    fetch::print_disk_info();
    fetch::print_network_info();
}
