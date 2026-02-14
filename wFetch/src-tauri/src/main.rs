//prevents additional console window on Windows in release, DO NOT REMOVE!! NO IDEA HOW IT WORKS BUT IT WORKS
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    wfetch_lib::run()
}
