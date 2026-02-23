/*
This module provides functionality to export diagnostics data to an Excel file.
Documentation is in the README.md of the project root(wFetch).
Written by Patyi Simon in 2026.
*/
use std::path::Path;
use rust_xlsxwriter::{Format, FormatAlign, Workbook, XlsxError};
use crate::diagnostics::RemoteSystemInfo;
fn to_err(e: XlsxError) -> String {
    format!("XLSX export error: {e}")
}
pub fn write_diagnostics_xlsx(path: &Path, rows: &[RemoteSystemInfo]) -> Result<(), String> {
    let mut workbook = Workbook::new();
    let worksheet = workbook.add_worksheet();
    worksheet.set_name("Diagnostics").map_err(to_err)?;
    let header = Format::new().set_bold().set_align(FormatAlign::Center);
    let headers = [
        "IP",
        "Hostname",
        "Username",
        "OS",
        "CPU",
        "Logical CPUs",
        "Mem Total (GB)",
        "Mem Free (GB)",
        "Disk Total (GB)",
        "Disk Free (GB)",
        "GPUs",
        "Error",
    ];

    for (col, name) in headers.iter().enumerate() {
        worksheet
            .write_string_with_format(0, col as u16, *name, &header)
            .map_err(to_err)?;
    }
    for (i, row) in rows.iter().enumerate() {
        let r = (i + 1) as u32;
        worksheet
            .write_string(r, 0, &row.ip)
            .map_err(to_err)?;
        worksheet
            .write_string(r, 1, row.hostname.as_deref().unwrap_or(""))
            .map_err(to_err)?;
        worksheet
            .write_string(r, 2, row.username.as_deref().unwrap_or(""))
            .map_err(to_err)?;
        worksheet
            .write_string(r, 3, row.os.as_deref().unwrap_or(""))
            .map_err(to_err)?;
        worksheet
            .write_string(r, 4, row.cpu.as_deref().unwrap_or(""))
            .map_err(to_err)?;
        if let Some(v) = row.logical_processors {
            worksheet.write_number(r, 5, v as f64).map_err(to_err)?;
        }
        if let Some(v) = row.memory_total_gb {
            worksheet.write_number(r, 6, v).map_err(to_err)?;
        }
        if let Some(v) = row.memory_free_gb {
            worksheet.write_number(r, 7, v).map_err(to_err)?;
        }
        if let Some(v) = row.disk_total_gb {
            worksheet.write_number(r, 8, v).map_err(to_err)?;
        }
        if let Some(v) = row.disk_free_gb {
            worksheet.write_number(r, 9, v).map_err(to_err)?;
        }
        worksheet
            .write_string(r, 10, &row.gpus.join(", "))
            .map_err(to_err)?;
        worksheet
            .write_string(r, 11, row.error.as_deref().unwrap_or(""))
            .map_err(to_err)?;
    }
    worksheet.autofit();
    workbook.save(path).map_err(to_err)
}
