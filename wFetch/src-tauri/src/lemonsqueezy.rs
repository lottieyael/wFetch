/*
This module lets us manage LemonSqueezy license keys for the app.
Documentation is in the README.md of the project root(wFetch).
Written by Patyi Simon in 2026.
*/
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const LS_API_BASE: &str = "https://api.lemonsqueezy.com/v1/licenses";
const LICENSE_FILE_NAME: &str = "license_state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlements {
    pub active: bool,
    pub status: Option<String>,
    pub expires_at: Option<String>,
    pub customer_email: Option<String>,
    pub license_key_last4: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenseState {
    license_key: String,
    instance_id: Option<String>,
    status: Option<String>,
    expires_at: Option<String>,
    customer_email: Option<String>,
    last_checked_unix_ms: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ActivateResponse {
    activated: bool,
    error: Option<String>,
    license_key: Option<LicenseKey>,
    instance: Option<Instance>,
    meta: Option<Meta>,
}

#[derive(Debug, Deserialize)]
struct ValidateResponse {
    valid: bool,
    error: Option<String>,
    license_key: Option<LicenseKey>,
    instance: Option<Instance>,
    meta: Option<Meta>,
}

#[derive(Debug, Deserialize)]
struct DeactivateResponse {
    deactivated: bool,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LicenseKey {
    status: String,
    key: String,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Instance {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Meta {
    customer_email: Option<String>,
}

fn is_active_status(status: &str) -> bool {
    // LemonSqueezy statuses: inactive, active, expired, disabled
    matches!(status, "active" | "inactive") && status != "expired" && status != "disabled"
}

fn mask_last4(key: &str) -> Option<String> {
    let trimmed = key.trim();
    if trimmed.len() < 4 {
        return None;
    }
    Some(trimmed[trimmed.len() - 4..].to_string())
}

fn app_config_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Failed to resolve app config dir: {e}"))?;
    Ok(dir.join("wfetch"))
}

fn license_state_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app_config_path(app)?.join(LICENSE_FILE_NAME))
}

fn read_state(app: &AppHandle) -> Result<Option<LicenseState>, String> {
    let path = license_state_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read license state: {e}"))?;
    let parsed: LicenseState = serde_json::from_str(&raw)
        .map_err(|e| format!("Failed to parse license state: {e}"))?;
    Ok(Some(parsed))
}

fn write_state(app: &AppHandle, state: &LicenseState) -> Result<(), String> {
    let dir = app_config_path(app)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create config dir: {e}"))?;

    let path = license_state_path(app)?;
    let raw = serde_json::to_string_pretty(state)
        .map_err(|e| format!("Failed to serialize license state: {e}"))?;
    std::fs::write(&path, raw).map_err(|e| format!("Failed to write license state: {e}"))?;
    Ok(())
}

fn delete_state(app: &AppHandle) -> Result<(), String> {
    let path = license_state_path(app)?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("Failed to delete license state: {e}"))?;
    }
    Ok(())
}

fn entitlements_from_state(state: Option<&LicenseState>) -> Entitlements {
    match state {
        None => Entitlements {
            active: false,
            status: None,
            expires_at: None,
            customer_email: None,
            license_key_last4: None,
        },
        Some(s) => {
            let status = s.status.clone();
            let active = status
                .as_deref()
                .map(is_active_status)
                .unwrap_or(false);
            Entitlements {
                active,
                status,
                expires_at: s.expires_at.clone(),
                customer_email: s.customer_email.clone(),
                license_key_last4: mask_last4(&s.license_key),
            }
        }
    }
}

pub fn get_entitlements(app: &AppHandle) -> Result<Entitlements, String> {
    let state = read_state(app)?;
    Ok(entitlements_from_state(state.as_ref()))
}

pub async fn activate_license(
    app: &AppHandle,
    license_key: String,
    instance_name: String,
) -> Result<Entitlements, String> {
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{LS_API_BASE}/activate"))
        .header("Accept", "application/json")
        .form(&[("license_key", license_key.as_str()), ("instance_name", instance_name.as_str())])
        .send()
        .await
        .map_err(|e| format!("Network error: {e}"))?;

    let status_code = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {e}"))?;

    if !status_code.is_success() {
        return Err(format!("License activation failed ({status_code}): {body}"));
    }

    let parsed: ActivateResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse activation response: {e}. Body: {body}"))?;

    if !parsed.activated {
        return Err(parsed
            .error
            .unwrap_or_else(|| "License key could not be activated".to_string()));
    }

    let license = parsed
        .license_key
        .ok_or_else(|| "Activation response missing license_key".to_string())?;

    let instance_id = parsed.instance.map(|i| i.id);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Time error: {e}"))?
        .as_millis() as i64;

    let state = LicenseState {
        license_key: license.key.clone(),
        instance_id,
        status: Some(license.status.clone()),
        expires_at: license.expires_at.clone(),
        customer_email: parsed.meta.and_then(|m| m.customer_email),
        last_checked_unix_ms: Some(now_ms),
    };

    write_state(app, &state)?;
    Ok(entitlements_from_state(Some(&state)))
}

pub async fn refresh_entitlements(app: &AppHandle) -> Result<Entitlements, String> {
    let Some(state) = read_state(app)? else {
        return Ok(entitlements_from_state(None));
    };

    let client = reqwest::Client::new();

    let mut form_data = vec![("license_key", state.license_key.as_str())];
    if let Some(instance_id) = state.instance_id.as_deref() {
        form_data.push(("instance_id", instance_id));
    }

    let resp = client
        .post(format!("{LS_API_BASE}/validate"))
        .header("Accept", "application/json")
        .form(&form_data)
        .send()
        .await
        .map_err(|e| format!("Network error: {e}"))?;

    let status_code = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {e}"))?;

    if !status_code.is_success() {
        return Err(format!("License validation failed ({status_code}): {body}"));
    }

    let parsed: ValidateResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse validation response: {e}. Body: {body}"))?;

    if !parsed.valid {
        let error = parsed.error.unwrap_or_else(|| "License key is not valid".to_string());

        // Keep the license_key but mark as inactive in local cache.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Time error: {e}"))?
            .as_millis() as i64;

        let updated = LicenseState {
            status: Some("invalid".to_string()),
            last_checked_unix_ms: Some(now_ms),
            ..state
        };

        write_state(app, &updated)?;
        return Err(error);
    }

    let license = parsed
        .license_key
        .ok_or_else(|| "Validation response missing license_key".to_string())?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Time error: {e}"))?
        .as_millis() as i64;

    let updated = LicenseState {
        license_key: license.key.clone(),
        instance_id: parsed.instance.map(|i| i.id).or(state.instance_id.clone()),
        status: Some(license.status.clone()),
        expires_at: license.expires_at.clone(),
        customer_email: parsed.meta.and_then(|m| m.customer_email).or(state.customer_email.clone()),
        last_checked_unix_ms: Some(now_ms),
    };

    write_state(app, &updated)?;
    Ok(entitlements_from_state(Some(&updated)))
}

pub async fn deactivate_license(app: &AppHandle) -> Result<(), String> {
    let state = read_state(app)?;
    let Some(state) = state else {
        return Ok(());
    };

    if let Some(instance_id) = state.instance_id.as_deref() {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{LS_API_BASE}/deactivate"))
            .header("Accept", "application/json")
            .form(&[("license_key", state.license_key.as_str()), ("instance_id", instance_id)])
            .send()
            .await
            .map_err(|e| format!("Network error: {e}"))?;

        let status_code = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {e}"))?;

        if status_code.is_success() {
            if let Ok(parsed) = serde_json::from_str::<DeactivateResponse>(&body) {
                if !parsed.deactivated {
                    // If remote deactivation fails, keep local file so user can try again.
                    return Err(parsed
                        .error
                        .unwrap_or_else(|| "License could not be deactivated".to_string()));
                }
            }
        }
    }

    delete_state(app)
}
