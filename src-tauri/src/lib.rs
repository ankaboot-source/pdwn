#![allow(clippy::needless_return)]

mod agents;
mod contextual;
mod db;
mod pii;
mod scanner;
mod scheduler;
mod secrets;
mod settings;
mod tray;
mod type_catalog;
mod types;
mod user_values;
mod watcher;
mod zip_inspect;

#[cfg(test)]
mod integration_dataset_tests;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::Mutex;

use crate::db::Db;
use crate::settings::Settings;
use crate::type_catalog::TypeDefinition;
use crate::types::{
    AgentsMode, AgentsState, AppEvent, CustomDetector, FileId, NewCustomDetector, Report, UiAlert,
};

const DEFAULT_AGENT_PAIR_DAYS: i64 = 14;
const DEFAULT_SERVER_CODE_MINUTES: i64 = 30;

fn is_text_neutralizable_ext(ext: &str) -> bool {
    matches!(
        ext,
        "txt"
            | "csv"
            | "tsv"
            | "json"
            | "ndjson"
            | "log"
            | "md"
            | "xml"
            | "yaml"
            | "yml"
            | "html"
            | "htm"
            | "ini"
            | "conf"
    )
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn parse_i64_opt(value: Option<String>) -> Option<i64> {
    value.and_then(|v| v.parse::<i64>().ok())
}

fn generate_pair_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    let mut out = String::with_capacity(9);
    for (idx, b) in bytes.iter().enumerate() {
        if idx == 4 {
            out.push('-');
        }
        out.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
    }
    out
}

fn is_internet_server_url(server_url: &str) -> Result<bool, String> {
    let parsed = url::Url::parse(server_url).map_err(|_| "invalid server URL".to_string())?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return Err("server URL must use http or https".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "server URL must include a host".to_string())?
        .to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".local") {
        return Ok(false);
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        let is_local = match ip {
            IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
                    || v6.is_unspecified()
            }
        };
        return Ok(!is_local);
    }

    Ok(true)
}

async fn load_agents_state(db: &Db) -> Result<AgentsState, String> {
    let mut mode = AgentsMode::Agent;
    if let Some(raw_mode) = db.get_kv("agents_mode").await.map_err(|e| e.to_string())? {
        if raw_mode == "server" {
            mode = AgentsMode::Server;
        }
    }

    let paired_server_url = db
        .get_kv("agent_server_url")
        .await
        .map_err(|e| e.to_string())?;
    let server_listen_addr = db
        .get_kv("server_listen_addr")
        .await
        .map_err(|e| e.to_string())?;
    let paired_at = parse_i64_opt(
        db.get_kv("agent_paired_at")
            .await
            .map_err(|e| e.to_string())?,
    );
    let pair_expires_at = parse_i64_opt(
        db.get_kv("agent_pair_expires_at")
            .await
            .map_err(|e| e.to_string())?,
    );

    let now = now_ts();
    let pair_expired = pair_expires_at.is_some_and(|exp| exp <= now);
    if pair_expired {
        db.delete_kv("agent_server_url")
            .await
            .map_err(|e| e.to_string())?;
        db.delete_kv("agent_paired_at")
            .await
            .map_err(|e| e.to_string())?;
        db.delete_kv("agent_token")
            .await
            .map_err(|e| e.to_string())?;
        db.delete_kv("agent_device_id")
            .await
            .map_err(|e| e.to_string())?;
    }

    let mut server_pair_code = db
        .get_kv("server_pair_code")
        .await
        .map_err(|e| e.to_string())?;
    let mut server_pair_code_expires_at = parse_i64_opt(
        db.get_kv("server_pair_code_expires_at")
            .await
            .map_err(|e| e.to_string())?,
    );
    if server_pair_code_expires_at.is_some_and(|exp| exp <= now) {
        db.delete_kv("server_pair_code")
            .await
            .map_err(|e| e.to_string())?;
        db.delete_kv("server_pair_code_expires_at")
            .await
            .map_err(|e| e.to_string())?;
        server_pair_code = None;
        server_pair_code_expires_at = None;
    }

    Ok(AgentsState {
        mode,
        server_listen_addr,
        paired_server_url: if pair_expired {
            None
        } else {
            paired_server_url
        },
        paired_at: if pair_expired { None } else { paired_at },
        pair_expires_at: if pair_expired { None } else { pair_expires_at },
        pair_expired,
        server_pair_code,
        server_pair_code_expires_at,
    })
}

#[derive(Clone)]
struct AppState {
    db: Arc<Db>,
    settings: Arc<Mutex<Settings>>,
    watchers: Arc<Mutex<Option<watcher::WatchersCtrl>>>,
    agents_server: Arc<Mutex<Option<agents::AgentsServerRuntime>>>,
    type_catalog: Arc<Mutex<type_catalog::TypeRegistry>>,
    scan_running: Arc<AtomicBool>,
    scan_cancel: Arc<AtomicBool>,
}

#[tauri::command]
async fn list_alerts(state: tauri::State<'_, AppState>) -> Result<Vec<UiAlert>, String> {
    tracing::debug!("command:list_alerts");
    state.db.list_alerts().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_report(
    state: tauri::State<'_, AppState>,
    file_id: FileId,
    reveal: bool,
) -> Result<Report, String> {
    tracing::debug!(file_id, reveal, "command:get_report");
    let mut report = state
        .db
        .get_latest_report(file_id)
        .await
        .map_err(|e| e.to_string())?;

    if reveal {
        let settings = state.settings.lock().await.clone();
        let custom_detectors = yaml_custom_detectors(state.inner()).await;
        let entity_settings = state
            .db
            .get_entity_settings()
            .await
            .map_err(|e| e.to_string())?;
        // Do not store revealed values in DB; rescan on-demand.
        let scan = scanner::scan_path_with_settings(
            &report.path,
            &settings,
            &custom_detectors,
            &entity_settings,
            scanner::ScanMode::Reveal,
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut revealed = scan.revealed.unwrap_or_default();
        for cat in &mut revealed.by_category {
            for v in &mut cat.values {
                let is_ignored = state
                    .db
                    .is_user_value(cat.category.clone(), &v.value)
                    .await
                    .unwrap_or(false);
                v.is_ignored = is_ignored;
            }
        }
        report.revealed = Some(revealed);
    }

    Ok(report)
}

// Ignore commands for values detected in revealed findings.
#[tauri::command]
async fn ignore_value(
    state: tauri::State<'_, AppState>,
    category: crate::types::PiiCategory,
    value: String,
) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    state
        .db
        .mark_user_value(category, &value, now)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn unignore_value(
    state: tauri::State<'_, AppState>,
    category: crate::types::PiiCategory,
    value: String,
) -> Result<(), String> {
    state
        .db
        .unmark_user_value(category, &value)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn ignore_file(state: tauri::State<'_, AppState>, file_id: FileId) -> Result<(), String> {
    tracing::debug!(file_id, "command:ignore_file");
    state
        .db
        .set_ignored(file_id, true)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn unignore_file(state: tauri::State<'_, AppState>, file_id: FileId) -> Result<(), String> {
    tracing::debug!(file_id, "command:unignore_file");
    state
        .db
        .set_ignored(file_id, false)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_file_to_trash(
    state: tauri::State<'_, AppState>,
    file_id: FileId,
) -> Result<(), String> {
    tracing::debug!(file_id, "command:delete_file_to_trash");
    let path = state
        .db
        .get_file_path(file_id)
        .await
        .map_err(|e| e.to_string())?;

    let path_buf = std::path::PathBuf::from(&path);
    if path_buf.exists() {
        trash::delete(&path_buf).map_err(|e| e.to_string())?;
    }

    state
        .db
        .mark_deleted(file_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn neutralize_file(
    state: tauri::State<'_, AppState>,
    file_id: FileId,
) -> Result<i64, String> {
    tracing::debug!(file_id, "command:neutralize_file");
    let path = state
        .db
        .get_file_path(file_id)
        .await
        .map_err(|e| e.to_string())?;

    let path_buf = std::path::PathBuf::from(&path);
    let ext = path_buf
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if !is_text_neutralizable_ext(&ext) {
        return Err(format!(
            "Neutralize currently supports text-like files only (got .{})",
            ext
        ));
    }

    let mut content = std::fs::read_to_string(&path_buf)
        .map_err(|e| format!("Failed to read file as UTF-8 text: {}", e))?;

    let settings = state.settings.lock().await.clone();
    let custom_detectors = yaml_custom_detectors(state.inner()).await;
    let entity_settings = state
        .db
        .get_entity_settings()
        .await
        .map_err(|e| e.to_string())?;
    let scan = scanner::scan_path_with_settings(
        &path,
        &settings,
        &custom_detectors,
        &entity_settings,
        scanner::ScanMode::Reveal,
    )
    .await
    .map_err(|e| e.to_string())?;

    let mut replacements: Vec<(String, String)> = Vec::new();
    if let Some(revealed) = scan.revealed {
        for by_cat in revealed.by_category {
            for v in by_cat.values {
                let original = v.value.trim().to_string();
                if original.is_empty() {
                    continue;
                }
                let redacted = crate::pii::redact_value(by_cat.category.clone(), &original);
                if redacted != original {
                    replacements.push((original, redacted));
                }
            }
        }
    }

    replacements.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    replacements.dedup_by(|a, b| a.0 == b.0);

    let mut replaced_total: i64 = 0;
    for (from, to) in replacements {
        let count = content.matches(&from).count() as i64;
        if count > 0 {
            replaced_total += count;
            content = content.replace(&from, &to);
        }
    }

    if replaced_total > 0 {
        std::fs::write(&path_buf, content)
            .map_err(|e| format!("Failed to write neutralized content: {}", e))?;
    }

    Ok(replaced_total)
}

#[tauri::command]
async fn open_in_file_manager(path: String) -> Result<(), String> {
    tracing::debug!(%path, "command:open_in_file_manager");
    let path_buf = std::path::PathBuf::from(&path);
    let target = if path_buf.is_file() {
        path_buf
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or(path_buf.clone())
    } else {
        path_buf.clone()
    };

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("xdg-open")
            .arg(&target)
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("xdg-open failed with status: {status}"));
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let status = if path_buf.exists() {
            std::process::Command::new("explorer")
                .arg(&target)
                .status()
                .map_err(|e| e.to_string())?
        } else {
            std::process::Command::new("explorer")
                .arg(&path)
                .status()
                .map_err(|e| e.to_string())?
        };
        if !status.success() {
            return Err(format!("explorer failed with status: {status}"));
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("open")
            .arg(&target)
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("open failed with status: {status}"));
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err("unsupported platform".to_string())
}

#[tauri::command]
async fn get_settings(state: tauri::State<'_, AppState>) -> Result<Settings, String> {
    tracing::debug!("command:get_settings");
    Ok(state.settings.lock().await.clone())
}

#[tauri::command]
async fn set_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    settings: Settings,
) -> Result<(), String> {
    tracing::debug!("command:set_settings");
    {
        let mut guard = state.settings.lock().await;
        *guard = settings.clone();
    }
    state
        .db
        .save_settings(&settings)
        .await
        .map_err(|e| e.to_string())?;

    // Restart watchers to reflect new directories.
    watcher::restart_watchers(&app, state.inner().clone())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn scan_now(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<(), String> {
    tracing::debug!("command:scan_now");
    if state.scan_running.swap(true, Ordering::SeqCst) {
        return Err("scan already running".to_string());
    }
    state.scan_cancel.store(false, Ordering::SeqCst);
    let _ = app.emit("pdd:event", AppEvent::ScanStarted);
    let cancel = state.scan_cancel.clone();
    let out = scheduler::run_initial_scan(&app, state.inner().clone(), Some(cancel)).await;
    state.scan_running.store(false, Ordering::SeqCst);
    let _ = app.emit("pdd:event", AppEvent::ScanFinished);
    out.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn stop_scan(state: tauri::State<'_, AppState>) -> Result<(), String> {
    tracing::debug!("command:stop_scan");
    state.scan_cancel.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
async fn clear_alerts(state: tauri::State<'_, AppState>) -> Result<(), String> {
    tracing::debug!("command:clear_alerts");
    state.db.clear_alerts().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_agents_state(state: tauri::State<'_, AppState>) -> Result<AgentsState, String> {
    load_agents_state(&state.db).await
}

#[tauri::command]
async fn set_agents_mode(
    state: tauri::State<'_, AppState>,
    mode: AgentsMode,
) -> Result<AgentsState, String> {
    let db = &state.db;
    let mode_value = match mode {
        AgentsMode::Agent => "agent",
        AgentsMode::Server => "server",
    };
    db.set_kv("agents_mode", mode_value)
        .await
        .map_err(|e| e.to_string())?;

    match mode {
        AgentsMode::Agent => {
            db.delete_kv("server_pair_code")
                .await
                .map_err(|e| e.to_string())?;
            db.delete_kv("server_pair_code_expires_at")
                .await
                .map_err(|e| e.to_string())?;
        }
        AgentsMode::Server => {
            db.delete_kv("agent_server_url")
                .await
                .map_err(|e| e.to_string())?;
            db.delete_kv("agent_paired_at")
                .await
                .map_err(|e| e.to_string())?;
            db.delete_kv("agent_pair_expires_at")
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    let out = load_agents_state(db).await?;
    agents::sync_server_runtime(state.inner().clone())
        .await
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tauri::command]
async fn create_server_pair_code(
    state: tauri::State<'_, AppState>,
    valid_minutes: Option<i64>,
) -> Result<AgentsState, String> {
    let db = &state.db;
    db.set_kv("agents_mode", "server")
        .await
        .map_err(|e| e.to_string())?;

    let minutes = valid_minutes
        .unwrap_or(DEFAULT_SERVER_CODE_MINUTES)
        .clamp(5, 24 * 60);
    let now = now_ts();
    let expires_at = now + minutes * 60;
    let code = generate_pair_code();

    db.set_kv("server_pair_code", &code)
        .await
        .map_err(|e| e.to_string())?;
    db.set_kv("server_pair_code_expires_at", &expires_at.to_string())
        .await
        .map_err(|e| e.to_string())?;

    let out = load_agents_state(db).await?;
    agents::sync_server_runtime(state.inner().clone())
        .await
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tauri::command]
async fn pair_as_agent(
    state: tauri::State<'_, AppState>,
    server_url: String,
    code: String,
    internet_confirmed: bool,
    valid_days: Option<i64>,
) -> Result<AgentsState, String> {
    let db = &state.db;
    let trimmed_url = server_url.trim();
    if trimmed_url.is_empty() {
        return Err("server URL is required".to_string());
    }
    if code.trim().is_empty() {
        return Err("pairing code is required".to_string());
    }

    let internet_url = is_internet_server_url(trimmed_url)?;
    if internet_url && !internet_confirmed {
        return Err("internet_confirmation_required".to_string());
    }

    let days = valid_days.unwrap_or(DEFAULT_AGENT_PAIR_DAYS).clamp(1, 180);
    let now = now_ts();
    let expires_at = agents::pair_on_remote_server(db, trimmed_url, &code, days).await?;

    db.set_kv("agents_mode", "agent")
        .await
        .map_err(|e| e.to_string())?;
    db.set_kv("agent_server_url", trimmed_url)
        .await
        .map_err(|e| e.to_string())?;
    db.set_kv("agent_paired_at", &now.to_string())
        .await
        .map_err(|e| e.to_string())?;
    db.set_kv("agent_pair_expires_at", &expires_at.to_string())
        .await
        .map_err(|e| e.to_string())?;

    db.delete_kv("server_pair_code")
        .await
        .map_err(|e| e.to_string())?;
    db.delete_kv("server_pair_code_expires_at")
        .await
        .map_err(|e| e.to_string())?;

    let out = load_agents_state(db).await?;
    agents::sync_server_runtime(state.inner().clone())
        .await
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tauri::command]
async fn unpair_agent(state: tauri::State<'_, AppState>) -> Result<AgentsState, String> {
    let db = &state.db;
    db.delete_kv("agent_server_url")
        .await
        .map_err(|e| e.to_string())?;
    db.delete_kv("agent_paired_at")
        .await
        .map_err(|e| e.to_string())?;
    db.delete_kv("agent_pair_expires_at")
        .await
        .map_err(|e| e.to_string())?;
    db.delete_kv("agent_token")
        .await
        .map_err(|e| e.to_string())?;
    db.delete_kv("agent_device_id")
        .await
        .map_err(|e| e.to_string())?;

    let out = load_agents_state(db).await?;
    agents::sync_server_runtime(state.inner().clone())
        .await
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tauri::command]
async fn list_server_devices(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<agents::ServerDeviceView>, String> {
    agents::list_server_devices(&state.db)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_server_device_enabled(
    state: tauri::State<'_, AppState>,
    device_id: String,
    enabled: bool,
) -> Result<(), String> {
    agents::set_server_device_enabled(&state.db, &device_id, enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn unpair_server_device(
    state: tauri::State<'_, AppState>,
    device_id: String,
) -> Result<(), String> {
    agents::unpair_server_device(&state.db, &device_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_server_alerts(
    state: tauri::State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<agents::ServerAlertView>, String> {
    let raw_limit = limit.unwrap_or(50);
    let safe_limit = raw_limit.clamp(1, 500) as usize;
    agents::list_server_alerts(&state.db, safe_limit)
        .await
        .map_err(|e| e.to_string())
}

fn validate_custom_detector_input(input: &NewCustomDetector) -> Result<(), String> {
    if input.name.trim().is_empty() {
        return Err("name is required".to_string());
    }
    let mut at_least_one = false;
    for rx in [
        input.filename_regex.as_ref(),
        input.field_name_regex.as_ref(),
        input.value_regex.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !rx.trim().is_empty() {
            at_least_one = true;
            crate::pii::validate_user_regex(rx)?;
        }
    }
    if !at_least_one {
        return Err("At least one regex is required".to_string());
    }
    Ok(())
}

#[tauri::command]
async fn list_custom_detectors(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<CustomDetector>, String> {
    state
        .db
        .list_custom_detectors()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_custom_detector(
    state: tauri::State<'_, AppState>,
    input: NewCustomDetector,
) -> Result<CustomDetector, String> {
    validate_custom_detector_input(&input)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    state
        .db
        .create_custom_detector(input, now)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_custom_detector(
    state: tauri::State<'_, AppState>,
    id: i64,
    input: NewCustomDetector,
) -> Result<(), String> {
    validate_custom_detector_input(&input)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    state
        .db
        .update_custom_detector(id, input, now)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_custom_detector(state: tauri::State<'_, AppState>, id: i64) -> Result<(), String> {
    state
        .db
        .delete_custom_detector(id)
        .await
        .map_err(|e| e.to_string())
}

fn emit_event<R: Runtime>(app: &tauri::AppHandle<R>, event: &AppEvent) {
    let _ = app.emit("pdd:event", event);
}

pub(crate) async fn yaml_custom_detectors(state: &AppState) -> Vec<CustomDetector> {
    let catalog = state.type_catalog.lock().await;
    let locale = app_locale();
    catalog
        .types
        .values()
        .filter(|def| def.enabled)
        .filter(|def| {
            def.locale_requirement
                .as_deref()
                .map(|required| type_catalog::locale_requirement_matches(required, &locale))
                .unwrap_or(true)
        })
        .filter(|def| {
            def.filename_regex
                .as_ref()
                .is_some_and(|v| !v.trim().is_empty())
                || def
                    .field_name_regex
                    .as_ref()
                    .is_some_and(|v| !v.trim().is_empty())
                || def
                    .value_regex
                    .as_ref()
                    .is_some_and(|v| !v.trim().is_empty())
        })
        .enumerate()
        .map(|(idx, def)| CustomDetector {
            id: idx as i64 + 1,
            name: def.id.clone(),
            risk_level: def.risk_level,
            filename_regex: def.filename_regex.clone(),
            field_name_regex: def.field_name_regex.clone(),
            value_regex: def.value_regex.clone(),
            enabled: true,
            created_at: 0,
            updated_at: 0,
        })
        .collect()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut log_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if let Ok(directive) = "lopdf=error".parse() {
        log_filter = log_filter.add_directive(directive);
    }
    if let Ok(directive) = "pdf_extract=error".parse() {
        log_filter = log_filter.add_directive(directive);
    }

    tracing_subscriber::fmt().with_env_filter(log_filter).init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::block_on(async move {
                tracing::info!("setup:start - beginning application initialization");

                let db = Db::open(&app_handle).await?;
                db.migrate().await?;
                db.cleanup_removed_native_categories().await?;
                db.seed_locale_entities(&app_locale()).await?;

                let settings = db
                    .load_settings()
                    .await?
                    .unwrap_or_else(Settings::default_from_os);
                db.save_settings(&settings).await?;

                let locale = app_locale();
                let custom_types_file =
                    user_custom_types_file(&app_handle).map_err(anyhow::Error::msg)?;
                let host_types_file =
                    user_host_types_file(&app_handle).map_err(anyhow::Error::msg)?;
                let type_catalog = match type_catalog::TypeRegistry::load(
                    &locale,
                    Some(custom_types_file.as_path()),
                    Some(host_types_file.as_path()),
                ) {
                    Ok(reg) => reg,
                    Err(e) => {
                        tracing::warn!("Failed to load type catalog: {}", e);
                        type_catalog::TypeRegistry {
                            types: std::collections::HashMap::new(),
                        }
                    }
                };

                let state = AppState {
                    db: Arc::new(db),
                    settings: Arc::new(Mutex::new(settings.clone())),
                    watchers: Arc::new(Mutex::new(None)),
                    agents_server: Arc::new(Mutex::new(None)),
                    scan_running: Arc::new(AtomicBool::new(false)),
                    scan_cancel: Arc::new(AtomicBool::new(false)),
                    type_catalog: Arc::new(Mutex::new(type_catalog)),
                };

                app_handle.manage(state.clone());

                let main_window = app_handle
                    .get_webview_window("main")
                    .ok_or_else(|| anyhow::anyhow!("main window not found"))?;
                if let Some(icon) = app_handle.default_window_icon().cloned() {
                    let _ = main_window.set_icon(icon);
                } else {
                    let fallback_icon = tauri::include_image!("icons/pdwn-logo.png");
                    let _ = main_window.set_icon(fallback_icon);
                }

                // Try fallback window creation if needed
                /*
                if app_handle.get_webview_window("main").is_none() {
                    tracing::warn!("window:attempting fallback window creation");
                    let _ = tauri::WebviewWindowBuilder::new(&app_handle, "main", Default::default())
                        .title("PDWN - Personal Data Watch & Neutralize")
                        .inner_size(800.0, 600.0)
                        .build();
                }
                */

                tray::setup_tray(&app_handle)?;

                // Start background tasks
                agents::sync_server_runtime(state.clone()).await?;
                watcher::start_watchers(&app_handle, state.clone()).await?;
                scheduler::start_scheduler(&app_handle, state.clone()).await?;
                scheduler::enqueue_initial_scan(&app_handle, state.clone()).await;

                emit_event(&app_handle, &AppEvent::Ready);
                Ok::<(), anyhow::Error>(())
            })?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_alerts,
            get_report,
            ignore_value,
            unignore_value,
            ignore_file,
            unignore_file,
            delete_file_to_trash,
            neutralize_file,
            open_in_file_manager,
            get_settings,
            set_settings,
            scan_now,
            clear_alerts,
            get_agents_state,
            set_agents_mode,
            create_server_pair_code,
            pair_as_agent,
            unpair_agent,
            list_server_devices,
            set_server_device_enabled,
            unpair_server_device,
            list_server_alerts,
            get_server_host_types_yaml,
            set_server_host_types_yaml,
            sync_host_types_from_server,
            list_custom_detectors,
            create_custom_detector,
            update_custom_detector,
            delete_custom_detector,
            stop_scan,
            get_entity_settings,
            update_entity_enabled,
            update_contextual_entity,
            list_type_definitions,
            reload_type_catalog,
            upsert_custom_type_definition,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn get_entity_settings(
    state: tauri::State<'_, AppState>,
) -> std::result::Result<Vec<crate::types::EntitySetting>, String> {
    let result: std::result::Result<Vec<crate::types::EntitySetting>, anyhow::Error> =
        state.db.get_entity_settings().await;
    result.map_err(|e: anyhow::Error| e.to_string())
}

#[tauri::command]
async fn update_entity_enabled(
    state: tauri::State<'_, AppState>,
    entity_type: String,
    enabled: bool,
) -> Result<(), String> {
    state
        .db
        .update_entity_enabled(&entity_type, enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_contextual_entity(
    state: tauri::State<'_, AppState>,
    entity_type: String,
    positive_indicators: Option<String>,
    negative_indicators: Option<String>,
    threshold: Option<f64>,
) -> Result<(), String> {
    state
        .db
        .update_contextual_entity(
            &entity_type,
            positive_indicators.as_deref(),
            negative_indicators.as_deref(),
            threshold,
        )
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_type_definitions(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<TypeDefinition>, String> {
    let catalog = state.type_catalog.lock().await;
    let mut types: Vec<TypeDefinition> = catalog.types.values().cloned().collect();
    types.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(types)
}

#[tauri::command]
async fn reload_type_catalog(app: AppHandle) -> Result<String, String> {
    let locale = app_locale();
    let custom_types_file = user_custom_types_file(&app)?;
    let host_types_file = user_host_types_file(&app)?;
    match type_catalog::TypeRegistry::load(
        &locale,
        Some(custom_types_file.as_path()),
        Some(host_types_file.as_path()),
    ) {
        Ok(new_catalog) => {
            let app_state = app.state::<AppState>();
            let mut catalog = app_state.type_catalog.lock().await;
            *catalog = new_catalog;
            Ok("Type catalog reloaded successfully".to_string())
        }
        Err(e) => Err(format!("Failed to reload type catalog: {}", e)),
    }
}

#[tauri::command]
async fn upsert_custom_type_definition(
    app: AppHandle,
    input: TypeDefinition,
) -> Result<String, String> {
    if input.id.trim().is_empty() {
        return Err("type id is required".to_string());
    }
    let custom_types_file = user_custom_types_file(&app)?;
    type_catalog::upsert_custom_type(custom_types_file.as_path(), input)?;
    reload_type_catalog(app).await
}

#[tauri::command]
async fn get_server_host_types_yaml(state: tauri::State<'_, AppState>) -> Result<String, String> {
    agents::get_server_host_types_yaml(&state.db)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_server_host_types_yaml(
    state: tauri::State<'_, AppState>,
    yaml: String,
) -> Result<i64, String> {
    agents::set_server_host_types_yaml(&state.db, &yaml)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn sync_host_types_from_server(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let mode = state
        .db
        .get_kv("agents_mode")
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| "agent".to_string());
    if mode != "agent" {
        return Err("host types sync is available in agent mode only".to_string());
    }

    let server_url = state
        .db
        .get_kv("agent_server_url")
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "agent is not paired".to_string())?;
    let token = state
        .db
        .get_kv("agent_token")
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "agent token is missing".to_string())?;

    let (version, yaml) = agents::fetch_host_types_policy(&state.db, &server_url, &token).await?;
    let current_version = parse_i64_opt(
        state
            .db
            .get_kv("agent_host_types_version")
            .await
            .map_err(|e| e.to_string())?,
    )
    .unwrap_or_default();
    if version <= current_version {
        return Ok("Host types already up to date".to_string());
    }

    let host_types_file = user_host_types_file(&app)?;
    if let Some(parent) = host_types_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    std::fs::write(&host_types_file, yaml)
        .map_err(|e| format!("Failed to write {}: {}", host_types_file.display(), e))?;

    state
        .db
        .set_kv("agent_host_types_version", &version.to_string())
        .await
        .map_err(|e| e.to_string())?;

    reload_type_catalog(app).await
}

fn user_custom_types_file(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Failed to resolve app config dir: {}", e))?;
    Ok(config_dir.join("types").join("custom.yaml"))
}

fn user_host_types_file(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Failed to resolve app config dir: {}", e))?;
    Ok(config_dir.join("types").join("host.yaml"))
}

fn app_locale() -> String {
    std::env::var("LC_ALL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("LANG").ok())
        .unwrap_or_else(|| "en".to_string())
}
