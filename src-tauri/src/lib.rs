#![allow(clippy::needless_return)]

mod contextual;
mod db;
mod pii;
mod scanner;
mod scheduler;
mod secrets;
mod settings;
mod tray;
mod types;
mod watcher;
mod zip_inspect;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tauri::{Emitter, Manager, Runtime};
use tokio::sync::Mutex;

use crate::db::Db;
use crate::settings::Settings;
use crate::types::{AppEvent, CustomDetector, FileId, NewCustomDetector, Report, UiAlert};

#[derive(Clone)]
struct AppState {
    db: Arc<Db>,
    settings: Arc<Mutex<Settings>>,
    watchers: Arc<Mutex<Option<watcher::WatchersCtrl>>>,
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
        let custom_detectors = state
            .db
            .list_enabled_custom_detectors()
            .await
            .map_err(|e| e.to_string())?;
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
                let is_mine = state
                    .db
                    .is_user_value(cat.category.clone(), &v.value)
                    .await
                    .unwrap_or(false);
                v.is_mine = is_mine;
            }
        }
        report.revealed = Some(revealed);
    }

    Ok(report)
}

#[tauri::command]
async fn mark_value_as_mine(
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
async fn unmark_value_as_mine(
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

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
                db.seed_default_custom_detectors(&app_locale(), now_unix()).await?;
                db.seed_locale_entities(&app_locale()).await?;

                let settings = db
                    .load_settings()
                    .await?
                    .unwrap_or_else(Settings::default_from_os);
                db.save_settings(&settings).await?;

                let state = AppState {
                    db: Arc::new(db),
                    settings: Arc::new(Mutex::new(settings.clone())),
                    watchers: Arc::new(Mutex::new(None)),
                    scan_running: Arc::new(AtomicBool::new(false)),
                    scan_cancel: Arc::new(AtomicBool::new(false)),
                };

                app_handle.manage(state.clone());

                let main_window = app_handle
                    .get_webview_window("main")
                    .ok_or_else(|| anyhow::anyhow!("main window not found"))?;
                if let Some(icon) = app_handle.default_window_icon().cloned() {
                    let _ = main_window.set_icon(icon);
                }

                // Try fallback window creation if needed
                /*
                if app_handle.get_webview_window("main").is_none() {
                    tracing::warn!("window:attempting fallback window creation");
                    let _ = tauri::WebviewWindowBuilder::new(&app_handle, "main", Default::default())
                        .title("Personal Data Detector")
                        .inner_size(800.0, 600.0)
                        .build();
                }
                */

                tray::setup_tray(&app_handle)?;

                // Start background tasks
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
            mark_value_as_mine,
            unmark_value_as_mine,
            ignore_file,
            unignore_file,
            delete_file_to_trash,
            open_in_file_manager,
            get_settings,
            set_settings,
            scan_now,
            clear_alerts,
            list_custom_detectors,
            create_custom_detector,
            update_custom_detector,
            delete_custom_detector,
            stop_scan,
            get_entity_settings,
            update_entity_enabled,
            update_contextual_entity,
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn app_locale() -> String {
    std::env::var("LC_ALL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var("LANG").ok())
        .unwrap_or_else(|| "en".to_string())
}
