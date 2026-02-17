use crate::db::Db;
use crate::scanner;
use crate::settings::Settings;
use crate::types::{AppEvent, RiskLevel};

use anyhow::{Context, Result};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tauri::Emitter;
use tokio::sync::{mpsc, Mutex};

use crate::AppState;

#[derive(Clone)]
pub struct WatchersCtrl {
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl WatchersCtrl {
    pub fn shutdown(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
struct PendingFile {
    last_size: u64,
    last_mtime: i64,
    last_change: Instant,
    first_seen: Instant,
}

pub async fn start_watchers(app: &tauri::AppHandle, state: AppState) -> Result<()> {
    let settings = state.settings.lock().await.clone();
    let watched_dirs = settings.watched_dirs();

    tracing::info!("watching directories: {:?}", watched_dirs);

    for dir in &watched_dirs {
        if !dir.exists() {
            tracing::warn!("watcher:directory does not exist: {:?}", dir);
        } else if !dir.is_dir() {
            tracing::warn!("watcher:directory is not a directory: {:?}", dir);
        }
    }

    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctrl = WatchersCtrl {
        shutdown: shutdown.clone(),
    };
    {
        let mut guard = state.watchers.lock().await;
        *guard = Some(ctrl.clone());
    }

    let app_handle = app.clone();
    let state_for_tasks = state.clone();

    let (path_tx, mut path_rx) = mpsc::unbounded_channel::<PathBuf>();

    // Watcher task (blocking thread) to keep watcher alive.
    let shutdown_watcher = shutdown.clone();
    let watched_dirs_clone = watched_dirs.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    for p in event.paths {
                        let _ = path_tx.send(p);
                    }
                }
            })
            .context("create notify watcher")?;

        for dir in watched_dirs_clone {
            let _ = watcher.watch(&dir, RecursiveMode::Recursive);
        }

        while !shutdown_watcher.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    });

    // Pending queue + stabilization worker.
    let pending: ArcPending = std::sync::Arc::new(Mutex::new(HashMap::new()));
    let pending_ingest = pending.clone();
    let settings_ingest = settings.clone();
    tokio::spawn(async move {
        while let Some(p) = path_rx.recv().await {
            if is_hidden_path(&p) || settings_ingest.is_ignored_extension(&p) || !p.is_file() {
                continue;
            }

            let meta = match std::fs::metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let size = meta.len();
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let mut guard = pending_ingest.lock().await;
            guard
                .entry(p)
                .and_modify(|e| {
                    e.last_size = size;
                    e.last_mtime = mtime;
                    e.last_change = Instant::now();
                })
                .or_insert(PendingFile {
                    last_size: size,
                    last_mtime: mtime,
                    last_change: Instant::now(),
                    first_seen: Instant::now(),
                });
        }
    });

    let worker_state = state_for_tasks.clone();
    let worker_app = app_handle.clone();
    let worker_pending = pending.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            ticker.tick().await;

            {
                let mut ready = Vec::new();
                {
                    let mut guard = worker_pending.lock().await;
                    let now = Instant::now();
                    guard.retain(|path, pending| {
                        let stable_for = now.duration_since(pending.last_change);
                        let alive_for = now.duration_since(pending.first_seen);
                        if stable_for >= Duration::from_secs(2)
                            || alive_for >= Duration::from_secs(20)
                        {
                            ready.push(path.clone());
                            return false;
                        }
                        true
                    });
                }
                for path in ready {
                    let _ = process_file(&worker_app, &worker_state, &path).await;
                }
            }
        }
    });

    Ok(())
}

pub async fn restart_watchers(app: &tauri::AppHandle, state: AppState) -> Result<()> {
    if let Some(ctrl) = state.watchers.lock().await.take() {
        ctrl.shutdown();
    }
    start_watchers(app, state).await
}

type ArcPending = std::sync::Arc<Mutex<HashMap<PathBuf, PendingFile>>>;

async fn process_file(app: &tauri::AppHandle, state: &AppState, path: &Path) -> Result<()> {
    tracing::debug!(path = %path.display(), "watcher:process_file:start");
    if is_hidden_path(path) {
        return Ok(());
    }
    let settings = state.settings.lock().await.clone();
    if settings.is_ignored_extension(path) {
        return Ok(());
    }

    if !is_in_watched_dirs(path, &settings) {
        return Ok(());
    }

    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(());
    }
    let size = meta.len() as i64;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let now = now_ts();

    let file_id = state
        .db
        .upsert_file(&path.to_string_lossy(), size, mtime, now)
        .await?;

    tracing::debug!(file_id, size, mtime, "watcher:upserted_file");

    if state.db.is_file_ignored(file_id).await? {
        return Ok(());
    }

    let custom_detectors = state
        .db
        .list_enabled_custom_detectors()
        .await
        .unwrap_or_default();
    let entity_settings = state.db.get_entity_settings().await.unwrap_or_default();

    let scan = match scanner::scan_path_with_settings(
        &path.to_string_lossy(),
        &settings,
        &custom_detectors,
        &entity_settings,
        scanner::ScanMode::Redacted,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            let _ = app.emit(
                "pdd:event",
                AppEvent::ScanError {
                    path: path.to_string_lossy().to_string(),
                    error: e.to_string(),
                },
            );
            return Ok(());
        }
    };

    // Only create a scan row when we have any signal.
    let has_non_filename_signal = scan
        .findings
        .iter()
        .any(|f| f.count > 0 && f.category != crate::types::PiiCategory::FileNameSignal);
    let has_filename_signal = scan
        .findings
        .iter()
        .any(|f| f.category == crate::types::PiiCategory::FileNameSignal && f.count > 0);
    let has_any_signal = has_non_filename_signal
        || scan.weak_zip_encryption
        || scan.custom_findings.iter().any(|f| f.count > 0)
        || (has_filename_signal && scan.risk_score >= 10);

    if !has_any_signal {
        tracing::debug!(file_id, "watcher:no_signal_skip");
        return Ok(());
    }

    let suggestion = suggestion_for(&scan.risk_level);
    let _scan_id = state
        .db
        .insert_scan(
            file_id,
            now,
            scan.risk_level,
            scan.risk_score,
            scan.weak_zip_encryption,
            &scan.reasons,
            &scan.findings,
            &scan.custom_findings,
            &suggestion,
        )
        .await?;

    tracing::debug!(file_id, risk_score = scan.risk_score, ?scan.risk_level, "watcher:scan_saved");

    // Schedule reminders.
    schedule_reminders(&state.db, &settings, file_id, now).await?;

    // Emit alert event (frontend will show notification).
    let _ = app.emit("pdd:event", AppEvent::AlertCreated { file_id });
    tracing::debug!(file_id, "watcher:alert_emitted");
    Ok(())
}

fn is_in_watched_dirs(path: &Path, settings: &Settings) -> bool {
    for dir in settings.watched_dirs() {
        if path.starts_with(&dir) {
            return true;
        }
    }
    false
}

pub(crate) async fn schedule_reminders(
    db: &Db,
    settings: &Settings,
    file_id: i64,
    now: i64,
) -> Result<()> {
    let due_24h = now + settings.reminders_hours * 3600;
    let due_7d = now + settings.reminders_days_7 * 86400;
    let due_30d = now + settings.reminders_days_30 * 86400;
    db.ensure_reminder(file_id, "24h", due_24h).await?;
    db.ensure_reminder(file_id, "7j", due_7d).await?;
    db.ensure_reminder(file_id, "30j", due_30d).await?;
    Ok(())
}

pub(crate) fn suggestion_for(level: &RiskLevel) -> String {
    match level {
        RiskLevel::Critical | RiskLevel::High => {
            "Suppression recommandée. Si vous devez le conserver, déplacez-le vers un emplacement sécurisé.".to_string()
        }
        RiskLevel::Medium => {
            "A vérifier : ce fichier semble contenir des données personnelles. Suppression recommandée si inutile.".to_string()
        }
        RiskLevel::Low => {
            "Vigilance : signal faible de données personnelles. Supprimez si ce fichier n'est pas nécessaire.".to_string()
        }
    }
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn is_hidden_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::path::Component;
        for c in path.components() {
            if let Component::Normal(name) = c {
                if let Some(s) = name.to_str() {
                    if s.starts_with('.') {
                        return true;
                    }
                }
            }
        }
    }
    false
}
