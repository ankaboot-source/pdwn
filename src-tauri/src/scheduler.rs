use crate::scanner;
use crate::types::AppEvent;
use crate::{settings::Settings, AppState};

use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;
use walkdir::WalkDir;

pub async fn start_scheduler(app: &tauri::AppHandle, state: AppState) -> Result<()> {
    let app_handle = app.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let now = now_ts();
            let due = match state.db.due_reminders(now).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("scheduler due_reminders failed: {e}");
                    continue;
                }
            };

            for r in due {
                tracing::debug!(file_id = r.file_id, threshold = %r.threshold, "scheduler:reminder_due");
                let path = match state.db.get_file_path(r.file_id).await {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = state.db.mark_reminder_sent(r.id, now).await;
                        continue;
                    }
                };

                // Only notify if the file still exists.
                if !std::path::Path::new(&path).exists() {
                    let _ = state.db.mark_deleted(r.file_id).await;
                    let _ = state.db.mark_reminder_sent(r.id, now).await;
                    continue;
                }

                let _ = app_handle.emit(
                    "pdd:event",
                    AppEvent::ReminderDue {
                        file_id: r.file_id,
                        threshold: r.threshold.clone(),
                    },
                );
                tracing::debug!(file_id = r.file_id, "scheduler:reminder_emitted");
                let _ = state.db.mark_reminder_sent(r.id, now).await;
            }
        }
    });
    Ok(())
}

pub async fn enqueue_initial_scan(app: &tauri::AppHandle, state: AppState) {
    let app_handle = app.clone();
    tokio::spawn(async move {
        if let Err(e) = run_initial_scan(&app_handle, state, None).await {
            tracing::warn!("initial scan failed: {e}");
        }
    });
}

pub async fn run_initial_scan(
    app_handle: &tauri::AppHandle,
    state: AppState,
    cancel: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let settings = state.settings.lock().await.clone();
    let mut candidates = Vec::new();
    for dir in settings.watched_dirs() {
        if !dir.exists() {
            continue;
        }

        let mut seen = 0usize;
        for entry in WalkDir::new(&dir).into_iter().flatten() {
            seen += 1;
            if seen > 20_000 {
                break;
            }

            if !entry.file_type().is_file() {
                continue;
            }

            let p = entry.path().to_path_buf();
            if is_hidden_path(&p) {
                continue;
            }
            if settings.is_ignored_extension(&p) {
                continue;
            }

            if let Ok(m) = entry.metadata() {
                let mtime = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                candidates.push((mtime, p));
            }
        }
    }

    let custom_detectors = state
        .db
        .list_enabled_custom_detectors()
        .await
        .unwrap_or_default();

    // Scan recent files first while still covering subdirectories.
    candidates.sort_by_key(|(mtime, _)| -mtime);
    let total = std::cmp::min(candidates.len(), 5_000) as i64;
    let _ = app_handle.emit(
        "pdd:event",
        AppEvent::ScanProgress {
            processed: 0,
            total,
        },
    );
    let entity_settings = state.db.get_entity_settings().await.unwrap_or_default();
    let mut processed: i64 = 0;
    for (_, p) in candidates.into_iter().take(5_000) {
        if cancel
            .as_ref()
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(false)
        {
            break;
        }
        let _ = initial_process_file(
            app_handle,
            &state,
            &settings,
            &custom_detectors,
            &entity_settings,
            &p,
        )
        .await;
        processed += 1;
        if processed % 100 == 0 || processed == total {
            let _ = app_handle.emit("pdd:event", AppEvent::ScanProgress { processed, total });
        }
    }
    Ok(())
}

async fn initial_process_file(
    _app: &tauri::AppHandle,
    state: &AppState,
    settings: &Settings,
    custom_detectors: &[crate::types::CustomDetector],
    entity_settings: &[crate::types::EntitySetting],
    path: &std::path::Path,
) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    if settings.is_ignored_extension(path) {
        return Ok(());
    }

    let meta = std::fs::metadata(path)?;
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

    if state.db.is_file_ignored(file_id).await? {
        return Ok(());
    }

    let scan = match scanner::scan_path_with_settings(
        &path.to_string_lossy(),
        settings,
        custom_detectors,
        entity_settings,
        scanner::ScanMode::Redacted,
    )
    .await
    {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

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
        return Ok(());
    }

    let suggestion = super::watcher::suggestion_for(&scan.risk_level);
    let _ = state
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

    super::watcher::schedule_reminders(&state.db, settings, file_id, now).await?;

    // Do not emit AlertCreated on initial scan to avoid notification spam.
    Ok(())
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn is_hidden_path(path: &std::path::Path) -> bool {
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
