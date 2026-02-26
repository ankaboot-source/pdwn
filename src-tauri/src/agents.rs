use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::db::Db;
use crate::types::Report;
use crate::{now_ts, parse_i64_opt, AppState};

const SERVER_BIND_ADDR: &str = "0.0.0.0:9487";

pub struct AgentsServerRuntime {
    shutdown_tx: oneshot::Sender<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerDevice {
    device_id: String,
    device_name: String,
    token: String,
    paired_at: i64,
    expires_at: i64,
    enabled: bool,
    last_seen_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerAlertRow {
    device_id: String,
    device_name: String,
    received_at: i64,
    payload: AgentAlertPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairRequest {
    code: String,
    valid_days: Option<i64>,
    device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairResponse {
    device_id: String,
    agent_token: String,
    pair_expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertIngestResponse {
    ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentAlertPayload {
    file_id: i64,
    path: String,
    risk_level: String,
    risk_score: i64,
    types: Vec<String>,
    last_seen_at: i64,
}

#[derive(Clone)]
struct ServerApiState {
    db: Arc<Db>,
}

pub async fn sync_server_runtime(state: AppState) -> Result<()> {
    let mode = state
        .db
        .get_kv("agents_mode")
        .await?
        .unwrap_or_else(|| "agent".to_string());

    if mode != "server" {
        let mut guard = state.agents_server.lock().await;
        if let Some(running) = guard.take() {
            let _ = running.shutdown_tx.send(());
        }
        let _ = state.db.delete_kv("server_listen_addr").await;
        return Ok(());
    }

    let mut guard = state.agents_server.lock().await;
    if guard.is_some() {
        return Ok(());
    }

    let listener = tokio::net::TcpListener::bind(SERVER_BIND_ADDR).await?;
    state
        .db
        .set_kv(
            "server_listen_addr",
            &format!("http://{}", listener.local_addr()?),
        )
        .await?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let app = Router::new()
        .route("/api/agents/pair", post(pair_agent))
        .route("/api/agents/alerts", post(ingest_alert))
        .with_state(ServerApiState {
            db: state.db.clone(),
        });

    tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        if let Err(error) = server.await {
            tracing::warn!("agents server exited: {}", error);
        }
    });

    *guard = Some(AgentsServerRuntime { shutdown_tx });
    Ok(())
}

pub async fn pair_on_remote_server(
    db: &Db,
    server_url: &str,
    code: &str,
    valid_days: i64,
) -> Result<i64, String> {
    let url = format!("{}/api/agents/pair", server_url.trim_end_matches('/'));
    let request = PairRequest {
        code: code.trim().to_string(),
        valid_days: Some(valid_days),
        device_name: Some(default_device_name()),
    };
    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("pairing failed with status {}", response.status()));
    }
    let payload = response
        .json::<PairResponse>()
        .await
        .map_err(|e| e.to_string())?;

    db.set_kv("agent_device_id", &payload.device_id)
        .await
        .map_err(|e| e.to_string())?;
    db.set_kv("agent_token", &payload.agent_token)
        .await
        .map_err(|e| e.to_string())?;
    Ok(payload.pair_expires_at)
}

pub async fn send_alert_if_agent(db: Arc<Db>, file_id: i64) -> Result<()> {
    let mode = db
        .get_kv("agents_mode")
        .await?
        .unwrap_or_else(|| "agent".to_string());
    if mode != "agent" {
        return Ok(());
    }

    let now = now_ts();
    let server_url = match db.get_kv("agent_server_url").await? {
        Some(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };
    let token = match db.get_kv("agent_token").await? {
        Some(v) if !v.trim().is_empty() => v,
        _ => return Ok(()),
    };
    let pair_expires = parse_i64_opt(db.get_kv("agent_pair_expires_at").await?);
    if pair_expires.is_some_and(|exp| exp <= now) {
        return Ok(());
    }

    let report = match db.get_latest_report(file_id).await {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let payload = map_report_to_payload(&report);
    let url = format!("{}/api/agents/alerts", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&payload)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "alert upload failed with status {}",
            response.status()
        ));
    }
    Ok(())
}

fn map_report_to_payload(report: &Report) -> AgentAlertPayload {
    let mut types: Vec<String> = report
        .findings
        .iter()
        .filter(|f| f.count > 0)
        .filter_map(|f| serde_json::to_string(&f.category).ok())
        .map(|v| v.trim_matches('"').to_string())
        .collect();
    for custom in &report.custom_findings {
        if custom.count > 0 {
            types.push(custom.category.clone());
        }
    }

    AgentAlertPayload {
        file_id: report.file_id,
        path: report.path.clone(),
        risk_level: serde_json::to_string(&report.risk_level)
            .unwrap_or_else(|_| "\"low\"".to_string())
            .trim_matches('"')
            .to_string(),
        risk_score: report.risk_score,
        types,
        last_seen_at: report.last_seen_at,
    }
}

async fn pair_agent(
    State(state): State<ServerApiState>,
    Json(request): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    let now = now_ts();
    let expected_code = state
        .db
        .get_kv("server_pair_code")
        .await
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "pairing code not generated".to_string(),
            )
        })?;
    let expires_at = parse_i64_opt(
        state
            .db
            .get_kv("server_pair_code_expires_at")
            .await
            .map_err(internal_error)?,
    )
    .unwrap_or_default();

    if now >= expires_at {
        return Err((StatusCode::BAD_REQUEST, "pairing code expired".to_string()));
    }
    if normalize_code(&expected_code) != normalize_code(&request.code) {
        return Err((StatusCode::UNAUTHORIZED, "invalid pairing code".to_string()));
    }

    let valid_days = request.valid_days.unwrap_or(14).clamp(1, 180);
    let pair_expires_at = now + valid_days * 24 * 60 * 60;
    let device_id = random_hex(8);
    let agent_token = random_hex(32);
    let device = ServerDevice {
        device_id: device_id.clone(),
        device_name: request
            .device_name
            .unwrap_or_else(|| "unknown-device".to_string()),
        token: agent_token.clone(),
        paired_at: now,
        expires_at: pair_expires_at,
        enabled: true,
        last_seen_at: None,
    };

    let mut devices = load_devices(&state.db).await.map_err(internal_error)?;
    devices.push(device);
    save_devices(&state.db, &devices)
        .await
        .map_err(internal_error)?;

    state
        .db
        .delete_kv("server_pair_code")
        .await
        .map_err(internal_error)?;
    state
        .db
        .delete_kv("server_pair_code_expires_at")
        .await
        .map_err(internal_error)?;

    Ok(Json(PairResponse {
        device_id,
        agent_token,
        pair_expires_at,
    }))
}

async fn ingest_alert(
    State(state): State<ServerApiState>,
    headers: HeaderMap,
    Json(payload): Json<AgentAlertPayload>,
) -> Result<Json<AlertIngestResponse>, (StatusCode, String)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let token = auth.trim().strip_prefix("Bearer ").unwrap_or_default();
    if token.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "missing bearer token".to_string()));
    }

    let now = now_ts();
    let mut devices = load_devices(&state.db).await.map_err(internal_error)?;
    let device = devices
        .iter_mut()
        .find(|d| d.token == token)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "unknown token".to_string()))?;
    if !device.enabled {
        return Err((StatusCode::FORBIDDEN, "device disabled".to_string()));
    }
    if device.expires_at <= now {
        return Err((
            StatusCode::UNAUTHORIZED,
            "device pairing expired".to_string(),
        ));
    }
    device.last_seen_at = Some(now);
    let device_id = device.device_id.clone();
    let device_name = device.device_name.clone();
    save_devices(&state.db, &devices)
        .await
        .map_err(internal_error)?;

    let mut alerts = load_server_alerts(&state.db)
        .await
        .map_err(internal_error)?;
    alerts.push(ServerAlertRow {
        device_id,
        device_name,
        received_at: now,
        payload,
    });
    if alerts.len() > 10_000 {
        let keep_from = alerts.len() - 10_000;
        alerts = alerts.split_off(keep_from);
    }
    save_server_alerts(&state.db, &alerts)
        .await
        .map_err(internal_error)?;

    Ok(Json(AlertIngestResponse { ok: true }))
}

async fn load_devices(db: &Db) -> Result<Vec<ServerDevice>> {
    let raw = db.get_kv("server_devices_json").await?;
    match raw {
        Some(v) if !v.trim().is_empty() => Ok(serde_json::from_str(&v).unwrap_or_default()),
        _ => Ok(Vec::new()),
    }
}

async fn save_devices(db: &Db, devices: &[ServerDevice]) -> Result<()> {
    db.set_kv("server_devices_json", &serde_json::to_string(devices)?)
        .await
}

async fn load_server_alerts(db: &Db) -> Result<Vec<ServerAlertRow>> {
    let raw = db.get_kv("server_alerts_json").await?;
    match raw {
        Some(v) if !v.trim().is_empty() => Ok(serde_json::from_str(&v).unwrap_or_default()),
        _ => Ok(Vec::new()),
    }
}

async fn save_server_alerts(db: &Db, alerts: &[ServerAlertRow]) -> Result<()> {
    db.set_kv("server_alerts_json", &serde_json::to_string(alerts)?)
        .await
}

fn normalize_code(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn random_hex(len_bytes: usize) -> String {
    let mut bytes = vec![0u8; len_bytes];
    let _ = getrandom::fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "pdwn-agent".to_string())
}

fn internal_error(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
