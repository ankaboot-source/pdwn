use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub type FileId = i64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PiiCategory {
    Email,
    Phone,
    Iban,
    CreditCard,
    IpAddress,
    Address,
    PostalCode,
    DateOfBirth,
    Cookie,
    UserId,
    Secret,
    FileNameSignal,
    WeakArchiveEncryption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFinding {
    pub category: PiiCategory,
    pub count: usize,
    pub redacted_examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomFinding {
    pub category: String,
    pub count: usize,
    pub redacted_examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDetector {
    pub id: i64,
    pub name: String,
    pub risk_level: RiskLevel,
    pub filename_regex: Option<String>,
    pub field_name_regex: Option<String>,
    pub value_regex: Option<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewCustomDetector {
    pub name: String,
    pub risk_level: RiskLevel,
    pub filename_regex: Option<String>,
    pub field_name_regex: Option<String>,
    pub value_regex: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySetting {
    pub entity_type: String,
    pub entity_category: String,
    pub enabled: bool,
    pub locale_requirement: Option<String>,
    pub positive_indicators: Option<String>,
    pub negative_indicators: Option<String>,
    pub threshold: Option<f64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentsMode {
    Agent,
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentsState {
    pub mode: AgentsMode,
    pub server_listen_addr: Option<String>,
    pub paired_server_url: Option<String>,
    pub agent_enabled: bool,
    pub paired_at: Option<i64>,
    pub pair_expires_at: Option<i64>,
    pub pair_expired: bool,
    pub server_pair_code: Option<String>,
    pub server_pair_code_expires_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevealedFindings {
    pub by_category: Vec<RevealedCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedCategory {
    pub category: PiiCategory,
    pub values: Vec<RevealedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedValue {
    pub value: String,
    pub is_ignored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub risk_level: RiskLevel,
    pub risk_score: i64,
    pub reasons: Vec<Reason>,
    pub findings: Vec<PiiFinding>,
    pub custom_findings: Vec<CustomFinding>,
    pub weak_zip_encryption: bool,
    pub revealed: Option<RevealedFindings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reason {
    pub key: String,
    pub vars: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiAlert {
    pub file_id: FileId,
    pub path: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub size: i64,
    pub mtime: i64,
    pub risk_level: RiskLevel,
    pub risk_score: i64,
    pub pii_summary: Vec<PiiFinding>,
    pub custom_summary: Vec<CustomFinding>,
    pub weak_zip_encryption: bool,
    pub ignored: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub file_id: FileId,
    pub path: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub size: i64,
    pub mtime: i64,
    pub risk_level: RiskLevel,
    pub risk_score: i64,
    pub reasons: Vec<Reason>,
    pub findings: Vec<PiiFinding>,
    pub custom_findings: Vec<CustomFinding>,
    pub weak_zip_encryption: bool,
    pub suggestion: String,
    pub revealed: Option<RevealedFindings>,
}

#[derive(Debug, Clone, Default)]
pub struct IgnoredValuesSnapshot {
    pub salt: String,
    pub set: std::collections::HashSet<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppEvent {
    Ready,
    ScanStarted,
    ScanProgress { processed: i64, total: i64 },
    ScanFinished,
    AlertCreated { file_id: FileId },
    ReminderDue { file_id: FileId, threshold: String },
    ScanError { path: String, error: String },
}
