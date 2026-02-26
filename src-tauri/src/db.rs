use crate::settings::Settings;
use crate::types::{
    CustomDetector, EntitySetting, FileId, IgnoredValuesSnapshot, NewCustomDetector, Reason, Report, RiskLevel, UiAlert,
};

use anyhow::{anyhow, Context, Result};
use libsql::{params, Builder};
use tauri::Manager;
use tokio::sync::Mutex;

use crate::types::PiiCategory;

pub struct Db {
    conn: Mutex<libsql::Connection>,
}

#[derive(Debug, Clone)]
pub struct DueReminder {
    pub id: i64,
    pub file_id: FileId,
    pub threshold: String,
}

impl Db {
    pub async fn open(app: &tauri::AppHandle) -> Result<Self> {
        let data_dir = app
            .path()
            .app_data_dir()
            .context("unable to resolve app_data_dir")?;
        std::fs::create_dir_all(&data_dir).context("unable to create app data dir")?;

        let db_path = data_dir.join("pdd.libsql");
        let db = Builder::new_local(db_path).build().await?;
        let conn = db.connect()?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub async fn migrate(&self) -> Result<()> {
        let sql = r#"
        CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          path TEXT NOT NULL UNIQUE,
          size INTEGER NOT NULL,
          mtime INTEGER NOT NULL,
          first_seen_at INTEGER NOT NULL,
          last_seen_at INTEGER NOT NULL,
          ignored INTEGER NOT NULL DEFAULT 0,
          deleted INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          file_id INTEGER NOT NULL,
          scanned_at INTEGER NOT NULL,
          risk_level TEXT NOT NULL,
          risk_score INTEGER NOT NULL,
          weak_zip_encryption INTEGER NOT NULL DEFAULT 0,
          reasons_json TEXT NOT NULL,
          findings_json TEXT NOT NULL,
          suggestion TEXT NOT NULL,
          FOREIGN KEY(file_id) REFERENCES files(id)
        );
        CREATE INDEX IF NOT EXISTS idx_scans_file_time ON scans(file_id, scanned_at DESC);

        CREATE TABLE IF NOT EXISTS reminders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          file_id INTEGER NOT NULL,
          threshold TEXT NOT NULL,
          due_at INTEGER NOT NULL,
          sent_at INTEGER,
          FOREIGN KEY(file_id) REFERENCES files(id),
          UNIQUE(file_id, threshold)
        );

        CREATE TABLE IF NOT EXISTS kv (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_values (
          category TEXT NOT NULL,
          value_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          PRIMARY KEY(category, value_hash)
        );

        CREATE TABLE IF NOT EXISTS custom_detectors (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          risk_level TEXT NOT NULL DEFAULT 'medium',
          filename_regex TEXT,
          field_name_regex TEXT,
          value_regex TEXT,
          enabled INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entity_settings (
          entity_type TEXT PRIMARY KEY,
          entity_category TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          locale_requirement TEXT,
          positive_indicators TEXT,
          negative_indicators TEXT,
          threshold REAL,
          updated_at INTEGER NOT NULL
        );
        "#;

        let conn = self.conn.lock().await;
        conn.execute_batch(sql).await?;
        // Backward compatibility for existing scans table.
        let _ = conn
            .execute(
                "ALTER TABLE scans ADD COLUMN custom_findings_json TEXT NOT NULL DEFAULT '[]'",
                params![],
            )
            .await;
        let _ = conn
            .execute(
                "ALTER TABLE custom_detectors ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'medium'",
                params![],
            )
            .await;

        // Seed default entity settings if table is empty
        drop(conn); // Release the lock first to avoid deadlock
        self.seed_default_entity_settings().await?;

        Ok(())
    }

    pub async fn seed_default_entity_settings(&self) -> Result<()> {
        let conn = self.conn.lock().await;

        // Check if entity_settings is empty
        let mut rows = conn
            .query("SELECT COUNT(*) FROM entity_settings", params![])
            .await?;

        if let Some(row) = rows.next().await? {
            let count: i64 = row.get(0)?;
            if count > 0 {
                return Ok(());
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        // Global entities (always enabled)
        let global_entities = [
            ("email", "pure"),
            ("phone", "pure"),
            ("iban", "pure"),
            ("credit_card", "pure"),
            ("ip_address", "pure"),
            ("mac_address", "pure"),
            ("bitcoin", "pure"),
            ("ethereum", "pure"),
        ];

        for (entity, category) in global_entities {
            conn.execute(
                "INSERT INTO entity_settings (entity_type, entity_category, enabled, locale_requirement, positive_indicators, negative_indicators, threshold, updated_at) VALUES (?, ?, 1, NULL, NULL, NULL, NULL, ?)",
                params![entity, category, now],
            )
            .await?;
        }

        // Contextual entities with default indicators
        let contextual_entities = [
            (
                "person",
                "contact,responsable,signed by,author,name,owner,represent",
                "the,a,an,product,feature,version,module",
                0.75,
            ),
            (
                "organization",
                "company,inc,ltd,corp,sa,gmbh,organization,firm",
                "product,feature,brand,trademark,copyright",
                0.70,
            ),
            (
                "location",
                "address,city,located,from,in,street,avenue,road",
                "product,feature,timezone,region",
                0.65,
            ),
        ];

        for (entity, positive, negative, threshold) in contextual_entities {
            conn.execute(
                "INSERT INTO entity_settings (entity_type, entity_category, enabled, locale_requirement, positive_indicators, negative_indicators, threshold, updated_at) VALUES (?, ?, 1, NULL, ?, ?, ?, ?)",
                params![entity, "contextual", positive, negative, threshold, now],
            )
            .await?;
        }

        Ok(())
    }

    pub async fn seed_locale_entities(&self, locale: &str) -> Result<()> {
        let conn = self.conn.lock().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        // Locale-specific entities
        let locale_entities: Vec<(&str, &str)> =
            if locale.starts_with("en-US") || locale.starts_with("en-CA") {
                vec![
                    ("us_ssn", "en-US"),
                    ("us_passport", "en-US"),
                    ("us_itin", "en-US"),
                ]
            } else if locale.starts_with("en-GB") {
                vec![("uk_nhs", "en-GB"), ("uk_nino", "en-GB")]
            } else if locale.starts_with("fr") {
                vec![("fr_nir", "fr"), ("fr_tva", "fr")]
            } else if locale.starts_with("es") {
                vec![("es_dni", "es"), ("es_nie", "es"), ("es_cif", "es")]
            } else if locale.starts_with("de") {
                vec![("de_tax_id", "de"), ("de_vat", "de")]
            } else {
                vec![]
            };

        for (entity, req_locale) in locale_entities {
            // Check if entity already exists
            let mut check = conn
                .query(
                    "SELECT 1 FROM entity_settings WHERE entity_type = ?",
                    params![entity],
                )
                .await?;

            if check.next().await?.is_none() {
                conn.execute(
                    "INSERT INTO entity_settings (entity_type, entity_category, enabled, locale_requirement, positive_indicators, negative_indicators, threshold, updated_at) VALUES (?, 'pure', 1, ?, NULL, NULL, NULL, ?)",
                    params![entity, req_locale, now],
                )
                .await?;
            }
        }

        Ok(())
    }

    pub async fn cleanup_removed_native_categories(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT id, findings_json, reasons_json, suggestion FROM scans",
                params![],
            )
            .await?;

        let mut updates: Vec<(i64, String, String, String)> = Vec::new();
        while let Some(row) = rows.next().await? {
            let id: i64 = row.get(0)?;
            let findings_json: String = row.get(1)?;
            let reasons_json: String = row.get(2)?;
            let suggestion: String = row.get(3)?;

            let mut next_findings = findings_json.clone();
            if let Ok(mut arr) = serde_json::from_str::<Vec<serde_json::Value>>(&findings_json) {
                let before = arr.len();
                arr.retain(|item| {
                    let cat = item
                        .get("category")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    !is_removed_native_category(cat)
                });
                if arr.len() != before {
                    next_findings = serde_json::to_string(&arr)?;
                }
            }

            let mut next_reasons = reasons_json.clone();
            if let Ok(mut arr) = serde_json::from_str::<Vec<serde_json::Value>>(&reasons_json) {
                let before = arr.len();
                arr.retain(|item| {
                    let cat = item
                        .get("vars")
                        .and_then(|vars| vars.get("category"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    !is_removed_native_category(cat)
                });
                if arr.len() != before {
                    next_reasons = serde_json::to_string(&arr)?;
                }
            }

            let next_suggestion = suggestion
                .replace(
                    "Suppression recommandee. Si vous devez le conserver, deplacez-le vers un emplacement securise.",
                    "Suppression recommandée. Si vous devez le conserver, déplacez-le vers un emplacement sécurisé.",
                )
                .replace(
                    "A verifier: ce fichier semble contenir des donnees personnelles. Suppression recommandee si inutile.",
                    "A vérifier : ce fichier semble contenir des données personnelles. Suppression recommandée si inutile.",
                )
                .replace(
                    "Vigilance: signal faible de donnees personnelles. Supprimez si ce fichier n'est pas necessaire.",
                    "Vigilance : signal faible de données personnelles. Supprimez si ce fichier n'est pas nécessaire.",
                );

            if next_findings != findings_json
                || next_reasons != reasons_json
                || next_suggestion != suggestion
            {
                updates.push((id, next_findings, next_reasons, next_suggestion));
            }
        }
        drop(rows);

        for (id, findings_json, reasons_json, suggestion) in updates {
            conn.execute(
                "UPDATE scans SET findings_json=?, reasons_json=?, suggestion=? WHERE id=?",
                params![findings_json, reasons_json, suggestion, id],
            )
            .await?;
        }

        Ok(())
    }

    pub async fn save_settings(&self, settings: &Settings) -> Result<()> {
        let value = serde_json::to_string(settings)?;
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO kv(key, value) VALUES('settings', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![value],
        )
        .await?;
        Ok(())
    }

    pub async fn load_settings(&self) -> Result<Option<Settings>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query("SELECT value FROM kv WHERE key='settings'", params![])
            .await?;
        if let Some(row) = rows.next().await? {
            let value: String = row.get(0)?;
            let settings: Settings = serde_json::from_str(&value)?;
            return Ok(Some(settings));
        }
        Ok(None)
    }

    pub async fn upsert_file(&self, path: &str, size: i64, mtime: i64, now: i64) -> Result<FileId> {
        let conn = self.conn.lock().await;

        conn.execute(
            r#"INSERT INTO files(path, size, mtime, first_seen_at, last_seen_at)
               VALUES(?, ?, ?, ?, ?)
               ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime, last_seen_at=excluded.last_seen_at"#,
            params![path, size, mtime, now, now],
        )
        .await?;

        let mut rows = conn
            .query("SELECT id FROM files WHERE path=?", params![path])
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| anyhow!("missing file row after upsert"))?;
        let id: i64 = row.get(0)?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_scan(
        &self,
        file_id: FileId,
        scanned_at: i64,
        risk_level: RiskLevel,
        risk_score: i64,
        weak_zip_encryption: bool,
        reasons: &[Reason],
        findings: &[crate::types::PiiFinding],
        custom_findings: &[crate::types::CustomFinding],
        suggestion: &str,
    ) -> Result<i64> {
        let risk_level_str = serde_json::to_string(&risk_level)?; // JSON string like "low"
        let risk_level_str = risk_level_str.trim_matches('"').to_string();
        let reasons_json = serde_json::to_string(reasons)?;
        let findings_json = serde_json::to_string(findings)?;
        let custom_findings_json = serde_json::to_string(custom_findings)?;

        let conn = self.conn.lock().await;
        conn.execute(
            r#"INSERT INTO scans(file_id, scanned_at, risk_level, risk_score, weak_zip_encryption, reasons_json, findings_json, custom_findings_json, suggestion)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            params![
                file_id,
                scanned_at,
                risk_level_str,
                risk_score,
                if weak_zip_encryption { 1 } else { 0 },
                reasons_json,
                findings_json,
                custom_findings_json,
                suggestion
            ],
        )
        .await?;

        let mut rows = conn.query("SELECT last_insert_rowid()", params![]).await?;
        let row = rows.next().await?.ok_or_else(|| anyhow!("no rowid"))?;
        let id: i64 = row.get(0)?;
        Ok(id)
    }

    pub async fn list_alerts(&self) -> Result<Vec<UiAlert>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                r#"
                SELECT
                  f.id, f.path, f.first_seen_at, f.last_seen_at, f.size, f.mtime, f.ignored, f.deleted,
                  s.risk_level, s.risk_score, s.weak_zip_encryption, s.findings_json, s.custom_findings_json
                FROM files f
                JOIN scans s ON s.id = (
                  SELECT id FROM scans WHERE file_id=f.id ORDER BY scanned_at DESC LIMIT 1
                )
                WHERE f.deleted=0
                ORDER BY s.risk_score DESC, s.scanned_at DESC
                "#,
                params![],
            )
            .await?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            let file_id: i64 = row.get(0)?;
            let path: String = row.get(1)?;
            let first_seen_at: i64 = row.get(2)?;
            let last_seen_at: i64 = row.get(3)?;
            let size: i64 = row.get(4)?;
            let mtime: i64 = row.get(5)?;
            let ignored: i64 = row.get(6)?;
            let deleted: i64 = row.get(7)?;
            let risk_level_str: String = row.get(8)?;
            let risk_score: i64 = row.get(9)?;
            let weak_zip: i64 = row.get(10)?;
            let findings_json: String = row.get(11)?;
            let custom_findings_json: String = row.get(12)?;

            let risk_level: RiskLevel =
                serde_json::from_str(&format!("\"{}\"", risk_level_str)).unwrap_or(RiskLevel::Low);
            let pii_summary: Vec<crate::types::PiiFinding> =
                serde_json::from_str(&findings_json).unwrap_or_default();
            let custom_summary: Vec<crate::types::CustomFinding> =
                serde_json::from_str(&custom_findings_json).unwrap_or_default();

            let has_non_filename_signal = pii_summary
                .iter()
                .any(|f| f.count > 0 && f.category != crate::types::PiiCategory::FileNameSignal);
            let has_filename_signal = pii_summary
                .iter()
                .any(|f| f.category == crate::types::PiiCategory::FileNameSignal && f.count > 0);
            let has_custom_signal = custom_summary.iter().any(|f| f.count > 0);
            let keep = has_non_filename_signal
                || weak_zip != 0
                || has_custom_signal
                || (has_filename_signal && risk_score >= 10);
            if !keep {
                continue;
            }

            out.push(UiAlert {
                file_id,
                path,
                first_seen_at,
                last_seen_at,
                size,
                mtime,
                risk_level,
                risk_score,
                pii_summary,
                custom_summary,
                weak_zip_encryption: weak_zip != 0,
                ignored: ignored != 0,
                deleted: deleted != 0,
            });
        }

        Ok(out)
    }

    pub async fn get_latest_report(&self, file_id: FileId) -> Result<Report> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                r#"
                SELECT
                  f.id, f.path, f.first_seen_at, f.last_seen_at, f.size, f.mtime,
                  s.risk_level, s.risk_score, s.weak_zip_encryption, s.reasons_json, s.findings_json, s.custom_findings_json, s.suggestion
                FROM files f
                JOIN scans s ON s.id = (
                  SELECT id FROM scans WHERE file_id=f.id ORDER BY scanned_at DESC LIMIT 1
                )
                WHERE f.id=?
                "#,
                params![file_id],
            )
            .await?;

        let row = rows
            .next()
            .await?
            .ok_or_else(|| anyhow!("file not found"))?;

        let file_id: i64 = row.get(0)?;
        let path: String = row.get(1)?;
        let first_seen_at: i64 = row.get(2)?;
        let last_seen_at: i64 = row.get(3)?;
        let size: i64 = row.get(4)?;
        let mtime: i64 = row.get(5)?;
        let risk_level_str: String = row.get(6)?;
        let risk_score: i64 = row.get(7)?;
        let weak_zip: i64 = row.get(8)?;
        let reasons_json: String = row.get(9)?;
        let findings_json: String = row.get(10)?;
        let custom_findings_json: String = row.get(11)?;
        let suggestion: String = row.get(12)?;

        let risk_level: RiskLevel =
            serde_json::from_str(&format!("\"{}\"", risk_level_str)).unwrap_or(RiskLevel::Low);
        let reasons: Vec<Reason> = serde_json::from_str(&reasons_json).unwrap_or_default();
        let findings: Vec<crate::types::PiiFinding> =
            serde_json::from_str(&findings_json).unwrap_or_default();
        let custom_findings: Vec<crate::types::CustomFinding> =
            serde_json::from_str(&custom_findings_json).unwrap_or_default();

        Ok(Report {
            file_id,
            path,
            first_seen_at,
            last_seen_at,
            size,
            mtime,
            risk_level,
            risk_score,
            reasons,
            findings,
            custom_findings,
            weak_zip_encryption: weak_zip != 0,
            suggestion,
            revealed: None,
        })
    }

    pub async fn list_custom_detectors(&self) -> Result<Vec<CustomDetector>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                r#"SELECT id, name, risk_level, filename_regex, field_name_regex, value_regex, enabled, created_at, updated_at
                   FROM custom_detectors
                   ORDER BY updated_at DESC, id DESC"#,
                params![],
            )
            .await?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(CustomDetector {
                id: row.get(0)?,
                name: row.get(1)?,
                risk_level: parse_risk_level(&row.get::<String>(2)?),
                filename_regex: row.get::<Option<String>>(3)?,
                field_name_regex: row.get::<Option<String>>(4)?,
                value_regex: row.get::<Option<String>>(5)?,
                enabled: row.get::<i64>(6)? != 0,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            });
        }
        Ok(out)
    }

    #[allow(dead_code)]
    pub async fn list_enabled_custom_detectors(&self) -> Result<Vec<CustomDetector>> {
        let all = self.list_custom_detectors().await?;
        Ok(all.into_iter().filter(|d| d.enabled).collect())
    }

    pub async fn create_custom_detector(
        &self,
        input: NewCustomDetector,
        now: i64,
    ) -> Result<CustomDetector> {
        let risk_level = serde_json::to_string(&input.risk_level)?
            .trim_matches('"')
            .to_string();
        let conn = self.conn.lock().await;
        conn.execute(
            r#"INSERT INTO custom_detectors(name, risk_level, filename_regex, field_name_regex, value_regex, enabled, created_at, updated_at)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)"#,
            params![
                input.name,
                risk_level,
                input.filename_regex,
                input.field_name_regex,
                input.value_regex,
                if input.enabled { 1 } else { 0 },
                now,
                now
            ],
        )
        .await?;
        let mut rows = conn.query("SELECT last_insert_rowid()", params![]).await?;
        let row = rows.next().await?.ok_or_else(|| anyhow!("no rowid"))?;
        let id: i64 = row.get(0)?;
        drop(rows);
        let mut one = conn
            .query(
                r#"SELECT id, name, risk_level, filename_regex, field_name_regex, value_regex, enabled, created_at, updated_at
                   FROM custom_detectors WHERE id=?"#,
                params![id],
            )
            .await?;
        let r = one
            .next()
            .await?
            .ok_or_else(|| anyhow!("detector missing"))?;
        Ok(CustomDetector {
            id: r.get(0)?,
            name: r.get(1)?,
            risk_level: parse_risk_level(&r.get::<String>(2)?),
            filename_regex: r.get::<Option<String>>(3)?,
            field_name_regex: r.get::<Option<String>>(4)?,
            value_regex: r.get::<Option<String>>(5)?,
            enabled: r.get::<i64>(6)? != 0,
            created_at: r.get(7)?,
            updated_at: r.get(8)?,
        })
    }

    pub async fn update_custom_detector(
        &self,
        id: i64,
        input: NewCustomDetector,
        now: i64,
    ) -> Result<()> {
        let risk_level = serde_json::to_string(&input.risk_level)?
            .trim_matches('"')
            .to_string();
        let conn = self.conn.lock().await;
        conn.execute(
            r#"UPDATE custom_detectors
               SET name=?, risk_level=?, filename_regex=?, field_name_regex=?, value_regex=?, enabled=?, updated_at=?
               WHERE id=?"#,
            params![
                input.name,
                risk_level,
                input.filename_regex,
                input.field_name_regex,
                input.value_regex,
                if input.enabled { 1 } else { 0 },
                now,
                id
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn delete_custom_detector(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM custom_detectors WHERE id=?", params![id])
            .await?;
        Ok(())
    }

    pub async fn get_file_path(&self, file_id: FileId) -> Result<String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query("SELECT path FROM files WHERE id=?", params![file_id])
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| anyhow!("file not found"))?;
        Ok(row.get::<String>(0)?)
    }

    pub async fn set_ignored(&self, file_id: FileId, ignored: bool) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE files SET ignored=? WHERE id=?",
            params![if ignored { 1 } else { 0 }, file_id],
        )
        .await?;
        Ok(())
    }

    pub async fn is_file_ignored(&self, file_id: FileId) -> Result<bool> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query("SELECT ignored FROM files WHERE id=?", params![file_id])
            .await?;
        if let Some(row) = rows.next().await? {
            let ignored: i64 = row.get(0)?;
            return Ok(ignored != 0);
        }
        Ok(false)
    }

    pub async fn mark_deleted(&self, file_id: FileId) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("UPDATE files SET deleted=1 WHERE id=?", params![file_id])
            .await?;
        Ok(())
    }

    pub async fn ensure_reminder(
        &self,
        file_id: FileId,
        threshold: &str,
        due_at: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            r#"INSERT INTO reminders(file_id, threshold, due_at) VALUES(?, ?, ?)
               ON CONFLICT(file_id, threshold) DO NOTHING"#,
            params![file_id, threshold, due_at],
        )
        .await?;
        Ok(())
    }

    pub async fn due_reminders(&self, now: i64) -> Result<Vec<DueReminder>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                r#"
                SELECT r.id, r.file_id, r.threshold
                FROM reminders r
                JOIN files f ON f.id = r.file_id
                WHERE r.due_at <= ? AND r.sent_at IS NULL AND f.ignored=0 AND f.deleted=0
                "#,
                params![now],
            )
            .await?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(DueReminder {
                id: row.get(0)?,
                file_id: row.get(1)?,
                threshold: row.get(2)?,
            });
        }
        Ok(out)
    }

    pub async fn mark_reminder_sent(&self, reminder_id: i64, sent_at: i64) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE reminders SET sent_at=? WHERE id=?",
            params![sent_at, reminder_id],
        )
        .await?;
        Ok(())
    }

    pub async fn get_or_create_user_salt(&self) -> Result<String> {
        // Not a secret store, but avoids plain-text user identifiers.
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query("SELECT value FROM kv WHERE key='user_salt'", params![])
            .await?;
        if let Some(row) = rows.next().await? {
            let v: String = row.get(0)?;
            if !v.is_empty() {
                return Ok(v);
            }
        }

        let salt = random_hex(32);
        conn.execute(
            "INSERT INTO kv(key, value) VALUES('user_salt', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![salt.clone()],
        )
        .await?;
        Ok(salt)
    }

    pub async fn mark_user_value(
        &self,
        category: PiiCategory,
        raw_value: &str,
        now: i64,
    ) -> Result<()> {
        let salt = self.get_or_create_user_salt().await?;
        let hash = crate::user_values::UserHash::hash_value(&salt, category.clone(), raw_value);
        let cat = serde_json::to_string(&category)?
            .trim_matches('"')
            .to_string();
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO user_values(category, value_hash, created_at) VALUES(?, ?, ?)",
            params![cat, hash, now],
        )
        .await?;
        Ok(())
    }

    pub async fn unmark_user_value(&self, category: PiiCategory, raw_value: &str) -> Result<()> {
        let salt = self.get_or_create_user_salt().await?;
        let hash = crate::user_values::UserHash::hash_value(&salt, category.clone(), raw_value);
        let cat = serde_json::to_string(&category)?
            .trim_matches('"')
            .to_string();
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM user_values WHERE category=? AND value_hash=?",
            params![cat, hash],
        )
        .await?;
        Ok(())
    }

    pub async fn is_user_value(&self, category: PiiCategory, raw_value: &str) -> Result<bool> {
        let salt = self.get_or_create_user_salt().await?;
        let hash = crate::user_values::UserHash::hash_value(&salt, category.clone(), raw_value);
        let cat = serde_json::to_string(&category)?
            .trim_matches('"')
            .to_string();
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT 1 FROM user_values WHERE category=? AND value_hash=? LIMIT 1",
                params![cat, hash],
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    pub async fn clear_alerts(&self) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch(
            r#"
            DELETE FROM reminders;
            DELETE FROM scans;
            DELETE FROM files;
            "#,
        )
        .await?;
        Ok(())
    }

    pub async fn get_ignored_values_snapshot(&self) -> Result<IgnoredValuesSnapshot> {
        let salt = self.get_or_create_user_salt().await?;
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query("SELECT category, value_hash FROM user_values", params![])
            .await?;

        let mut set = std::collections::HashSet::new();
        while let Some(row) = rows.next().await? {
            let category: String = row.get(0)?;
            let hash: String = row.get(1)?;
            set.insert((category, hash));
        }

        Ok(IgnoredValuesSnapshot { salt, set })
    }

    pub async fn get_entity_settings(&self) -> Result<Vec<EntitySetting>> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT entity_type, entity_category, enabled, locale_requirement, positive_indicators, negative_indicators, threshold FROM entity_settings ORDER BY entity_type",
                params![],
            )
            .await?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().await? {
            out.push(EntitySetting {
                entity_type: row.get(0)?,
                entity_category: row.get(1)?,
                enabled: row.get::<i64>(2)? != 0,
                locale_requirement: row.get::<Option<String>>(3)?,
                positive_indicators: row.get::<Option<String>>(3)?,
                negative_indicators: row.get::<Option<String>>(5)?,
                threshold: row.get::<Option<f64>>(6)?,
            });
        }
        Ok(out)
    }

    pub async fn update_entity_enabled(&self, entity_type: &str, enabled: bool) -> Result<()> {
        let conn = self.conn.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        conn.execute(
            "UPDATE entity_settings SET enabled = ?, updated_at = ? WHERE entity_type = ?",
            params![if enabled { 1 } else { 0 }, now, entity_type],
        )
        .await?;
        Ok(())
    }

    pub async fn update_contextual_entity(
        &self,
        entity_type: &str,
        positive_indicators: Option<&str>,
        negative_indicators: Option<&str>,
        threshold: Option<f64>,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        conn.execute(
            "UPDATE entity_settings SET positive_indicators = ?, negative_indicators = ?, threshold = ?, updated_at = ? WHERE entity_type = ?",
            params![positive_indicators, negative_indicators, threshold, now, entity_type],
        )
        .await?;
        Ok(())
    }
}

fn random_hex(len_bytes: usize) -> String {
    let mut bytes = vec![0u8; len_bytes];
    let _ = getrandom::fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_risk_level(value: &str) -> RiskLevel {
    serde_json::from_str(&format!("\"{}\"", value)).unwrap_or(RiskLevel::Medium)
}

fn is_removed_native_category(category: &str) -> bool {
    matches!(category, "loyalty_id" | "digital_account" | "rcu_id")
}
