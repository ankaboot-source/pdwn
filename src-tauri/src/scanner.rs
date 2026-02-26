use crate::contextual::ContextualAnalyzer;
use crate::pii;
use crate::settings::Settings;
use crate::types::{CustomDetector, EntitySetting, PiiCategory, Reason, RiskLevel, ScanSummary};
use crate::zip_inspect::{inspect_zip_encryption, ZipEncryption};

use anyhow::{Context, Result};
use calamine::{Reader, Xls, Xlsx};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek};
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Redacted,
    Reveal,
}

pub async fn scan_path_with_settings(
    path: &str,
    settings: &Settings,
    custom_detectors: &[crate::types::CustomDetector],
    entity_settings: &[EntitySetting],
    mode: ScanMode,
) -> Result<ScanSummary> {
    scan_path_with_ignore_snapshot(
        path,
        settings,
        custom_detectors,
        entity_settings,
        mode,
        None,
    )
    .await
}

pub async fn scan_path_with_ignore_snapshot(
    path: &str,
    settings: &Settings,
    custom_detectors: &[crate::types::CustomDetector],
    entity_settings: &[EntitySetting],
    mode: ScanMode,
    ignored: Option<&crate::types::IgnoredValuesSnapshot>,
) -> Result<ScanSummary> {
    // Run scan in blocking thread; parsers are synchronous.
    let path = path.to_string();
    let settings = settings.clone();
    let custom_detectors = custom_detectors.to_vec();
    let entity_settings = entity_settings.to_vec();
    let ignored_snapshot = ignored.cloned();
    tokio::task::spawn_blocking(move || {
        scan_path_blocking_with_ignore(
            &path,
            &settings,
            &custom_detectors,
            &entity_settings,
            mode,
            ignored_snapshot,
        )
    })
    .await?
}

fn scan_path_blocking_with_ignore(
    path: &str,
    settings: &Settings,
    custom_detectors: &[crate::types::CustomDetector],
    entity_settings: &[EntitySetting],
    mode: ScanMode,
    ignored: Option<crate::types::IgnoredValuesSnapshot>,
) -> Result<ScanSummary> {
    // Build contextual analyzers from enabled entity settings
    let contextual_analyzers: Vec<ContextualAnalyzer> = entity_settings
        .iter()
        .filter(|e| e.enabled && e.entity_category == "contextual")
        .map(|e| ContextualAnalyzer::new(e.clone()))
        .collect();
    let p = Path::new(path);
    let file_name = p.file_name().and_then(|s| s.to_str()).unwrap_or(path);
    let compiled_custom = pii::compile_custom_detectors(custom_detectors).unwrap_or_default();

    let file_name_matches = pii::detect_in_filename(path);

    let mut matches: BTreeMap<PiiCategory, Vec<String>> = BTreeMap::new();
    let mut custom_matches: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut reasons: Vec<Reason> = Vec::new();
    let mut weak_zip_encryption = false;

    for (cat, values) in &file_name_matches.by_category {
        if let Some(snapshot) = &ignored {
            let filtered_values: Vec<String> = values
                .iter()
                .filter(|v| !is_value_ignored(snapshot, cat, v))
                .cloned()
                .collect();
            if !filtered_values.is_empty() {
                matches
                    .entry(cat.clone())
                    .or_default()
                    .extend(filtered_values);
            }
        } else {
            matches
                .entry(cat.clone())
                .or_default()
                .extend(values.clone());
        }
    }
    reasons.extend(file_name_matches.filename_reasons);
    merge_custom_matches(
        &mut custom_matches,
        &pii::detect_custom("", file_name, &compiled_custom),
    );

    let ext = p
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let mut filename_bonus = file_name_matches.filename_score_bonus;

    if ext == "pst" {
        filename_bonus += 8;
        reasons.push(Reason {
            key: "reason.filenameKeyword".to_string(),
            vars: json!({ "keyword": "pst" }),
        });
        matches
            .entry(PiiCategory::FileNameSignal)
            .or_default()
            .push("pst".to_string());
    }

    if !p.is_file() {
        let score = 0;
        return Ok(ScanSummary {
            risk_level: RiskLevel::Low,
            risk_score: score,
            reasons: vec![Reason {
                key: "reason.notAFile".to_string(),
                vars: json!({}),
            }],
            findings: vec![],
            custom_findings: vec![],
            weak_zip_encryption: false,
            revealed: None,
        });
    }

    let metadata = std::fs::metadata(p).context("metadata")?;
    let size = metadata.len();
    if size > settings.max_file_bytes {
        reasons.push(Reason {
            key: "reason.fileTooLarge".to_string(),
            vars: json!({ "bytes": size }),
        });
        let (score, mut score_reasons) = pii::score_from_matches(&matches, filename_bonus, false);
        reasons.append(&mut score_reasons);
        let custom_findings = summarize_custom_matches(&custom_matches);
        let (custom_score, mut custom_reasons) =
            custom_score_and_reasons(&custom_findings, custom_detectors);
        reasons.append(&mut custom_reasons);
        let score = score + custom_score;
        let findings = pii::summarize_matches(&matches, true);
        let (max_level, high_type_count) =
            overall_risk_evidence(&findings, &custom_findings, custom_detectors, false);
        let risk_level = pii::risk_level_from_evidence(score, max_level, high_type_count);
        return Ok(ScanSummary {
            risk_level,
            risk_score: score,
            reasons,
            findings,
            custom_findings,
            weak_zip_encryption: false,
            revealed: None,
        });
    }

    match ext.as_str() {
        "pdf" => {
            if let Ok(text) = scan_pdf_text(p, settings.max_text_bytes) {
                let text_matches = pii::detect_in_text(&text, true);
                merge_matches(&mut matches, &text_matches, &ignored);
                merge_custom_matches(
                    &mut custom_matches,
                    &pii::detect_custom(&text, file_name, &compiled_custom),
                );
                detect_contextual_entities(&text, &contextual_analyzers, &mut custom_matches);
            }
        }
        "xlsx" | "xls" => {
            scan_excel(
                p,
                settings,
                &mut matches,
                &mut custom_matches,
                &compiled_custom,
                file_name,
            )?;
        }
        "docx" => {
            if let Ok(text) = scan_docx_text(p, settings.max_text_bytes) {
                let text_matches = pii::detect_in_text(&text, true);
                merge_matches(&mut matches, &text_matches, &ignored);
                merge_custom_matches(
                    &mut custom_matches,
                    &pii::detect_custom(&text, file_name, &compiled_custom),
                );
                detect_contextual_entities(&text, &contextual_analyzers, &mut custom_matches);
            }
        }
        "zip" => {
            let enc = inspect_zip_encryption(p).unwrap_or(ZipEncryption::Unknown);
            if enc == ZipEncryption::ZipCrypto {
                weak_zip_encryption = true;
                matches
                    .entry(PiiCategory::WeakArchiveEncryption)
                    .or_default()
                    .push("ZipCrypto".to_string());
            }
            scan_zip_path(
                p,
                settings,
                &mut matches,
                &mut custom_matches,
                &compiled_custom,
                file_name,
                0,
            )?;
        }
        _ => {
            if is_image_ext(&ext) {
                if let Ok(text) = scan_image_with_optional_ocr(p, settings.max_text_bytes) {
                    let text_matches = pii::detect_in_text(&text, true);
                    merge_matches(&mut matches, &text_matches, &ignored);
                    merge_custom_matches(
                        &mut custom_matches,
                        &pii::detect_custom(&text, file_name, &compiled_custom),
                    );
                    detect_contextual_entities(&text, &contextual_analyzers, &mut custom_matches);
                }
            }
            // Treat as text-like when extension matches common formats.
            else if is_text_like_ext(&ext) {
                if let Ok(text) = read_text_prefix(p, settings.max_text_bytes) {
                    let enable_secrets = !is_technical_file_ext(&ext);
                    let text_matches = pii::detect_in_text(&text, enable_secrets);
                    merge_matches(&mut matches, &text_matches, &ignored);
                    merge_custom_matches(
                        &mut custom_matches,
                        &pii::detect_custom(&text, file_name, &compiled_custom),
                    );
                    detect_contextual_entities(&text, &contextual_analyzers, &mut custom_matches);
                }
            } else {
                // Best-effort: read small chunk and detect if it is text.
                if let Ok(text) = read_text_prefix_if_probably_text(p, settings.max_text_bytes) {
                    let text_matches = pii::detect_in_text(&text, true);
                    merge_matches(&mut matches, &text_matches, &ignored);
                    merge_custom_matches(
                        &mut custom_matches,
                        &pii::detect_custom(&text, file_name, &compiled_custom),
                    );
                    detect_contextual_entities(&text, &contextual_analyzers, &mut custom_matches);
                }
            }
        }
    }

    let (builtin_score, mut score_reasons) =
        pii::score_from_matches(&matches, filename_bonus, weak_zip_encryption);
    reasons.append(&mut score_reasons);
    let custom_findings = summarize_custom_matches(&custom_matches);
    let (custom_score, mut custom_reasons) =
        custom_score_and_reasons(&custom_findings, custom_detectors);
    reasons.append(&mut custom_reasons);
    let score = builtin_score + custom_score;
    let findings = pii::summarize_matches(&matches, true);
    let (max_level, high_type_count) = overall_risk_evidence(
        &findings,
        &custom_findings,
        custom_detectors,
        weak_zip_encryption,
    );
    let risk_level = pii::risk_level_from_evidence(score, max_level, high_type_count);

    let revealed = if mode == ScanMode::Reveal {
        Some(pii::reveal_matches(&matches))
    } else {
        None
    };

    Ok(ScanSummary {
        risk_level,
        risk_score: score,
        reasons,
        findings,
        custom_findings,
        weak_zip_encryption,
        revealed,
    })
}

fn merge_matches(
    dst: &mut BTreeMap<PiiCategory, Vec<String>>,
    src: &BTreeMap<PiiCategory, Vec<String>>,
    ignored: &Option<crate::types::IgnoredValuesSnapshot>,
) {
    for (cat, values) in src {
        let filtered_values: Vec<String> = if let Some(snapshot) = ignored {
            values
                .iter()
                .filter(|v| !is_value_ignored(snapshot, cat, v))
                .cloned()
                .collect()
        } else {
            values.clone()
        };
        if !filtered_values.is_empty() {
            dst.entry(cat.clone()).or_default().extend(filtered_values);
        }
    }
}

fn is_value_ignored(
    snapshot: &crate::types::IgnoredValuesSnapshot,
    cat: &PiiCategory,
    value: &str,
) -> bool {
    let cat_str = serde_json::to_string(cat)
        .unwrap()
        .trim_matches('"')
        .to_string();
    let hash = crate::user_values::UserHash::hash_value(&snapshot.salt, cat.clone(), value);
    snapshot.set.contains(&(cat_str, hash))
}

fn merge_custom_matches(
    dst: &mut BTreeMap<String, Vec<String>>,
    src: &BTreeMap<String, Vec<String>>,
) {
    for (cat, values) in src {
        dst.entry(cat.clone()).or_default().extend(values.clone());
    }
}

fn summarize_custom_matches(
    map: &BTreeMap<String, Vec<String>>,
) -> Vec<crate::types::CustomFinding> {
    let mut out = Vec::new();
    for (cat, values) in map {
        let redacted_examples = values
            .iter()
            .take(5)
            .map(|v| pii::redact_value(crate::types::PiiCategory::UserId, v))
            .collect();
        out.push(crate::types::CustomFinding {
            category: cat.clone(),
            count: values.len(),
            redacted_examples,
        });
    }
    out
}

fn custom_score_and_reasons(
    findings: &[crate::types::CustomFinding],
    detectors: &[CustomDetector],
) -> (i64, Vec<Reason>) {
    let risk_by_name: BTreeMap<&str, &RiskLevel> = detectors
        .iter()
        .map(|d| (d.name.as_str(), &d.risk_level))
        .collect();
    let mut score = 0i64;
    let mut reasons = Vec::new();

    for finding in findings {
        let level = risk_by_name
            .get(finding.category.as_str())
            .copied()
            .unwrap_or(&RiskLevel::Medium);
        let weight = custom_risk_weight(level);
        let count = (finding.count as i64).min(20);
        if count <= 0 {
            continue;
        }
        score += weight * count;
        reasons.push(Reason {
            key: "reason.customCategoryCount".to_string(),
            vars: json!({
                "category": finding.category,
                "count": finding.count,
                "risk": format_custom_risk(level),
            }),
        });
    }

    (score, reasons)
}

fn overall_risk_evidence(
    findings: &[crate::types::PiiFinding],
    custom_findings: &[crate::types::CustomFinding],
    detectors: &[CustomDetector],
    weak_zip_encryption: bool,
) -> (RiskLevel, usize) {
    let risk_by_name: BTreeMap<&str, RiskLevel> = detectors
        .iter()
        .map(|d| (d.name.as_str(), d.risk_level))
        .collect();

    let mut max_level = RiskLevel::Low;
    let mut high_types: BTreeSet<String> = BTreeSet::new();

    for finding in findings {
        if finding.count == 0 {
            continue;
        }
        let level = pii::builtin_risk_level(&finding.category);
        if level > max_level {
            max_level = level;
        }
        if level >= RiskLevel::High {
            high_types.insert(format!("{:?}", finding.category));
        }
    }

    for finding in custom_findings {
        if finding.count == 0 {
            continue;
        }
        let level = risk_by_name
            .get(finding.category.as_str())
            .copied()
            .unwrap_or(RiskLevel::Medium);
        if level > max_level {
            max_level = level;
        }
        if level >= RiskLevel::High {
            high_types.insert(finding.category.clone());
        }
    }

    if weak_zip_encryption {
        if RiskLevel::High > max_level {
            max_level = RiskLevel::High;
        }
        high_types.insert("weak_archive_encryption".to_string());
    }

    (max_level, high_types.len())
}

fn custom_risk_weight(level: &RiskLevel) -> i64 {
    match level {
        RiskLevel::Low => 2,
        RiskLevel::Medium => 4,
        RiskLevel::High => 7,
        RiskLevel::Critical => 10,
    }
}

fn format_custom_risk(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn is_text_like_ext(ext: &str) -> bool {
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
            | "ics"
            | "ical"
            | "calendar"
            | "excalidraw"
    )
}

fn is_technical_file_ext(ext: &str) -> bool {
    matches!(ext, "ics" | "ical" | "calendar" | "excalidraw")
}

fn is_image_ext(ext: &str) -> bool {
    matches!(
        ext,
        "png" | "jpg" | "jpeg" | "webp" | "bmp" | "tif" | "tiff"
    )
}

fn scan_image_with_optional_ocr(path: &Path, max_bytes: u64) -> Result<String> {
    fn run_tesseract(path: &Path, lang: &str) -> Result<String> {
        let output = std::process::Command::new("tesseract")
            .arg(path)
            .arg("stdout")
            .arg("-l")
            .arg(lang)
            .arg("--dpi")
            .arg("300")
            .output()
            .context("run tesseract")?;
        if !output.status.success() {
            anyhow::bail!(
                "tesseract failed (lang={lang}, code={:?})",
                output.status.code()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    let mut text =
        run_tesseract(path, "eng+fra+deu+spa+ara").or_else(|_| run_tesseract(path, "eng"))?;
    if text.len() > max_bytes as usize {
        text.truncate(max_bytes as usize);
    }
    Ok(text)
}

fn scan_pdf_text(path: &Path, max_bytes: u64) -> Result<String> {
    let extracted = panic::catch_unwind(AssertUnwindSafe(|| pdf_extract::extract_text(path)));
    let mut text = match extracted {
        Ok(result) => result.context("extract pdf text")?,
        Err(_) => anyhow::bail!("extract pdf text panicked"),
    };
    if text.len() > max_bytes as usize {
        text.truncate(max_bytes as usize);
    }
    Ok(normalize_pdf_pua(text))
}

fn normalize_pdf_pua(text: String) -> String {
    fn map_char(ch: char) -> Option<char> {
        match ch {
            '\u{f8eb}' => Some('⎛'),
            '\u{f8ed}' => Some('⎝'),
            '\u{f8ef}' => Some('⎢'),
            '\u{f8f0}' => Some('⎣'),
            '\u{f8f1}' => Some('⎧'),
            '\u{f8f2}' => Some('⎨'),
            '\u{f8f3}' => Some('⎩'),
            '\u{f8f4}' => Some('⎪'),
            '\u{f8f6}' => Some('⎞'),
            '\u{f8f9}' => Some('⎤'),
            '\u{f8fa}' => Some('⎥'),
            '\u{f8fb}' => Some('⎦'),
            '\u{f8fc}' => Some('⎫'),
            '\u{f8fd}' => Some('⎬'),
            '\u{f8fe}' => Some('⎭'),
            _ => None,
        }
    }

    if !text.chars().any(|c| map_char(c).is_some()) {
        return text;
    }

    text.chars().map(|c| map_char(c).unwrap_or(c)).collect()
}

fn scan_docx_text(path: &Path, max_bytes: u64) -> Result<String> {
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut out = String::new();
    let mut remaining = max_bytes as usize;
    for i in 0..archive.len() {
        if remaining == 0 {
            break;
        }
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_lowercase();
        if !name.ends_with(".xml") {
            continue;
        }
        if !(name.starts_with("word/") || name.starts_with("docprops/")) {
            continue;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        if buf.contains(&0) {
            continue;
        }
        let mut text = String::from_utf8_lossy(&buf).to_string();
        if text.len() > remaining {
            text.truncate(remaining);
        }
        remaining = remaining.saturating_sub(text.len());
        out.push('\n');
        out.push_str(&text);
    }
    Ok(out)
}

fn read_text_prefix(path: &Path, max_bytes: u64) -> Result<String> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; max_bytes as usize];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn read_text_prefix_if_probably_text(path: &Path, max_bytes: u64) -> Result<String> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; max_bytes as usize];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    if buf.contains(&0) {
        anyhow::bail!("binary file");
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn scan_excel(
    path: &Path,
    settings: &Settings,
    matches: &mut BTreeMap<PiiCategory, Vec<String>>,
    custom_matches: &mut BTreeMap<String, Vec<String>>,
    custom_detectors: &[pii::CompiledCustomDetector],
    filename: &str,
) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext == "xlsx" {
        let mut workbook: Xlsx<_> = calamine::open_workbook(path)?;
        scan_workbook_xlsx(
            &mut workbook,
            settings,
            matches,
            custom_matches,
            custom_detectors,
            filename,
        )?;
    } else {
        let mut workbook: Xls<_> = calamine::open_workbook(path)?;
        scan_workbook_xls(
            &mut workbook,
            settings,
            matches,
            custom_matches,
            custom_detectors,
            filename,
        )?;
    }
    Ok(())
}

fn scan_workbook_xlsx<R: Read + Seek>(
    workbook: &mut Xlsx<R>,
    settings: &Settings,
    matches: &mut BTreeMap<PiiCategory, Vec<String>>,
    custom_matches: &mut BTreeMap<String, Vec<String>>,
    custom_detectors: &[pii::CompiledCustomDetector],
    filename: &str,
) -> Result<()> {
    let mut remaining = settings.max_text_bytes as usize;
    for sheet_name in workbook.sheet_names().to_owned() {
        if remaining == 0 {
            break;
        }
        if let Ok(range) = workbook.worksheet_range(&sheet_name) {
            let mut text = String::new();
            text.push_str(&format!("sheet:{}\n", sheet_name));
            for row in range.rows().take(5000) {
                for cell in row.iter().take(50) {
                    let s = cell.to_string();
                    if s.is_empty() {
                        continue;
                    }
                    if text.len() + s.len() + 1 > remaining {
                        remaining = 0;
                        break;
                    }
                    text.push_str(&s);
                    text.push('\n');
                }
                if remaining == 0 {
                    break;
                }
            }

            merge_matches(matches, &pii::detect_in_text(&text, true), &None);
            merge_custom_matches(
                custom_matches,
                &pii::detect_custom(&text, filename, custom_detectors),
            );
            remaining = remaining.saturating_sub(text.len());
        }
    }
    Ok(())
}

fn scan_workbook_xls<R: Read + Seek>(
    workbook: &mut Xls<R>,
    settings: &Settings,
    matches: &mut BTreeMap<PiiCategory, Vec<String>>,
    custom_matches: &mut BTreeMap<String, Vec<String>>,
    custom_detectors: &[pii::CompiledCustomDetector],
    filename: &str,
) -> Result<()> {
    let mut remaining = settings.max_text_bytes as usize;
    for sheet_name in workbook.sheet_names().to_owned() {
        if remaining == 0 {
            break;
        }
        if let Ok(range) = workbook.worksheet_range(&sheet_name) {
            let mut text = String::new();
            text.push_str(&format!("sheet:{}\n", sheet_name));
            for row in range.rows().take(5000) {
                for cell in row.iter().take(50) {
                    let s = cell.to_string();
                    if s.is_empty() {
                        continue;
                    }
                    if text.len() + s.len() + 1 > remaining {
                        remaining = 0;
                        break;
                    }
                    text.push_str(&s);
                    text.push('\n');
                }
                if remaining == 0 {
                    break;
                }
            }

            merge_matches(matches, &pii::detect_in_text(&text, true), &None);
            merge_custom_matches(
                custom_matches,
                &pii::detect_custom(&text, filename, custom_detectors),
            );
            remaining = remaining.saturating_sub(text.len());
        }
    }
    Ok(())
}

fn scan_zip_path(
    path: &Path,
    settings: &Settings,
    matches: &mut BTreeMap<PiiCategory, Vec<String>>,
    custom_matches: &mut BTreeMap<String, Vec<String>>,
    custom_detectors: &[pii::CompiledCustomDetector],
    filename: &str,
    depth: usize,
) -> Result<()> {
    let f = File::open(path)?;
    let mut archive = ZipArchive::new(f)?;
    scan_zip_archive(
        &mut archive,
        settings,
        matches,
        custom_matches,
        custom_detectors,
        filename,
        depth,
    )
}

fn scan_zip_archive<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    settings: &Settings,
    matches: &mut BTreeMap<PiiCategory, Vec<String>>,
    custom_matches: &mut BTreeMap<String, Vec<String>>,
    custom_detectors: &[pii::CompiledCustomDetector],
    filename: &str,
    depth: usize,
) -> Result<()> {
    if depth > settings.max_zip_depth {
        return Ok(());
    }

    let mut total_uncompressed: u64 = 0;
    let len = archive.len().min(settings.max_zip_entries);
    for i in 0..len {
        let mut file = archive.by_index(i)?;
        if file.encrypted() {
            continue;
        }

        let name = file.name().to_string();
        let uncompressed = file.size();
        total_uncompressed = total_uncompressed.saturating_add(uncompressed);
        if total_uncompressed > settings.max_zip_total_uncompressed_bytes {
            break;
        }
        if uncompressed > settings.max_zip_entry_bytes {
            continue;
        }

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        // If nested zip.
        if name.to_lowercase().ends_with(".zip") && depth < settings.max_zip_depth {
            if let Ok(mut nested) = ZipArchive::new(std::io::Cursor::new(buf.clone())) {
                let _ = scan_zip_archive(
                    &mut nested,
                    settings,
                    matches,
                    custom_matches,
                    custom_detectors,
                    filename,
                    depth + 1,
                );
            }
            continue;
        }

        // XLSX inside ZIP.
        if name.to_lowercase().ends_with(".xlsx") {
            if let Ok(mut xlsx) = Xlsx::new(std::io::Cursor::new(buf.clone())) {
                let _ = scan_workbook_xlsx(
                    &mut xlsx,
                    settings,
                    matches,
                    custom_matches,
                    custom_detectors,
                    filename,
                );
            }
            continue;
        }

        if is_text_entry_name(&name) {
            if buf.contains(&0) {
                continue;
            }
            let text = String::from_utf8_lossy(&buf);
            merge_matches(matches, &pii::detect_in_text(&text, true), &None);
            merge_custom_matches(
                custom_matches,
                &pii::detect_custom(&text, filename, custom_detectors),
            );
        }
    }

    Ok(())
}

fn is_text_entry_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    for ext in [
        ".txt", ".csv", ".tsv", ".json", ".ndjson", ".log", ".md", ".xml", ".yaml", ".yml",
    ] {
        if lower.ends_with(ext) {
            return true;
        }
    }
    false
}

fn detect_contextual_entities(
    text: &str,
    analyzers: &[ContextualAnalyzer],
    custom_matches: &mut BTreeMap<String, Vec<String>>,
) {
    for analyzer in analyzers {
        let detections = analyzer.analyze(text);
        for detection in detections {
            custom_matches
                .entry(detection.entity_type.clone())
                .or_default()
                .push(detection.text.clone());
        }
    }
}
