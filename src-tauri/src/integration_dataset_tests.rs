use crate::pii;
use crate::type_catalog;
use crate::types::{CustomDetector, PiiCategory};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct DatasetCase {
    id: String,
    target_type: String,
    text: String,
    should_detect: bool,
}

fn dataset_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/integration_dataset.jsonl")
}

fn category_to_id(cat: &PiiCategory) -> &'static str {
    match cat {
        PiiCategory::Email => "email",
        PiiCategory::Phone => "phone",
        PiiCategory::Iban => "iban",
        PiiCategory::CreditCard => "credit_card",
        PiiCategory::IpAddress => "ip_address",
        PiiCategory::Address => "address",
        PiiCategory::PostalCode => "postal_code",
        PiiCategory::DateOfBirth => "date_of_birth",
        PiiCategory::Cookie => "cookie",
        PiiCategory::UserId => "user_id",
        PiiCategory::Secret => "secret",
        PiiCategory::FileNameSignal => "file_name_signal",
        PiiCategory::WeakArchiveEncryption => "weak_archive_encryption",
    }
}

fn load_dataset() -> Vec<DatasetCase> {
    let path = dataset_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read dataset {}: {}", path.display(), e));

    let mut out = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let row: DatasetCase = serde_json::from_str(trimmed).unwrap_or_else(|e| {
            panic!(
                "Invalid JSONL at {} line {}: {}",
                path.display(),
                index + 1,
                e
            )
        });
        out.push(row);
    }
    out
}

fn yaml_custom_detectors_for_tests() -> Vec<CustomDetector> {
    let registry = type_catalog::TypeRegistry::load("fr", None, None)
        .unwrap_or_else(|e| panic!("Failed to load type catalog for tests: {}", e));

    registry
        .types
        .values()
        .filter(|def| def.enabled)
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

#[test]
fn integration_dataset_detection_consistency() {
    let cases = load_dataset();
    assert!(!cases.is_empty(), "Dataset is empty");

    let custom_detectors = yaml_custom_detectors_for_tests();
    let compiled = pii::compile_custom_detectors(&custom_detectors)
        .unwrap_or_else(|e| panic!("Failed to compile custom detectors: {}", e));

    let mut failures: Vec<String> = Vec::new();

    for case in &cases {
        let mut detected: BTreeSet<String> = BTreeSet::new();

        let builtin_matches = pii::detect_in_text(&case.text, true);
        for (cat, values) in &builtin_matches {
            if !values.is_empty() {
                detected.insert(category_to_id(cat).to_string());
            }
        }

        let custom_matches = pii::detect_custom(&case.text, "dataset.txt", &compiled);
        for (cat, values) in custom_matches {
            if !values.is_empty() {
                detected.insert(cat);
            }
        }

        let has_target = detected.contains(case.target_type.as_str());
        if case.should_detect && !has_target {
            failures.push(format!(
                "MISS {}: expected detection of {} | text='{}' | got={:?}",
                case.id, case.target_type, case.text, detected
            ));
        }
        if !case.should_detect && has_target {
            failures.push(format!(
                "FALSE_POS {}: expected no detection of {} | text='{}' | got={:?}",
                case.id, case.target_type, case.text, detected
            ));
        }
    }

    if !failures.is_empty() {
        let max_lines = 40usize;
        let preview = failures
            .iter()
            .take(max_lines)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "Integration dataset mismatches: {} failures\n{}{}",
            failures.len(),
            preview,
            if failures.len() > max_lines {
                "\n...truncated..."
            } else {
                ""
            }
        );
    }
}
