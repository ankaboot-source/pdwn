use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::types::RiskLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefinition {
    pub id: String,
    pub display_name_key: String,
    pub description_key: String,
    pub category: String,
    pub risk_level: RiskLevel,
    pub requires_key: bool,
    #[serde(default)]
    pub key_labels: Vec<String>,
    #[serde(default)]
    pub advanced: TypeAdvanced,
    pub enabled: bool,
    pub locale_requirement: Option<String>,
    pub positive_indicators: Option<String>,
    pub negative_indicators: Option<String>,
    pub threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TypeAdvanced {
    #[serde(default)]
    pub blocked_extensions: Vec<String>,
    #[serde(default)]
    pub filename_keywords: Vec<FilenameKeyword>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilenameKeyword {
    pub keyword: String,
    pub score: i64,
}

#[derive(Debug, Clone)]
pub struct TypeRegistry {
    pub types: HashMap<String, TypeDefinition>,
}

impl TypeRegistry {
    pub fn load(locale: &str, user_custom_file: Option<&Path>) -> Result<Self, String> {
        let mut registry: HashMap<String, TypeDefinition> = HashMap::new();

        Self::load_into_registry("base.yaml", "standard/base", &mut registry)?;

        for locale_token in locale_candidates(locale) {
            let locale_path = format!("{}.yaml", locale_token);
            Self::load_into_registry(&locale_path, "standard/locale", &mut registry)?;

            let custom_path = format!("custom/{}.yaml", locale_token);
            Self::load_into_registry(&custom_path, "custom", &mut registry)?;
        }

        if let Some(user_path) = user_custom_file {
            if let Err(e) = Self::load_into_registry_from_path(user_path, "custom", &mut registry) {
                tracing::warn!(
                    "Failed to load user custom types from {}: {}",
                    user_path.display(),
                    e
                );
            }
        }

        Ok(Self { types: registry })
    }

    fn load_into_registry(
        relative_path: &str,
        origin: &str,
        registry: &mut HashMap<String, TypeDefinition>,
    ) -> Result<(), String> {
        let Some(resolved_path) = resolve_types_path(relative_path) else {
            return Ok(());
        };
        Self::load_into_registry_from_path(&resolved_path, origin, registry)
    }

    fn load_into_registry_from_path(
        path: &Path,
        origin: &str,
        registry: &mut HashMap<String, TypeDefinition>,
    ) -> Result<(), String> {
        let content = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("Failed to read {}: {}", path.display(), e)),
        };

        let catalog: YamlCatalog = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

        for mut def in catalog.types {
            def.origin = origin.to_string();
            registry.insert(def.id.clone(), def);
        }

        Ok(())
    }
}

pub fn upsert_custom_type(path: &Path, mut new_type: TypeDefinition) -> Result<(), String> {
    new_type.origin.clear();

    let mut catalog = if path.is_file() {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        serde_yaml::from_str::<YamlCatalog>(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?
    } else {
        YamlCatalog { types: Vec::new() }
    };

    if let Some(existing) = catalog.types.iter_mut().find(|t| t.id == new_type.id) {
        *existing = new_type;
    } else {
        catalog.types.push(new_type);
    }

    catalog.types.sort_by(|a, b| a.id.cmp(&b.id));

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }

    let serialized = serde_yaml::to_string(&catalog)
        .map_err(|e| format!("Failed to serialize {}: {}", path.display(), e))?;
    std::fs::write(path, serialized)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    Ok(())
}

fn resolve_types_path(relative_path: &str) -> Option<PathBuf> {
    for base in types_base_dirs() {
        let candidate = base.join(relative_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn types_base_dirs() -> Vec<PathBuf> {
    let mut bases = Vec::new();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    bases.push(manifest_dir.join("types"));
    if let Some(parent) = manifest_dir.parent() {
        bases.push(parent.join("src-tauri/types"));
    }

    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd.join("types"));
        bases.push(cwd.join("src-tauri/types"));
    }

    dedup_paths(bases)
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        if !out.iter().any(|existing| same_path(existing, &p)) {
            out.push(p);
        }
    }
    out
}

fn same_path(a: &Path, b: &Path) -> bool {
    a == b
}

fn locale_candidates(locale: &str) -> Vec<String> {
    let normalized = locale
        .trim()
        .split('.')
        .next()
        .unwrap_or_default()
        .split('@')
        .next()
        .unwrap_or_default();

    if normalized.is_empty() {
        return Vec::new();
    }

    let lang = normalized
        .split_once('_')
        .or_else(|| normalized.split_once('-'))
        .map(|(l, _)| l)
        .unwrap_or(normalized);

    let mut out = Vec::new();
    let candidates = vec![
        normalized.to_string(),
        normalized.to_ascii_lowercase(),
        lang.to_string(),
        lang.to_ascii_lowercase(),
    ];
    for candidate in candidates {
        if !candidate.is_empty() && !out.iter().any(|existing| existing == &candidate) {
            out.push(candidate);
        }
    }
    out
}

fn locale_parts(locale: &str) -> (String, Option<String>) {
    let normalized = locale
        .trim()
        .split('.')
        .next()
        .unwrap_or_default()
        .split('@')
        .next()
        .unwrap_or_default()
        .replace('_', "-")
        .to_ascii_lowercase();

    let mut parts = normalized.split('-');
    let lang = parts.next().unwrap_or_default().to_string();
    let region = parts
        .next()
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string());
    (lang, region)
}

pub fn locale_requirement_matches(requirement: &str, locale: &str) -> bool {
    let req = requirement.trim();
    if req.is_empty() {
        return true;
    }

    let (locale_lang, locale_region) = locale_parts(locale);
    if locale_lang.is_empty() {
        return false;
    }

    let (req_lang, req_region) = locale_parts(req);
    if req_lang.is_empty() {
        return false;
    }

    if req_region.is_some() {
        return req_lang == locale_lang && req_region == locale_region;
    }

    if req_lang.len() == 2 && req_lang == locale_lang {
        return true;
    }
    locale_region.as_deref() == Some(req_lang.as_str())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct YamlCatalog {
    pub types: Vec<TypeDefinition>,
}
