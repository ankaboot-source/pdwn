use crate::types::PiiCategory;

/// Helper for normalizing and hashing user values with salt.
/// All hashed values include a stable salt per user.
pub struct UserHash;

impl UserHash {
    /// Normalize value for consistent hashing.
    pub fn normalize_value(category: PiiCategory, raw: &str) -> String {
        let v = raw.trim();
        match category {
            PiiCategory::Email => v.to_lowercase(),
            PiiCategory::Iban => v
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_uppercase(),
            PiiCategory::Phone => v.chars().filter(|c| c.is_ascii_digit()).collect(),
            _ => v.to_string(),
        }
    }

    /// Compute salted hash of normalized value.
    pub fn hash_value(salt_head: &str, category: PiiCategory, raw_value: &str) -> String {
        let normalized = Self::normalize_value(category.clone(), raw_value);
        let mut hasher = blake3::Hasher::new();
        hasher.update(salt_head.as_bytes());
        hasher.update(b"\n");
        hasher.update(normalized.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}
