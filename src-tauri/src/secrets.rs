use once_cell::sync::Lazy;
use regex::Regex;

const SECRET_KEY_LABELS: &[&str] = &[
    "api_key",
    "x-api-key",
    "client_secret",
    "private_key",
    "secret_key",
    "access_token",
    "bearer_token",
    "auth_token",
    "password",
    "jwt",
    "aws_access_key_id",
    "aws_secret_access_key",
    "azure_client_secret",
    "gcp_api_key",
    "github_token",
    "github_pat",
    "gitlab_token",
    "bitbucket_token",
    "stripe_secret",
    "paypal_key",
    "database_url",
    "db_password",
    "env",
    // add more as needed
];

static SECRET_PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| {
    vec![
        // AWS Access Key ID
        SecretPattern::new(
            r"(?i)AKIA[0-9A-Z]{16}",
            20,
            Some(|v: &str| {
                let upper = v.to_uppercase();
                (upper.starts_with("AKIA") || upper.starts_with("ASIA")) && upper.len() == 20
            }),
        ),
        // AWS Secret Access Key (in context)
        SecretPattern::new(
            r"(?i)(aws_secret_access_key|aws_secret_key|aws_access_key_secret)[\s]*[=:][\s]*[A-Za-z0-9/+=]{40}",
            40,
            None,
        ),
        // AWS Session Token
        SecretPattern::new(
            r"(?i)(aws_session_token|aws_session)[\s]*[=:][\s]*[A-Za-z0-9/+=]{200,}",
            200,
            None,
        ),
        // Azure Client ID / Tenant ID / Subscription ID (GUIDs in context)
        SecretPattern::new(
            r"(?i)(azure_client_id|azure_tenant_id|azure_subscription_id|client_id|tenant_id|subscription_id)[\s]*[=:][\s]*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            36,
            None,
        ),
        // Azure Client Secret
        SecretPattern::new(
            r"(?i)(azure_client_secret|client_secret|app_secret)[\s]*[=:][\s]*[A-Za-z0-9_~.-]{20,}",
            20,
            None,
        ),
        // Azure Storage Account Key
        SecretPattern::new(
            r"(?i)(azure_storage_key|storage_account_key|AccountKey=)[A-Za-z0-9/+=]{86,}",
            86,
            None,
        ),
        // GCP API Key
        SecretPattern::new(
            r"(?i)(google_api_key|gcp_api_key|api_key)[\s]*[=:][\s]*AIza[0-9A-Za-z_-]{35,45}",
            35,
            None,
        ),
        // GCP Service Account JSON (content with private_key)
        SecretPattern::new(
            r#""private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----""#,
            200,
            None,
        ),
        // GCP Project ID (in context)
        SecretPattern::new(
            r"(?i)(gcp_project_id|google_project|project_id)[\s]*[=:][\s]*[a-z0-9-]{6,30}",
            6,
            None,
        ),
        // GitHub Tokens (case insensitive)
        SecretPattern::new(r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9_]{20,}", 20, None),
        // Generic token patterns in context
        SecretPattern::new(
            r"(?i)(github_token|github_pat|gitlab_token|gh_token)[\s]*[=:][\s]*[a-zA-Z0-9_-]{20,}",
            20,
            None,
        ),
        // Generic access token
        SecretPattern::new(
            r"(?i)(access_token|access_token_secret|api_token|accesskey)[\s]*[=:][\s]*[a-zA-Z0-9_-]{16,}",
            16,
            None,
        ),
        // JWT Token
        SecretPattern::new(
            r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            50,
            Some(|v: &str| {
                let parts: Vec<&str> = v.split('.').collect();
                if parts.len() != 3 {
                    return false;
                }
                // Basic JWT structure check - first part should be base64 JSON
                parts.iter().all(|p| {
                    !p.is_empty()
                        && p.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
                })
            }),
        ),
        // Private Key PEM
        SecretPattern::new(
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            40,
            None,
        ),
        // Private Key PEM (multiline with newlines)
        SecretPattern::new(
            r"(?s)-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.+?-----END (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            100,
            None,
        ),
        // SSH Private Key
        SecretPattern::new(r"-----BEGIN OPENSSH PRIVATE KEY-----", 100, None),
        // Database URL with password
        SecretPattern::new(
            r"(?i)(mysql|postgres|postgresql|mongodb|redis|sqlite)://[^:]+:[^@]+@",
            20,
            None,
        ),
        // Generic database connection string
        SecretPattern::new(
            r#"(?i)(database_url|db_url|db_password|connection_string)[\s]*[=:][\s]*[^&\s"']+"#,
            20,
            None,
        ),
        // Password in key-value (explicit)
        SecretPattern::new(
            r#"(?i)(password|passwd|pwd)[\s]*[=:][\s]*[^\s"';]{6,}"#,
            6,
            None,
        ),
        // Authorization header with token
        SecretPattern::new(
            r#"(?i)Authorization[\s]*:[\s]*(Bearer|Basic|Digest) [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#,
            30,
            None,
        ),
        // Generic secret with high entropy context
        SecretPattern::new(
            r"(?i)(secret|secret_key|encryption_key|private_key|api_key|token)[\s]*[=:][\s]*[A-Za-z0-9/+=]{20,}",
            20,
            Some(|s: &str| has_api_context(s)),
        ),
    ]
});

pub struct SecretPattern {
    pub regex: Regex,
    pub min_length: usize,
    pub validator: Option<fn(&str) -> bool>,
}

impl SecretPattern {
    fn new(pattern: &str, min_length: usize, validator: Option<fn(&str) -> bool>) -> Self {
        Self {
            regex: Regex::new(pattern).unwrap_or_else(|_| Regex::new("$^").unwrap()),
            min_length,
            validator,
        }
    }
}

pub fn detect_secrets(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();

    // Pattern-based detection
    for pattern in SECRET_PATTERNS.iter() {
        for mat in pattern.regex.find_iter(text) {
            let matched = mat.as_str();
            if matched.len() >= pattern.min_length {
                // Apply validator if present
                let is_valid = pattern.validator.is_none() || pattern.validator.unwrap()(matched);
                if is_valid
                    && !is_placeholder_value(matched)
                    && !found.contains(&matched.to_string())
                {
                    found.push(matched.to_string());
                }
            }
        }
    }

    // Entropy-based detection for remaining high-entropy strings
    if let Some(entropy_matches) = detect_high_entropy_secrets(text) {
        for m in entropy_matches {
            if !found.contains(&m) {
                found.push(m);
            }
        }
    }

    found
}

fn is_placeholder_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    let placeholders = [
        "your_api_key_here",
        "your_key_here",
        "your_secret_here",
        "xxx",
        "xxxx",
        "xxxxx",
        "xxxxxx",
        "placeholder",
        "replace_me",
        "changeme",
        "changeme123",
        "password123",
        "admin123",
        "test123",
        "example_key",
        "example_secret",
        "sample_key",
        "sample_secret",
        "null",
        "none",
        "undefined",
    ];

    // Check exact match or contains
    if placeholders
        .iter()
        .any(|p| lower == *p || lower.contains(p))
    {
        return true;
    }

    // Check if it's mostly repeated characters
    let chars: Vec<char> = lower.chars().collect();
    if chars.len() > 4 {
        let first = chars[0];
        if chars.iter().skip(1).all(|&c| c == first) {
            return true;
        }
    }

    // Check for sequential patterns like "123456" or "abcdef"
    if chars.len() >= 6 {
        let mut is_sequential = true;
        for i in 1..chars.len() {
            if chars[i] as u32 != chars[i - 1] as u32 + 1 {
                is_sequential = false;
                break;
            }
        }
        if is_sequential {
            return true;
        }
    }

    false
}

fn detect_high_entropy_secrets(text: &str) -> Option<Vec<String>> {
    let threshold = 5.0;
    let min_length = 10;
    let max_length = 200;
    let mut secrets: Vec<String> = Vec::new();

    // Look for quoted strings that might be secrets
    let re = Regex::new(r#""([^"]{10,200})""#).ok()?;

    for cap in re.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let value = m.as_str();
            if value.len() >= min_length && value.len() <= max_length {
                let entropy = calculate_entropy(value);
                if entropy >= threshold
                    && !is_placeholder_value(value)
                    && looks_like_secret_value(value)
                    && !secrets.contains(&value.to_string())
                {
                    secrets.push(value.to_string());
                }
            }
        }
    }

    // Also check for key=value patterns without quotes
    let kv_re = Regex::new(
        r"(?i)(?:secret|key|token|password|auth|client_secret|api_key|access_token|private_key|auth_token|bearer_token|aws_secret_access_key|azure_client_secret)[\s]*[=:][\s]*([A-Za-z0-9_~./+-]{10,200})",
    )
    .ok()?;

    for cap in kv_re.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let value = m.as_str();
            if value.len() >= min_length && value.len() <= max_length {
                let entropy = calculate_entropy(value);
                if entropy >= threshold
                    && !is_placeholder_value(value)
                    && looks_like_secret_value(value)
                    && !secrets.contains(&value.to_string())
                {
                    secrets.push(value.to_string());
                }
            }
        }
    }

    if secrets.is_empty() {
        None
    } else {
        Some(secrets)
    }
}

fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    // Use a simpler character frequency analysis
    // Count unique characters and calculate based on character diversity
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    if len == 0 {
        return 0.0;
    }

    // Calculate character diversity ratio
    let unique_count = chars.iter().collect::<std::collections::HashSet<_>>().len();
    let diversity_ratio = unique_count as f64 / len as f64;

    // Base entropy from diversity (0-1 normalized)
    let base_entropy = diversity_ratio;

    // Bonus for having different character types
    let has_upper = chars.iter().any(|c| c.is_uppercase());
    let has_lower = chars.iter().any(|c| c.is_lowercase());
    let has_digit = chars.iter().any(|c| c.is_ascii_digit());
    let has_special = chars.iter().any(|c| !c.is_alphanumeric());

    let type_bonus = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&b| b)
        .count() as f64
        * 0.1;

    // Length factor - longer strings with high diversity are more likely to be secrets
    let length_factor = (len as f64 / 20.0).min(1.0);

    // Combined entropy score (roughly 0-5+ scale)
    (base_entropy * 4.0 + type_bonus + length_factor * 0.5).min(6.0)
}

fn looks_like_secret_value(value: &str) -> bool {
    let v = value.trim();

    // Must have mixed character types
    let has_upper = v.chars().any(|c| c.is_uppercase());
    let has_lower = v.chars().any(|c| c.is_lowercase());
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    let has_special = v.chars().any(|c| !c.is_alphanumeric());

    // At least 3 of 4 character types
    let type_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&b| b)
        .count();

    if type_count < 3 {
        return false;
    }

    // Reject if it's a URL or path
    if v.contains("://") || v.starts_with('/') || v.contains('\\') {
        return false;
    }

    // Reject if it's a date/time
    if v.len() <= 20 {
        let date_patterns = [r"^\d{4}-\d{2}-\d{2}", r"^\d{2}/\d{2}/\d{4}", r"^\d{10,13}$"];
        for pattern in date_patterns {
            if Regex::new(pattern).is_ok_and(|r| r.is_match(v)) {
                return false;
            }
        }
    }

    // Reject if it's a UUID
    if Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        .is_ok_and(|r| r.is_match(v))
    {
        return false;
    }

    // Reject if it's base64 but looks like normal text
    if is_likely_plain_base64(v) {
        return false;
    }

    true
}

fn has_api_context(s: &str) -> bool {
    let lower = s.to_lowercase();
    let has_label = SECRET_KEY_LABELS.iter().any(|&label| lower.contains(label));
    has_label &&
    // Exclude file types with technical content that might look like secrets
    !lower.contains(".ics") && !lower.contains(".ical") &&
    !lower.contains(".excalidraw") && !lower.contains(".txt") &&
    !lower.contains(".calendar")
}

fn is_likely_plain_base64(s: &str) -> bool {
    // Common English words that appear in base64-encoded content
    let common_words = [
        "the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one",
        "our", "out", "day", "get", "has", "him", "his", "how", "its", "may", "new", "now", "old",
        "see", "two", "way", "who", "boy", "did", "own", "say", "she", "too", "use",
    ];

    let lower = s.to_lowercase();
    for word in common_words {
        if lower.contains(word) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key() {
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let secrets = detect_secrets(text);
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_github_token() {
        let text = "github_token=ghp_abcdef1234567890abcdef1234567890ab";
        let secrets = detect_secrets(text);
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_jwt_token() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let secrets = detect_secrets(text);
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_placeholder_rejected() {
        let text = "api_key=your_api_key_here";
        let secrets = detect_secrets(text);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_azure_secret() {
        let text = "AZURE_CLIENT_SECRET=abc123def456ghi789jkl012mno345pqr";
        let secrets = detect_secrets(text);
        assert!(!secrets.is_empty());
    }

    #[test]
    fn test_private_key() {
        let text = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----";
        let secrets = detect_secrets(text);
        assert!(!secrets.is_empty());
    }
}
