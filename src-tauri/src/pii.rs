use crate::types::{
    PiiCategory, PiiFinding, Reason, RevealedCategory, RevealedFindings, RevealedValue,
};

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct CompiledCustomDetector {
    pub name: String,
    pub filename_regex: Option<Regex>,
    pub field_name_regex: Option<Regex>,
    pub value_regex: Option<Regex>,
}

pub fn validate_user_regex(pattern: &str) -> Result<(), String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err("regex vide".to_string());
    }
    if trimmed.len() > 512 {
        return Err("regex trop longue (max 512)".to_string());
    }
    if trimmed.chars().filter(|c| *c == '|').count() > 32 {
        return Err("regex trop complexe (trop d'alternatives)".to_string());
    }
    Regex::new(trimmed)
        .map(|_| ())
        .map_err(|e| format!("regex invalide: {e}"))
}

pub fn compile_custom_detectors(
    detectors: &[crate::types::CustomDetector],
) -> Result<Vec<CompiledCustomDetector>, String> {
    let mut out = Vec::new();
    for d in detectors {
        let filename_regex = match d.filename_regex.as_ref().map(|s| s.trim()) {
            Some(v) if !v.is_empty() => {
                validate_user_regex(v)?;
                Some(Regex::new(v).map_err(|e| format!("regex invalide (filename): {e}"))?)
            }
            _ => None,
        };
        let field_name_regex = match d.field_name_regex.as_ref().map(|s| s.trim()) {
            Some(v) if !v.is_empty() => {
                validate_user_regex(v)?;
                Some(Regex::new(v).map_err(|e| format!("regex invalide (field): {e}"))?)
            }
            _ => None,
        };
        let value_regex = match d.value_regex.as_ref().map(|s| s.trim()) {
            Some(v) if !v.is_empty() => {
                validate_user_regex(v)?;
                Some(Regex::new(v).map_err(|e| format!("regex invalide (value): {e}"))?)
            }
            _ => None,
        };

        if filename_regex.is_none() && field_name_regex.is_none() && value_regex.is_none() {
            continue;
        }

        out.push(CompiledCustomDetector {
            name: d.name.clone(),
            filename_regex,
            field_name_regex,
            value_regex,
        });
    }
    Ok(out)
}

static RE_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{2,253}\.[a-z]{2,}\b").unwrap());

static RE_IP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap()
});

// Loose phone pattern; we post-filter to reasonable digit count.
static RE_PHONE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\+?\d[\d\s().-]{6,}\d)\b").unwrap());

static RE_E164: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\+[1-9]\d{7,14}$").unwrap());
static RE_FR_LOCAL_CONTIGUOUS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^0\d{9}$").unwrap());
static RE_FR_LOCAL_GROUPED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^0\d(?:[ .]\d{2}){4}$").unwrap());
static RE_ES_LOCAL_CONTIGUOUS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[6-9]\d{8}$").unwrap());
static RE_ES_LOCAL_GROUPED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[6-9]\d{2}(?:[ .]\d{3}){2}$").unwrap());

static RE_IBAN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}[ ]?[A-Z0-9]{1,4}\b").unwrap()
});

// Candidate sequences; we validate with Luhn.
static RE_CARD_CANDIDATE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap());

static RE_KEY_VALUE: Lazy<Regex> = Lazy::new(|| {
    // Capture common key-value patterns for identifiers/cookies.
    Regex::new(
        r"(?ix)
        \b(
          user\s*id|userid|user_id|uid|
          user[_\s-]*device[_\s-]*technical[_\s-]*id|device[_\s-]*id|deviceid|device[_\s-]*identifier|device[_\s-]*token|
          advertising[_\s-]*id|ad[_\s-]*id|adid|maid|idfa|gaid|aaid|
          id\s*de\s*usuario|identificador\s*de\s*usuario|
          identifiant\s*utilisateur|id\s*utilisateur|
          benutzer\s*id|benutzerkennung|
          معرف\s*المستخدم|
          cookie|cookies|cookie\s*id|session\s*id|sessionid|sid|vec|vec_id|ملف\s*تعريف\s*الارتباط|جلسة
        )\b
        \s*(?:[:=]|->)\s*
        ([A-Za-z0-9._~\-+/=]{6,256})
        ",
    )
    .unwrap()
});

static RE_SECRET_KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        \b(
          api[_\s-]*key|x[_\s-]*api[_\s-]*key|apikey|
          access[_\s-]*token|refresh[_\s-]*token|id[_\s-]*token|auth[_\s-]*token|token|
          secret|client[_\s-]*secret|
          password|passwd|pwd
        )\b
        \s*(?:[:=]|->)\s*
        ([A-Za-z0-9._~\-+/=]{8,256})
        ",
    )
    .unwrap()
});

static RE_BEARER_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bbearer\s+([A-Za-z0-9._\-+/=]{12,512})\b").unwrap());

static RE_JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap()
});

static RE_PRIVATE_KEY_BLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?is)-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
    )
    .unwrap()
});

static RE_DEVICE_HINT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)\b(user[_\s-]*device[_\s-]*technical[_\s-]*id|device[_\s-]*id|deviceid|maid|idfa|gaid|aaid|advertising[_\s-]*id|ad[_\s-]*id)\b",
    )
    .unwrap()
});

static RE_GUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
        .unwrap()
});

static RE_GENERIC_KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)([A-Za-z0-9_\-.]{2,80})\s*(?:[:=]|->)\s*([^\n\r]{1,300})").unwrap()
});

static RE_ADDR_KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        \b(address|adresse|direccion|anschrift|street|rue|calle|strasse|stra\xDF?e|عنوان)\b
        \s*(?:[:=])\s*
        ([^\n\r]{8,140})
        ",
    )
    .unwrap()
});

static RE_POSTAL_KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        \b(code\s*postal|postal\s*code|postcode|zip\s*code|codigo\s*postal|plz|الرمز\s*البريدي)\b
        \s*(?:[:=])\s*
        ([A-Za-z0-9\-\s]{3,10})
        ",
    )
    .unwrap()
});

static RE_DOB_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
        \b(date\s*de\s*naissance|naissance|dob|date\s*of\s*birth|birth\s*date|geburtsdatum|fecha\s*de\s*nacimiento|تاريخ\s*الميلاد)\b
        [^\n\r]{0,25}
        (\d{4}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])|(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.]\d{2,4})
        ",
    )
    .unwrap()
});

static FILENAME_KEYWORDS: &[(&str, PiiCategory, i64)] = &[
    ("iban", PiiCategory::FileNameSignal, 6),
    ("rib", PiiCategory::FileNameSignal, 6),
    ("cni", PiiCategory::FileNameSignal, 6),
    ("carteidentite", PiiCategory::FileNameSignal, 6),
    ("passport", PiiCategory::FileNameSignal, 6),
    ("passeport", PiiCategory::FileNameSignal, 6),
    ("nir", PiiCategory::FileNameSignal, 8),
    ("ssn", PiiCategory::FileNameSignal, 8),
    ("payroll", PiiCategory::FileNameSignal, 6),
    ("paie", PiiCategory::FileNameSignal, 6),
    ("rh", PiiCategory::FileNameSignal, 4),
    ("medical", PiiCategory::FileNameSignal, 6),
    ("sante", PiiCategory::FileNameSignal, 6),
    ("assurance", PiiCategory::FileNameSignal, 5),
    ("bank", PiiCategory::FileNameSignal, 5),
    ("banque", PiiCategory::FileNameSignal, 5),
    ("facture", PiiCategory::FileNameSignal, 4),
    ("invoice", PiiCategory::FileNameSignal, 4),
    ("clients", PiiCategory::FileNameSignal, 4),
    ("export", PiiCategory::FileNameSignal, 4),
    ("userid", PiiCategory::FileNameSignal, 4),
    ("user_id", PiiCategory::FileNameSignal, 4),
    ("cookie", PiiCategory::FileNameSignal, 4),
    ("session", PiiCategory::FileNameSignal, 3),
    ("user_device_technical_id", PiiCategory::FileNameSignal, 7),
    ("device_id", PiiCategory::FileNameSignal, 6),
    ("deviceid", PiiCategory::FileNameSignal, 6),
    ("maid", PiiCategory::FileNameSignal, 6),
    ("idfa", PiiCategory::FileNameSignal, 6),
    ("gaid", PiiCategory::FileNameSignal, 6),
    ("aaid", PiiCategory::FileNameSignal, 6),
    ("api_key", PiiCategory::FileNameSignal, 6),
    ("apikey", PiiCategory::FileNameSignal, 6),
    ("security_key", PiiCategory::FileNameSignal, 6),
    ("secret", PiiCategory::FileNameSignal, 5),
    ("token", PiiCategory::FileNameSignal, 5),
    ("password", PiiCategory::FileNameSignal, 6),
    ("client_secret", PiiCategory::FileNameSignal, 8),
    ("api_key", PiiCategory::FileNameSignal, 8),
    ("access_token", PiiCategory::FileNameSignal, 8),
    ("cv", PiiCategory::FileNameSignal, 2),
    ("resume", PiiCategory::FileNameSignal, 2),
    ("adresse", PiiCategory::FileNameSignal, 3),
    ("address", PiiCategory::FileNameSignal, 3),
    ("postal", PiiCategory::FileNameSignal, 3),
    ("naissance", PiiCategory::FileNameSignal, 3),
    ("birth", PiiCategory::FileNameSignal, 3),
];

#[derive(Debug, Clone, Default)]
pub struct PiiMatches {
    pub by_category: BTreeMap<PiiCategory, Vec<String>>,
    pub filename_score_bonus: i64,
    pub filename_reasons: Vec<Reason>,
}

pub fn detect_in_filename(path: &str) -> PiiMatches {
    let filename = std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    let normalized = normalize_filename(filename);
    let mut out = PiiMatches::default();
    let mut seen_kw = BTreeSet::new();

    for (kw, _cat, score) in FILENAME_KEYWORDS {
        if filename_has_keyword(&normalized, kw) && seen_kw.insert(*kw) {
            out.filename_score_bonus += *score;
            out.filename_reasons.push(Reason {
                key: "reason.filenameKeyword".to_string(),
                vars: json!({ "keyword": kw }),
            });
            out.by_category
                .entry(PiiCategory::FileNameSignal)
                .or_default()
                .push(kw.to_string());
        }
    }
    out
}

fn normalize_filename(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
}

fn filename_has_keyword(normalized: &str, keyword: &str) -> bool {
    let phrase = keyword.replace(['_', '-'], " ").to_lowercase();
    let needle = format!(" {} ", phrase);
    let haystack = format!(" {} ", normalized);
    haystack.contains(&needle)
}

#[allow(unused_variables)]
pub fn detect_in_text(
    text: &str,
    enable_secret_detection: bool,
) -> BTreeMap<PiiCategory, Vec<String>> {
    let mut map = BTreeMap::new();
    detect_into(text, enable_secret_detection, &mut map);
    map
}

fn detect_into(
    text: &str,
    enable_secret_detection: bool,
    map: &mut BTreeMap<PiiCategory, Vec<String>>,
) {
    for m in RE_EMAIL.find_iter(text) {
        let email = m.as_str();
        if is_example_email(email) {
            continue;
        }
        push_limited(map, PiiCategory::Email, email);
    }
    for m in RE_IP.find_iter(text) {
        let ip = m.as_str();
        if is_relevant_public_ip(ip, text, m.start(), m.end()) {
            push_limited(map, PiiCategory::IpAddress, ip);
        }
    }
    for m in RE_IBAN.find_iter(text) {
        let candidate = m.as_str();
        if is_valid_iban(candidate) {
            push_limited(map, PiiCategory::Iban, candidate);
        }
    }
    for m in RE_PHONE.find_iter(text) {
        let candidate = m.as_str();
        if looks_like_phone(candidate) {
            push_limited(map, PiiCategory::Phone, candidate);
        }
    }
    for m in RE_CARD_CANDIDATE.find_iter(text) {
        let candidate = m.as_str();
        if let Some(digits) = digits_only(candidate) {
            if digits.len() >= 13
                && digits.len() <= 19
                && luhn_check(&digits)
                && looks_like_card_number(&digits)
            {
                push_limited(map, PiiCategory::CreditCard, &digits);
            }
        }
    }

    // Contextual fields (ids/cookies/accounts)
    for caps in RE_KEY_VALUE.captures_iter(text) {
        let key = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_lowercase();
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let cat = classify_key(&key);
        push_limited(map, cat, value);
    }

    for caps in RE_SECRET_KV.captures_iter(text) {
        let key = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_lowercase();
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if (looks_like_secret_value(value) && looks_like_secret_key(&key))
            || key.contains("password")
            || key == "pwd"
        {
            push_limited(map, PiiCategory::Secret, value);
        }
    }

    for caps in RE_BEARER_TOKEN.captures_iter(text) {
        let token = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if looks_like_secret_value(token) {
            push_limited(map, PiiCategory::Secret, token);
        }
    }

    if RE_PRIVATE_KEY_BLOCK.is_match(text) {
        push_limited(
            map,
            PiiCategory::Secret,
            "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----",
        );
    }

    if enable_secret_detection {
        for m in RE_JWT.find_iter(text) {
            let value = m.as_str();
            if looks_like_secret_value(value) && !likely_calendar_noise(value, text) {
                push_limited(map, PiiCategory::Secret, value);
            }
        }

        // Enhanced secret detection from secrets module
        for secret in crate::secrets::detect_secrets(text) {
            if !likely_calendar_noise(&secret, text) {
                push_limited(map, PiiCategory::Secret, &secret);
            }
        }
    }

    if RE_DEVICE_HINT.is_match(text) {
        for m in RE_GUID.find_iter(text).take(200) {
            push_limited(map, PiiCategory::UserId, m.as_str());
        }
    }

    // Address and postal code as key-value (signal with value)
    for caps in RE_ADDR_KV.captures_iter(text) {
        let key = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_lowercase();
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if looks_like_address_value(&key, value) {
            push_limited(map, PiiCategory::Address, value.trim());
        }
    }
    for caps in RE_POSTAL_KV.captures_iter(text) {
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        push_limited(map, PiiCategory::PostalCode, value.trim());
    }
    for caps in RE_DOB_CONTEXT.captures_iter(text) {
        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        push_limited(map, PiiCategory::DateOfBirth, value.trim());
    }
}

pub fn detect_custom(
    text: &str,
    filename: &str,
    detectors: &[CompiledCustomDetector],
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for d in detectors {
        let mut matched = false;

        if let Some(rx) = &d.filename_regex {
            if rx.is_match(filename) {
                out.entry(d.name.clone())
                    .or_default()
                    .push(filename.to_string());
                matched = true;
            }
        }

        if let Some(rx) = &d.field_name_regex {
            for caps in RE_GENERIC_KV.captures_iter(text).take(300) {
                let key = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                if rx.is_match(key) {
                    out.entry(d.name.clone())
                        .or_default()
                        .push(value.to_string());
                    matched = true;
                }
            }
        }

        if let Some(rx) = &d.value_regex {
            for m in rx.find_iter(text).take(300) {
                out.entry(d.name.clone())
                    .or_default()
                    .push(m.as_str().to_string());
                matched = true;
            }
        }

        if matched {
            let values = out.entry(d.name.clone()).or_default();
            if values.len() > 250 {
                values.truncate(250);
            }
        }
    }
    out
}

fn classify_key(key: &str) -> PiiCategory {
    if key.contains("cookie") || key.contains("session") || key == "sid" {
        return PiiCategory::Cookie;
    }
    if key.contains("vec") {
        return PiiCategory::Cookie;
    }
    if key.contains("device")
        || key.contains("advertising")
        || key.contains("adid")
        || key.contains("maid")
        || key.contains("idfa")
        || key.contains("gaid")
        || key.contains("aaid")
    {
        return PiiCategory::UserId;
    }
    // default
    PiiCategory::UserId
}

fn looks_like_secret_key(key: &str) -> bool {
    let normalized = key.to_lowercase().replace(['_', '-'], "");

    // Exact patterns for secrets
    let patterns = [
        "apikey",
        "api_key",
        "api-key",
        "x-api-key",
        "secret",
        "secretkey",
        "secret_key",
        "secret-key",
        "privatekey",
        "private_key",
        "private-key",
        "token",
        "accesstoken",
        "access_token",
        "access-token",
        "refreshtoken",
        "refresh_token",
        "refresh-token",
        "authtoken",
        "auth_token",
        "auth-token",
        "idtoken",
        "id_token",
        "id-token",
        "password",
        "passwd",
        "pwd",
        "authorization",
        "bearer",
        "clientsecret",
        "client_secret",
        "client-secret",
        "appsecret",
        "app_secret",
        "app-secret",
        "encryptionkey",
        "encryption_key",
        "encryption-key",
        "sessiontoken",
        "session_token",
        "session-token",
        // AWS
        "awsaccesskeyid",
        "awssecretaccesskey",
        "awsacceskeyid",
        "awssecretkey",
        "awssessiontoken",
        "awstoken",
        "awsregion",
        // Azure
        "azureclientid",
        "azureclientsecret",
        "azuretenantid",
        "azuresubscriptionid",
        "azurestoragekey",
        "azurestorageaccount",
        "azureusername",
        "azurepassword",
        // GCP
        "googleapplicationcredentials",
        "googleapikey",
        "googleclientid",
        "googleclientsecret",
        "gcpprojectid",
        "gcpserviceaccountkey",
        // GitHub/GitLab
        "githubtoken",
        "githubpat",
        "gitlabtoken",
    ];

    patterns.iter().any(|p| normalized == *p)
        || normalized.ends_with("_key")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_token")
        || normalized.ends_with("_password")
        || normalized.ends_with("_pwd")
}

fn likely_calendar_noise(value: &str, text: &str) -> bool {
    if !(text.contains("BEGIN:VCALENDAR") || text.contains("BEGIN:VEVENT")) {
        return false;
    }
    value.len() < 24
}

fn looks_like_address_value(key: &str, value: &str) -> bool {
    let bad_keys = [
        "arrivee",
        "arrival",
        "ticket",
        "information",
        "informations",
    ];
    if bad_keys.iter().any(|k| key.contains(k)) {
        return false;
    }
    let v = value.trim().to_lowercase();
    if v.len() < 8 {
        return false;
    }
    let street_words = [
        " rue ",
        " avenue ",
        " av ",
        " boulevard ",
        " bd ",
        " street ",
        " road ",
        " lane ",
        " drive ",
        " chemin ",
        " impasse ",
        " allée ",
        " alley ",
        " strasse ",
    ];
    let padded = format!(" {} ", v);
    let has_street_word = street_words.iter().any(|w| padded.contains(w));
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    has_street_word && has_digit
}

fn is_relevant_public_ip(ip: &str, full_text: &str, match_start: usize, match_end: usize) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse::<u8>().ok()).collect();
    if parts.len() != 4 {
        return false;
    }

    let [a, b, c, d] = [parts[0], parts[1], parts[2], parts[3]];
    let _ = d;

    if a == 127
        || a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
    {
        return false;
    }

    // SVG/XML graphics can contain dotted numeric patterns that look like IPv4.
    // Require nearby network context to keep false positives low there.
    if looks_like_svg_markup(full_text)
        && !has_network_context_near(full_text, match_start, match_end)
    {
        return false;
    }

    // Exclude likely section numbering like 1.2.3.1 in docs.
    if a <= 31 && b <= 31 && c <= 31 && d <= 31 {
        if !has_network_context_near(full_text, match_start, match_end) {
            return false;
        }
    }

    true
}

fn looks_like_svg_markup(full_text: &str) -> bool {
    let lower = full_text.to_lowercase();
    lower.contains("<svg")
        || lower.contains("</svg>")
        || lower.contains("xmlns=\"http://www.w3.org/2000/svg\"")
}

fn has_network_context_near(full_text: &str, match_start: usize, match_end: usize) -> bool {
    let mut left = match_start.saturating_sub(64);
    while left > 0 && !full_text.is_char_boundary(left) {
        left -= 1;
    }
    let mut right = (match_end + 64).min(full_text.len());
    while right < full_text.len() && !full_text.is_char_boundary(right) {
        right += 1;
    }
    let local = full_text[left..right].to_lowercase();

    let tokens: Vec<&str> = local
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();

    tokens.iter().any(|t| {
        matches!(
            *t,
            "ip" | "ipv4"
                | "ipv6"
                | "hostname"
                | "dns"
                | "gateway"
                | "router"
                | "server"
                | "clientip"
                | "remoteaddr"
                | "remoteip"
                | "addr"
        )
    })
}

fn looks_like_secret_value(value: &str) -> bool {
    let v = value.trim();
    if v.len() < 10 {
        return false;
    }
    if v.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if has_long_repeating_run(v, 8) {
        return false;
    }
    let mixed = v.chars().any(|c| c.is_ascii_uppercase())
        && v.chars().any(|c| c.is_ascii_lowercase())
        && (v.chars().any(|c| c.is_ascii_digit()) || v.contains('-') || v.contains('_'));
    mixed || v.len() >= 24
}

fn push_limited(map: &mut BTreeMap<PiiCategory, Vec<String>>, cat: PiiCategory, value: &str) {
    let values = map.entry(cat).or_default();
    if values.len() >= 250 {
        return;
    }
    values.push(value.to_string());
}

fn digits_only(s: &str) -> Option<String> {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            out.push(ch);
        } else if ch == ' ' || ch == '-' {
            continue;
        } else {
            // ignore other chars
            continue;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn looks_like_phone(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.contains('/') {
        return false;
    }

    if RE_E164.is_match(trimmed) {
        let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
        return distinct_digit_count(&digits) >= 4
            && !has_long_repeating_run(&digits, 6)
            && !is_sequential_number(&digits);
    }

    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    let len = digits.len();
    if !(8..=12).contains(&len) {
        return false;
    }
    if distinct_digit_count(&digits) < 4 {
        return false;
    }
    if has_long_repeating_run(&digits, 6) || is_sequential_number(&digits) {
        return false;
    }

    match user_phone_locale() {
        PhoneLocale::Fr => {
            RE_FR_LOCAL_CONTIGUOUS.is_match(trimmed) || RE_FR_LOCAL_GROUPED.is_match(trimmed)
        }
        PhoneLocale::Es => {
            RE_ES_LOCAL_CONTIGUOUS.is_match(trimmed) || RE_ES_LOCAL_GROUPED.is_match(trimmed)
        }
        // For other locales, keep local-mode strict: digits only with plausible lengths.
        _ => trimmed.chars().all(|c| c.is_ascii_digit()) && (9..=11).contains(&len),
    }
}

#[derive(Debug, Clone, Copy)]
enum PhoneLocale {
    Fr,
    Es,
    De,
    Other,
}

fn user_phone_locale() -> PhoneLocale {
    let raw = std::env::var("LC_ALL")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("LANG").ok())
        .unwrap_or_default()
        .to_lowercase();

    if raw.starts_with("fr") {
        return PhoneLocale::Fr;
    }
    if raw.starts_with("es") {
        return PhoneLocale::Es;
    }
    if raw.starts_with("de") {
        return PhoneLocale::De;
    }
    PhoneLocale::Other
}

fn luhn_check(number: &str) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for ch in number.chars().rev() {
        let mut n = match ch.to_digit(10) {
            Some(v) => v,
            None => return false,
        };
        if alt {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

fn looks_like_card_number(number: &str) -> bool {
    let bytes = number.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if number.chars().all(|c| c == bytes[0] as char) {
        return false;
    }
    if distinct_digit_count(number) < 4 {
        return false;
    }
    if has_long_repeating_run(number, 6) || is_sequential_number(number) {
        return false;
    }

    let len = number.len();
    let starts_with = |prefix: &str| number.starts_with(prefix);
    let prefix2 = number.get(0..2).and_then(|s| s.parse::<u32>().ok());
    let prefix3 = number.get(0..3).and_then(|s| s.parse::<u32>().ok());
    let prefix4 = number.get(0..4).and_then(|s| s.parse::<u32>().ok());

    if starts_with("4") && matches!(len, 13 | 16 | 19) {
        return true;
    }
    if len == 16 {
        if let Some(p2) = prefix2 {
            if (51..=55).contains(&p2) {
                return true;
            }
        }
        if let Some(p4) = prefix4 {
            if (2221..=2720).contains(&p4) {
                return true;
            }
        }
    }
    if len == 15 && (starts_with("34") || starts_with("37")) {
        return true;
    }
    if matches!(len, 16 | 19)
        && (starts_with("6011")
            || starts_with("65")
            || prefix3.map(|p| (644..=649).contains(&p)).unwrap_or(false))
    {
        return true;
    }
    if len == 16 && prefix4.map(|p| (3528..=3589).contains(&p)).unwrap_or(false) {
        return true;
    }
    if len == 14
        && (prefix3.map(|p| (300..=305).contains(&p)).unwrap_or(false)
            || starts_with("36")
            || starts_with("38")
            || starts_with("39"))
    {
        return true;
    }

    false
}

fn distinct_digit_count(number: &str) -> usize {
    let mut seen = [false; 10];
    for ch in number.chars() {
        if let Some(d) = ch.to_digit(10) {
            seen[d as usize] = true;
        }
    }
    seen.into_iter().filter(|v| *v).count()
}

fn has_long_repeating_run(number: &str, min_run: usize) -> bool {
    let mut prev: Option<char> = None;
    let mut run = 0usize;
    for ch in number.chars() {
        if Some(ch) == prev {
            run += 1;
        } else {
            prev = Some(ch);
            run = 1;
        }
        if run >= min_run {
            return true;
        }
    }
    false
}

fn is_sequential_number(number: &str) -> bool {
    let bytes = number.as_bytes();
    if bytes.len() < 6 {
        return false;
    }

    let mut asc = true;
    let mut desc = true;
    for pair in bytes.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if b != a.saturating_add(1) {
            asc = false;
        }
        if b.saturating_add(1) != a {
            desc = false;
        }
    }
    asc || desc
}

fn is_valid_iban(iban: &str) -> bool {
    // IBAN validation (mod 97).
    let s = iban
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase();
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut mod97 = 0u32;
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            mod97 = (mod97 * 10 + (ch as u8 - b'0') as u32) % 97;
        } else if ch.is_ascii_uppercase() {
            let val = (ch as u8 - b'A') as u32 + 10;
            // append two digits
            mod97 = (mod97 * 10 + (val / 10)) % 97;
            mod97 = (mod97 * 10 + (val % 10)) % 97;
        } else {
            return false;
        }
    }
    mod97 == 1
}

pub fn redact_value(cat: PiiCategory, value: &str) -> String {
    match cat {
        PiiCategory::Email => redact_email(value),
        PiiCategory::Iban => redact_iban(value),
        PiiCategory::CreditCard => redact_last(value, 4),
        PiiCategory::Phone => redact_phone(value),
        PiiCategory::IpAddress => redact_prefix(value, 7),
        PiiCategory::Address => redact_prefix(value, 10),
        PiiCategory::PostalCode => redact_prefix(value, 2),
        PiiCategory::DateOfBirth => redact_prefix(value, 4),
        PiiCategory::Cookie => redact_last(value, 4),
        PiiCategory::UserId => redact_last(value, 4),
        PiiCategory::Secret => redact_last(value, 4),
        PiiCategory::FileNameSignal => redact_prefix(value, 12),
        PiiCategory::WeakArchiveEncryption => value.to_string(),
    }
}

fn redact_prefix(s: &str, keep: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i < keep {
            out.push(ch);
        } else {
            out.push('*');
        }
    }
    out
}

fn redact_last(s: &str, keep_last: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= keep_last {
        return "*".repeat(chars.len().max(1));
    }
    let mask_len = chars.len() - keep_last;
    let mut out = "*".repeat(mask_len);
    for ch in &chars[mask_len..] {
        out.push(*ch);
    }
    out
}

fn redact_phone(s: &str) -> String {
    let total_digits = s.chars().filter(|c| c.is_ascii_digit()).count();
    if total_digits <= 4 {
        return s
            .chars()
            .map(|c| if c.is_ascii_digit() { '*' } else { c })
            .collect();
    }

    let mut seen_digits = 0usize;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            let keep = seen_digits < 2 || seen_digits >= total_digits.saturating_sub(2);
            out.push(if keep { ch } else { '*' });
            seen_digits += 1;
        } else {
            out.push(ch);
        }
    }
    out
}

fn redact_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return redact_prefix(email, 6);
    }
    let local = parts[0];
    let domain = parts[1];
    let local_prefix: String = local.chars().take(3).collect();
    format!("{}***@{}", local_prefix, domain)
}

fn is_example_email(email: &str) -> bool {
    let lower = email.to_lowercase();
    lower.ends_with("@example.com")
        || lower.ends_with("@example.org")
        || lower.ends_with("@example.net")
        || lower.ends_with("@test.com")
        || lower.ends_with("@localhost")
}

fn redact_iban(iban: &str) -> String {
    let clean = iban
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase();
    if clean.len() < 8 {
        return redact_prefix(&clean, 4);
    }
    let start: String = clean.chars().take(4).collect();
    let end: String = clean
        .chars()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!(
        "{}{}{}",
        start,
        "*".repeat(clean.len().saturating_sub(7)),
        end
    )
}

pub fn summarize_matches(
    map: &BTreeMap<PiiCategory, Vec<String>>,
    include_redacted_examples: bool,
) -> Vec<PiiFinding> {
    let mut out = Vec::new();
    for (cat, values) in map {
        let count = values.len();
        let mut examples = Vec::new();
        if include_redacted_examples {
            for v in values.iter().take(5) {
                examples.push(redact_value(cat.clone(), v));
            }
        }
        out.push(PiiFinding {
            category: cat.clone(),
            count,
            redacted_examples: examples,
        });
    }
    out
}

pub fn reveal_matches(map: &BTreeMap<PiiCategory, Vec<String>>) -> RevealedFindings {
    let mut out = Vec::new();
    for (cat, values) in map {
        out.push(RevealedCategory {
            category: cat.clone(),
            values: values
                .iter()
                .take(100)
                .map(|v| RevealedValue {
                    value: v.clone(),
                    is_ignored: false,
                })
                .collect(),
        });
    }
    RevealedFindings { by_category: out }
}

pub fn score_from_matches(
    matches: &BTreeMap<PiiCategory, Vec<String>>,
    filename_bonus: i64,
    weak_zip_encryption: bool,
) -> (i64, Vec<Reason>) {
    let mut score: i64 = 0;
    let mut reasons: Vec<Reason> = Vec::new();

    for (cat, values) in matches {
        let c = values.len() as i64;
        let mut weight = builtin_weight(cat);

        // If values look like hashes (opaque identifiers), reduce weight.
        if matches!(cat, PiiCategory::Cookie | PiiCategory::UserId) {
            let sample = values.iter().take(10);
            let mut hashy = 0;
            let mut total = 0;
            for v in sample {
                total += 1;
                if looks_like_hash(v) {
                    hashy += 1;
                }
            }
            if total > 0 && hashy * 2 >= total {
                weight = (weight * 60) / 100;
                reasons.push(Reason {
                    key: "reason.hashLike".to_string(),
                    vars: json!({ "category": format_category(cat) }),
                });
            }
        }

        if c > 0 {
            let add = weight * (1 + (c.saturating_sub(1)).min(20));
            score += add;
            reasons.push(Reason {
                key: "reason.categoryCount".to_string(),
                vars: json!({ "category": format_category(cat), "count": c }),
            });
        }
    }

    if filename_bonus > 0 {
        score += filename_bonus;
        reasons.push(Reason {
            key: "reason.filenameSignal".to_string(),
            vars: json!({ "bonus": filename_bonus }),
        });
    }

    if weak_zip_encryption {
        score += 10;
        reasons.push(Reason {
            key: "reason.weakZipEncryption".to_string(),
            vars: json!({}),
        });
    }

    (score, reasons)
}

fn looks_like_hash(value: &str) -> bool {
    let v = value.trim();
    if v.len() < 16 {
        return false;
    }
    let is_hex = v.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex && matches!(v.len(), 32 | 40 | 64) {
        return true;
    }

    // base64 / base64url-ish
    let b64ish = v.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+' || c == '/' || c == '='
    });
    if b64ish && v.len() >= 22 {
        let digits = v.chars().filter(|c| c.is_ascii_digit()).count();
        // heuristic: mixed charset, not only digits
        return digits * 3 < v.len();
    }
    false
}

pub fn risk_level_from_score(score: i64) -> crate::types::RiskLevel {
    use crate::types::RiskLevel::*;
    if score >= 55 {
        Critical
    } else if score >= 25 {
        High
    } else if score >= 10 {
        Medium
    } else {
        Low
    }
}

pub fn builtin_risk_level(cat: &PiiCategory) -> crate::types::RiskLevel {
    let weight = builtin_weight(cat);
    if weight >= 6 {
        crate::types::RiskLevel::High
    } else if weight >= 3 {
        crate::types::RiskLevel::Medium
    } else {
        crate::types::RiskLevel::Low
    }
}

pub fn risk_level_from_evidence(
    score: i64,
    max_level: crate::types::RiskLevel,
    high_type_count: usize,
) -> crate::types::RiskLevel {
    use crate::types::RiskLevel;

    let mut level = risk_level_from_score(score);
    if level == RiskLevel::Critical && high_type_count < 2 {
        level = RiskLevel::High;
    }

    if level > max_level {
        max_level
    } else {
        level
    }
}

fn builtin_weight(cat: &PiiCategory) -> i64 {
    match cat {
        PiiCategory::Email => 2,
        PiiCategory::Phone => 2,
        PiiCategory::Iban => 7,
        PiiCategory::CreditCard => 8,
        PiiCategory::IpAddress => 1,
        PiiCategory::Address => 4,
        PiiCategory::PostalCode => 2,
        PiiCategory::DateOfBirth => 6,
        PiiCategory::Cookie => 4,
        PiiCategory::UserId => 3,
        PiiCategory::Secret => 12,
        PiiCategory::FileNameSignal => 3,
        PiiCategory::WeakArchiveEncryption => 8,
    }
}

fn format_category(cat: &PiiCategory) -> &'static str {
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
