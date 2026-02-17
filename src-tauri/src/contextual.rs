#![allow(dead_code)]

use crate::types::EntitySetting;
use once_cell::sync::Lazy;
use regex::Regex;

static RE_PERSON: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}").unwrap());

static RE_ORGANIZATION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Inc|Ltd|Corp|SA|GmbH|LLC|BV|SARL|EURL|PLC)")
        .unwrap()
});

static RE_LOCATION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*").unwrap());

pub struct ContextualAnalyzer {
    settings: EntitySetting,
}

impl ContextualAnalyzer {
    pub fn new(settings: EntitySetting) -> Self {
        Self { settings }
    }

    pub fn analyze(&self, text: &str) -> Vec<ContextualDetection> {
        let entity_type = self.settings.entity_type.as_str();

        match entity_type {
            "person" => self.analyze_person(text),
            "organization" => self.analyze_organization(text),
            "location" => self.analyze_location(text),
            _ => Vec::new(),
        }
    }

    fn analyze_person(&self, text: &str) -> Vec<ContextualDetection> {
        let mut detections = Vec::new();

        for mat in RE_PERSON.find_iter(text) {
            let matched_text = mat.as_str();

            // Skip if looks like a title or common word
            if self.is_likely_name(matched_text) {
                let context = self.extract_context(text, mat.start(), mat.end());
                let score = self.calculate_score(&context, matched_text.len());

                if score >= self.settings.threshold.unwrap_or(0.75) {
                    detections.push(ContextualDetection {
                        entity_type: self.settings.entity_type.clone(),
                        text: matched_text.to_string(),
                        span: (mat.start(), mat.end()),
                        confidence: score,
                    });
                }
            }
        }

        detections
    }

    fn analyze_organization(&self, text: &str) -> Vec<ContextualDetection> {
        let mut detections = Vec::new();

        for mat in RE_ORGANIZATION.find_iter(text) {
            let matched_text = mat.as_str();
            let context = self.extract_context(text, mat.start(), mat.end());
            let score = self.calculate_score(&context, matched_text.len());

            // Boost score if has organization suffix
            let score = if self.has_org_suffix(matched_text) {
                (score + 0.15).min(1.0)
            } else {
                score
            };

            if score >= self.settings.threshold.unwrap_or(0.70) {
                detections.push(ContextualDetection {
                    entity_type: self.settings.entity_type.clone(),
                    text: matched_text.to_string(),
                    span: (mat.start(), mat.end()),
                    confidence: score,
                });
            }
        }

        detections
    }

    fn analyze_location(&self, text: &str) -> Vec<ContextualDetection> {
        let mut detections = Vec::new();

        for mat in RE_LOCATION.find_iter(text) {
            let matched_text = mat.as_str();

            // Skip common non-location words
            if self.is_likely_location(matched_text) {
                let context = self.extract_context(text, mat.start(), mat.end());
                let score = self.calculate_score(&context, matched_text.len());

                if score >= self.settings.threshold.unwrap_or(0.65) {
                    detections.push(ContextualDetection {
                        entity_type: self.settings.entity_type.clone(),
                        text: matched_text.to_string(),
                        span: (mat.start(), mat.end()),
                        confidence: score,
                    });
                }
            }
        }

        detections
    }

    fn extract_context<'a>(&self, text: &'a str, start: usize, end: usize) -> Context<'a> {
        // Get 3 words before and after
        let before_text = &text[..start];
        let after_text = &text[end..];

        let words_before: Vec<&'a str> = before_text
            .split_whitespace()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        let words_after: Vec<&'a str> = after_text.split_whitespace().take(5).collect();

        Context {
            words_before,
            words_after,
        }
    }

    fn calculate_score<'a>(&self, context: &Context<'a>, text_len: usize) -> f64 {
        let mut score = 0.5; // Base score

        // Positive indicators
        if let Some(positive) = &self.settings.positive_indicators {
            let positive_words: Vec<&str> = positive.split(',').map(|s| s.trim()).collect();
            let pos_matches = context
                .words_before
                .iter()
                .chain(context.words_after.iter())
                .filter(|&&w| {
                    positive_words
                        .iter()
                        .any(|&p| w.to_lowercase().contains(&p.to_lowercase()))
                })
                .count();
            score += (pos_matches as f64 * 0.1).min(0.35);
        }

        // Negative indicators (penalty)
        if let Some(negative) = &self.settings.negative_indicators {
            let negative_words: Vec<&str> = negative.split(',').map(|s| s.trim()).collect();
            let neg_matches = context
                .words_before
                .iter()
                .chain(context.words_after.iter())
                .filter(|&&w| {
                    negative_words
                        .iter()
                        .any(|&n| w.to_lowercase().contains(&n.to_lowercase()))
                })
                .count();
            score -= (neg_matches as f64 * 0.1).min(0.25);
        }

        // Length factor (reasonable name length)
        if (5..=40).contains(&text_len) {
            score += 0.1;
        }

        score.clamp(0.0, 1.0)
    }

    fn is_likely_name(&self, text: &str) -> bool {
        let common_non_names = [
            "The", "This", "That", "These", "Those", "Product", "Feature", "Version", "Module",
            "Example", "Sample", "Test", "Demo", "Contact", "Signed", "For", "More",
        ];

        !common_non_names.iter().any(|&word| text.starts_with(word))
    }

    fn has_org_suffix(&self, text: &str) -> bool {
        let suffixes = [
            "Inc", "Ltd", "Corp", "SA", "GmbH", "LLC", "BV", "SARL", "PLC",
        ];
        suffixes.iter().any(|&suffix| text.ends_with(suffix))
    }

    fn is_likely_location(&self, text: &str) -> bool {
        let common_non_locations = [
            "Product",
            "Feature",
            "Version",
            "Module",
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];

        !common_non_locations.iter().any(|&word| text.contains(word))
    }
}

#[derive(Debug, Clone)]
pub struct ContextualDetection {
    pub entity_type: String,
    pub text: String,
    pub span: (usize, usize),
    pub confidence: f64,
}

#[allow(dead_code)]
struct Context<'a> {
    words_before: Vec<&'a str>,
    words_after: Vec<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_person_detection_with_context() {
        // Test that regex matches
        let text = "signed by John Smith for more information";
        let matches: Vec<_> = RE_PERSON.find_iter(text).collect();
        assert!(!matches.is_empty(), "Regex should match John Smith");
        assert_eq!(matches[0].as_str(), "John Smith");

        // Now test with analyzer
        let settings = EntitySetting {
            entity_type: "person".to_string(),
            entity_category: "contextual".to_string(),
            enabled: true,
            locale_requirement: None,
            positive_indicators: Some("contact,name,author,signed by".to_string()),
            negative_indicators: Some("product,feature".to_string()),
            threshold: Some(0.60),
        };

        let analyzer = ContextualAnalyzer::new(settings);
        let detections = analyzer.analyze(text);

        assert!(!detections.is_empty(), "Should detect person name");
        assert_eq!(detections[0].text, "John Smith");
    }

    #[test]
    fn test_organization_detection() {
        let settings = EntitySetting {
            entity_type: "organization".to_string(),
            entity_category: "contextual".to_string(),
            enabled: true,
            locale_requirement: None,
            positive_indicators: Some("company,inc,ltd".to_string()),
            negative_indicators: Some("product".to_string()),
            threshold: Some(0.70),
        };

        let analyzer = ContextualAnalyzer::new(settings);
        let text = "Company: Acme Corp Inc provides services";
        let detections = analyzer.analyze(text);

        assert!(!detections.is_empty());
    }

    #[test]
    fn test_low_confidence_filtered() {
        let settings = EntitySetting {
            entity_type: "person".to_string(),
            entity_category: "contextual".to_string(),
            enabled: true,
            locale_requirement: None,
            positive_indicators: Some("contact".to_string()),
            negative_indicators: Some("product,feature".to_string()),
            threshold: Some(0.75),
        };

        let analyzer = ContextualAnalyzer::new(settings);
        // No context words, should be filtered
        let text = "Product Feature";
        let detections = analyzer.analyze(text);

        assert!(detections.is_empty());
    }
}
