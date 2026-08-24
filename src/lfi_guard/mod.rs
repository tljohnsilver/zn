//! Local File Inclusion (LFI) Guard Module
//!
//! High-performance detection of path traversal and sensitive file access patterns.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::sync::OnceLock;

/// Static Aho-Corasick automaton for LFI patterns
static LFI_AUTOMATON: OnceLock<AhoCorasick> = OnceLock::new();

/// Common LFI and path traversal patterns
const LFI_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/proc/self",
    "/var/log/",
    "C:\\Windows\\",
    "C:/Windows/",
    ".ssh/id_rsa",
    ".ssh/id_dsa",
    ".ssh/authorized_keys",
    "config.php",
    "wp-config.php",
    ".env",
    ".git/",
    "htaccess",
];

/// Initialize the Aho-Corasick automaton
fn get_automaton() -> &'static AhoCorasick {
    LFI_AUTOMATON.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(LFI_PATTERNS)
            .expect("Failed to build LFI pattern automaton")
    })
}

/// Result of LFI detection
#[derive(Debug, Clone)]
pub struct LfiDetectionResult {
    /// Whether LFI was detected
    pub is_attack: bool,
    /// The pattern that matched (if any)
    pub matched_pattern: Option<String>,
}

/// Check if input contains LFI patterns
pub fn detect_lfi(input: &str) -> LfiDetectionResult {
    let automaton = get_automaton();
    if let Some(mat) = automaton.find(input) {
        return LfiDetectionResult {
            is_attack: true,
            matched_pattern: Some(LFI_PATTERNS[mat.pattern().as_usize()].to_string()),
        };
    }

    LfiDetectionResult {
        is_attack: false,
        matched_pattern: None,
    }
}

/// Quick check if input contains LFI patterns
#[inline]
pub fn contains_lfi(input: &str) -> bool {
    get_automaton().is_match(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal() {
        assert!(contains_lfi("../../../etc/passwd"));
        assert!(contains_lfi("....\\\\....\\\\windows\\\\system32"));
        assert!(contains_lfi("file:///../../../"));
    }

    #[test]
    fn test_sensitive_files() {
        assert!(contains_lfi("Read /etc/passwd for user info"));
        assert!(contains_lfi("Check /etc/shadow for hashes"));
        assert!(contains_lfi("Look in /proc/self/environ"));
        assert!(contains_lfi("cat /var/log/syslog"));
    }

    #[test]
    fn test_windows_paths() {
        assert!(contains_lfi("C:\\Windows\\System32\\config"));
        assert!(contains_lfi("C:/Windows/System32/drivers"));
    }

    #[test]
    fn test_dot_files() {
        assert!(contains_lfi("Check .ssh/id_rsa for keys"));
        assert!(contains_lfi("Read .git/config"));
        assert!(contains_lfi("Load .env for secrets"));
        assert!(contains_lfi(".htaccess rules"));
    }

    #[test]
    fn test_config_files() {
        assert!(contains_lfi("Include wp-config.php"));
        assert!(contains_lfi("Look at config.php"));
    }

    #[test]
    fn test_safe_input() {
        assert!(!contains_lfi("Read the README.md file"));
        assert!(!contains_lfi("Check the documentation"));
        assert!(!contains_lfi("Create a new folder called 'data'"));
        assert!(!contains_lfi("Normal file: report.pdf"));
    }

    #[test]
    fn test_detection_result() {
        let result = detect_lfi("Show me /etc/passwd");
        assert!(result.is_attack);
        assert_eq!(result.matched_pattern, Some("/etc/passwd".to_string()));

        let safe_result = detect_lfi("Hello world");
        assert!(!safe_result.is_attack);
        assert!(safe_result.matched_pattern.is_none());
    }
}
