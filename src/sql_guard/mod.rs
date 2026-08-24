//! SQL Injection Guard Module
//!
//! High-performance SQL injection detection using Aho-Corasick algorithm.
//! Provides O(n) pattern matching for 67+ attack patterns.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::sync::OnceLock;

/// Static Aho-Corasick automaton for SQL injection patterns
static SQL_AUTOMATON: OnceLock<AhoCorasick> = OnceLock::new();

/// SQL injection attack patterns
const SQL_PATTERNS: &[&str] = &[
    // Basic injection patterns
    "' or '1'='1",
    "' or 1=1",
    "\" or \"1\"=\"1",
    "\" or 1=1",
    "or 1=1--",
    "or 1=1#",
    "' or ''='",
    "' or 'x'='x",
    "') or ('1'='1",
    "') or ('1'='1",
    "') or ('x'='x",
    // Generic Tautologies (High risk of false positives, but safer)
    " or 1=1",
    " or 0=0",
    " or true",
    // Comment-based attacks
    "--",
    "/*",
    "*/",
    "#",
    // Union-based attacks
    "union select",
    "union all select",
    "union distinct select",
    // Destructive commands
    "drop table",
    "drop database",
    "truncate table",
    "delete from",
    "insert into",
    "update set",
    // Information extraction
    "information_schema",
    "sysobjects",
    "syscolumns",
    "pg_tables",
    "pg_catalog",
    // Function-based attacks
    "concat(",
    "char(",
    "chr(",
    "substr(",
    "substring(",
    "ascii(",
    "hex(",
    "unhex(",
    "benchmark(",
    "sleep(",
    "waitfor delay",
    "pg_sleep(",
    // Stacked queries
    "; drop",
    "; delete",
    "; insert",
    "; update",
    "; truncate",
    "; exec",
    "; execute",
    // Blind SQL injection
    "' and '1'='1",
    "' and '1'='2",
    "and 1=1",
    "and 1=2",
    "' and sleep(",
    "' and benchmark(",
    // Error-based
    "extractvalue(",
    "updatexml(",
    "floor(rand(",
    // Auth bypass
    "admin'--",
    "admin'#",
    "' or 'a'='a",
    "') or 'a'='a",
    // Second-order
    "'; waitfor delay",
];

/// Initialize the Aho-Corasick automaton
fn get_automaton() -> &'static AhoCorasick {
    SQL_AUTOMATON.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(SQL_PATTERNS)
            .expect("Failed to build SQL injection pattern automaton")
    })
}

/// Result of SQL injection detection
#[derive(Debug, Clone)]
pub struct SqlDetectionResult {
    /// Whether SQL injection was detected
    pub is_attack: bool,
    /// The pattern that matched (if any)
    pub matched_pattern: Option<String>,
    /// Position in input where pattern was found
    pub position: Option<usize>,
}

/// Check if input contains SQL injection patterns
///
/// Uses Aho-Corasick algorithm for O(n) multi-pattern matching,
/// much faster than checking each pattern individually.
///
/// # Arguments
/// * `input` - The string to check for SQL injection
///
/// # Returns
/// Detection result with matched pattern info
pub fn detect_sql_injection(input: &str) -> SqlDetectionResult {
    let automaton = get_automaton();

    // Find first match
    if let Some(mat) = automaton.find(input) {
        SqlDetectionResult {
            is_attack: true,
            matched_pattern: Some(SQL_PATTERNS[mat.pattern().as_usize()].to_string()),
            position: Some(mat.start()),
        }
    } else {
        SqlDetectionResult {
            is_attack: false,
            matched_pattern: None,
            position: None,
        }
    }
}

/// Quick check if input contains SQL injection patterns
///
/// Faster than `detect_sql_injection` when you don't need pattern details.
#[inline]
pub fn contains_sql_injection(input: &str) -> bool {
    get_automaton().is_match(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_injection() {
        assert!(contains_sql_injection("' or '1'='1"));
        assert!(contains_sql_injection("1' OR '1'='1' --"));
        assert!(contains_sql_injection("admin'--"));
    }

    #[test]
    fn test_union_attack() {
        assert!(contains_sql_injection("1 UNION SELECT * FROM users"));
        assert!(contains_sql_injection("1' union all select null,null--"));
    }

    #[test]
    fn test_destructive_commands() {
        assert!(contains_sql_injection("'; DROP TABLE users;--"));
        assert!(contains_sql_injection("1; DELETE FROM sessions"));
    }

    #[test]
    fn test_safe_input() {
        assert!(!contains_sql_injection(
            "SELECT name FROM products WHERE id = 1"
        ));
        assert!(!contains_sql_injection("normal user input"));
        assert!(!contains_sql_injection("alice.doe@example.com"));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(contains_sql_injection("UNION SELECT"));
        assert!(contains_sql_injection("Union Select"));
        assert!(contains_sql_injection("DROP TABLE"));
    }

    #[test]
    fn test_detection_result() {
        let result = detect_sql_injection("test' or '1'='1");
        assert!(result.is_attack);
        assert!(result.matched_pattern.is_some());
        assert!(result.position.is_some());
    }
}
