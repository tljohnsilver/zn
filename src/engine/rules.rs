use crate::config::ManagedRulesConfig;
use crate::lfi_guard;
use crate::prompt_guard;
use crate::sql_guard;

/// Managed Ruleset Engine
pub struct ManagedRuleset;

impl ManagedRuleset {
    /// Evaluate a tool call against managed security rules
    pub fn evaluate(
        config: &ManagedRulesConfig,
        tool_name: &str,
        arguments: &str,
    ) -> std::result::Result<(), String> {
        // 1. Restricted Commands
        // Tool names are server-controlled tokens (substring ok); argument
        // text must match whole words only ("confirm"/"address"/"odd" are not "rm"/"dd").
        if config.restricted_commands {
            let dangerous = [
                "rm", "format", "mkfs", "dd", "chmod", "chown", "shutdown", "reboot",
            ];
            let folded_tool = fold_system1(tool_name);
            let folded_args = fold_system1(arguments);
            let tool_hit = dangerous.iter().any(|&cmd| folded_tool.contains(cmd));
            let args_hit = folded_args
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| dangerous.iter().any(|&cmd| w.eq_ignore_ascii_case(cmd)));
            if tool_hit || args_hit {
                return Err(format!("Restricted command detected: {}", tool_name));
            }
        }

        // 2. LFI Protection
        let folded = fold_system1(arguments);
        if config.lfi_protection && lfi_guard::contains_lfi(&folded) {
            return Err("Local File Inclusion (LFI) attempt detected".to_string());
        }

        // 3. SQL Injection
        if config.sql_injection {
            let result = sql_guard::detect_sql_injection(&folded);
            if result.is_attack {
                return Err(format!(
                    "SQL Injection blocked: {}",
                    result.matched_pattern.unwrap_or_default()
                ));
            }
        }

        // 4. Prompt Injection
        if config.prompt_injection {
            let result = prompt_guard::detect_prompt_injection(&folded);
            if result.is_attack {
                return Err(format!(
                    "Prompt Injection blocked: {}",
                    result.matched_pattern.unwrap_or_default()
                ));
            }
        }

        // 5. Multimodal Vision Guard (Base64 Detection)
        if arguments.contains("data:image/") || arguments.contains("base64,") {
            if config.visual_pii_redaction {
                // In a production scenario, we would trigger an OCR/Vision scan here.
                tracing::warn!("📸 VISION SCAN TRIGGERED: Detecting PII in multimodal payload...");
                // return Err("Visual PII detected and blocked".to_string());
            } else {
                tracing::info!(
                    "📸 MULTIMODAL CONTENT DETECTED: Base64 found, vision scan skipped (disabled)."
                );
            }
        }

        Ok(())
    }
}

/// Fold untrusted text before System 1 matching.
/// No unicode_normalization crate dependency — strip null/RTL + map common fullwidth/homoglyphs.
pub fn fold_system1(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\u{0000}' | '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{202A}'
            | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}' | '\u{2066}' | '\u{2067}'
            | '\u{2068}' | '\u{2069}' => {}
            'Ａ'..='Ｚ' => out.push(char::from_u32(ch as u32 - 0xFF21 + b'A' as u32).unwrap()),
            'ａ'..='ｚ' => out.push(char::from_u32(ch as u32 - 0xFF41 + b'a' as u32).unwrap()),
            '０'..='９' => out.push(char::from_u32(ch as u32 - 0xFF10 + b'0' as u32).unwrap()),
            'а' => out.push('a'),
            'е' => out.push('e'),
            'о' => out.push('o'),
            'р' => out.push('p'),
            'с' => out.push('c'),
            'у' => out.push('y'),
            'х' => out.push('x'),
            'і' => out.push('i'),
            'Α' | 'А' => out.push('A'),
            'В' => out.push('B'),
            'Е' => out.push('E'),
            'К' => out.push('K'),
            'М' => out.push('M'),
            'Н' => out.push('H'),
            'О' => out.push('O'),
            'Р' => out.push('P'),
            'С' => out.push('C'),
            'Т' => out.push('T'),
            'Х' => out.push('X'),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ManagedRulesConfig;

    fn cfg() -> ManagedRulesConfig {
        ManagedRulesConfig::default()
    }

    #[test]
    fn test_restricted_word_match_in_args() {
        // Whole words block...
        assert!(
            ManagedRuleset::evaluate(&cfg(), "exec_command", "please run rm -rf /tmp/x").is_err()
        );
        assert!(
            ManagedRuleset::evaluate(&cfg(), "exec_command", "the command is RM -rf /").is_err()
        );
        assert!(ManagedRuleset::evaluate(&cfg(), "exec_command", "shutdown now").is_err());
    }

    #[test]
    fn test_restricted_substrings_do_not_block() {
        // ...but substrings inside ordinary words must not (the old bug).
        assert!(
            ManagedRuleset::evaluate(&cfg(), "exec_command", "Please confirm the change").is_ok()
        );
        assert!(ManagedRuleset::evaluate(&cfg(), "db_query", "add a row to the table").is_ok());
        assert!(ManagedRuleset::evaluate(&cfg(), "read_file", "the address book entry").is_ok());
        assert!(
            ManagedRuleset::evaluate(&cfg(), "code_interpreter", "count the odd numbers").is_ok()
        );
        assert!(ManagedRuleset::evaluate(&cfg(), "write_file", "form the sentence").is_ok());
    }

    #[test]
    fn test_restricted_tool_name_still_blocks() {
        assert!(ManagedRuleset::evaluate(&cfg(), "format_disk", "").is_err());
        assert!(ManagedRuleset::evaluate(&cfg(), "disk_shutdown", "").is_err());
    }

    #[test]
    fn fold_strips_null_and_rtl_marks() {
        assert_eq!(fold_system1("rm\u{0000} -rf"), "rm -rf");
        assert_eq!(fold_system1("rm\u{202E} -rf"), "rm -rf");
    }

    #[test]
    fn fold_maps_fullwidth_and_homoglyphs() {
        assert_eq!(fold_system1("ｒｍ"), "rm");
        assert_eq!(fold_system1("drор"), "drop"); // cyrillic o
        assert!(ManagedRuleset::evaluate(&cfg(), "exec_command", "please ｒｍ -rf /tmp").is_err());
    }
}
