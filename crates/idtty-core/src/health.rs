//! Password health analysis.
//!
//! Local computation: weak, reused, and old passwords.
//! No network. No external API. Pure local analysis.

use crate::types::Cipher;

/// Password health report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthReport {
    /// Entries with weak passwords.
    pub weak: Vec<HealthEntry>,
    /// Entries with reused passwords (same password appears on multiple entries).
    pub reused: Vec<HealthEntry>,
    /// Entries with passwords unchanged for more than 90 days.
    pub old: Vec<HealthEntry>,
}

/// A single health finding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthEntry {
    pub cipher_id: String,
    pub name: String,
    pub reason: String,
}

/// Common passwords (top 100 from breach databases).
const COMMON_PASSWORDS: &[&str] = &[
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "696969", "mustang",
    "666666", "access", "hello", "charlie", "1234567890",
    "password1", "qwerty123", "admin", "welcome", "login",
    "passw0rd", "starwars", "123456a", "password123", "123qwe",
    "whatever", "trustno1", "princess", "iloveyou", "sunshine",
    "superman", "batman", "ashley", "michael", "ninja",
    "solo", "jordan", "hunter", "hunter2", "test",
];

/// Analyze all ciphers for password health issues.
pub fn analyze(ciphers: &[Cipher]) -> HealthReport {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let ninety_days_secs: u64 = 90 * 24 * 60 * 60;

    let mut weak = Vec::new();
    let mut reused = Vec::new();
    let mut old = Vec::new();

    // Build password -> cipher list for reuse detection
    let mut password_map: std::collections::HashMap<String, Vec<(String, String)>> = std::collections::HashMap::new();

    for cipher in ciphers {
        let password = match &cipher.kind {
            crate::types::CipherKind::Login(data) => data.password.as_deref(),
            _ => continue,
        };

        let Some(pw) = password else { continue };
        if pw.is_empty() { continue; }

        // Weak: too short, or in common list
        let is_weak = pw.len() < 8
            || COMMON_PASSWORDS.contains(&pw.to_lowercase().as_str())
            || is_all_same_char(pw)
            || is_sequential(pw);

        if is_weak {
            weak.push(HealthEntry {
                cipher_id: cipher.id.to_string(),
                name: cipher.name.clone(),
                reason: if pw.len() < 8 {
                    format!("Too short ({} chars, minimum 8)", pw.len())
                } else if COMMON_PASSWORDS.contains(&pw.to_lowercase().as_str()) {
                    "Common password".into()
                } else if is_all_same_char(pw) {
                    "All same character".into()
                } else if is_sequential(pw) {
                    "Sequential characters".into()
                } else {
                    "Weak".into()
                },
            });
        }

        // Old: unchanged for >90 days
        let revision_date = match &cipher.kind {
            crate::types::CipherKind::Login(data) => data.password_revision_date.unwrap_or(cipher.updated_at),
            _ => cipher.updated_at,
        };
        if now.saturating_sub(revision_date) > ninety_days_secs {
            let days = (now.saturating_sub(revision_date) / 86400).max(1);
            old.push(HealthEntry {
                cipher_id: cipher.id.to_string(),
                name: cipher.name.clone(),
                reason: format!("Unchanged for {} days", days),
            });
        }

        // Track for reuse
        password_map
            .entry(pw.to_string())
            .or_default()
            .push((cipher.id.to_string(), cipher.name.clone()));
    }

    // Reuse: passwords used on multiple entries
    for (_pw, entries) in &password_map {
        if entries.len() > 1 {
            for (id, name) in entries {
                reused.push(HealthEntry {
                    cipher_id: id.clone(),
                    name: name.clone(),
                    reason: format!("Used on {} entries", entries.len()),
                });
            }
        }
    }

    // Sort by name for consistent output
    weak.sort_by(|a, b| a.name.cmp(&b.name));
    reused.sort_by(|a, b| a.name.cmp(&b.name));
    old.sort_by(|a, b| a.name.cmp(&b.name));

    HealthReport { weak, reused, old }
}

fn is_all_same_char(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() { return false; }
    chars.windows(2).all(|w| w[0] == w[1])
}

fn is_sequential(s: &str) -> bool {
    let lower: String = s.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    if chars.len() < 4 { return false; }

    let mut ascending = 0;
    let mut descending = 0;

    for w in chars.windows(2) {
        if w[0] as i32 + 1 == w[1] as i32 {
            ascending += 1;
            descending = 0;
        } else if w[0] as i32 - 1 == w[1] as i32 {
            descending += 1;
            ascending = 0;
        } else {
            ascending = 0;
            descending = 0;
        }

        if ascending >= 3 || descending >= 3 {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_login(id: &str, name: &str, password: &str, updated_at: u64) -> Cipher {
        Cipher {
            id: uuid::Uuid::parse_str(id).unwrap(),
            name: name.to_string(),
            folder_id: None,
            kind: CipherKind::Login(LoginData {
                username: Some("u@test.com".into()),
                password: Some(password.to_string()),
                uris: vec![],
                totp_uri: None,
                autofill_on_page_load: false,
                password_revision_date: None,
            }),
            favorite: false,
            reprompt: false,
            notes: None,
            custom_fields: vec![],
            key_epoch: 1,
            update_seq: 1,
            tier: Tier::Xs,
            created_at: updated_at - 100000,
            updated_at,
            password_history: vec![],
            attachments: vec![],
        }
    }

    #[test]
    fn detect_weak_short() {
        let ciphers = vec![make_login("00000000-0000-0000-0000-000000000001", "Short", "abc", 1700000000)];
        let report = analyze(&ciphers);
        assert_eq!(report.weak.len(), 1);
        assert!(report.weak[0].reason.contains("Too short"));
    }

    #[test]
    fn detect_weak_common() {
        let ciphers = vec![make_login("00000000-0000-0000-0000-000000000001", "Common", "password", 1700000000)];
        let report = analyze(&ciphers);
        assert_eq!(report.weak.len(), 1);
        assert!(report.weak[0].reason.contains("Common"));
    }

    #[test]
    fn detect_reused() {
        let ciphers = vec![
            make_login("00000000-0000-0000-0000-000000000001", "Site1", "samepass", 1700000000),
            make_login("00000000-0000-0000-0000-000000000002", "Site2", "samepass", 1700000000),
            make_login("00000000-0000-0000-0000-000000000003", "Site3", "samepass", 1700000000),
        ];
        let report = analyze(&ciphers);
        assert_eq!(report.reused.len(), 3);
        assert!(report.reused[0].reason.contains("3 entries"));
    }

    #[test]
    fn detect_old() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old_time = now - (120 * 24 * 60 * 60); // 120 days ago
        let ciphers = vec![make_login("00000000-0000-0000-0000-000000000001", "Old", "goodpass123!", old_time)];
        let report = analyze(&ciphers);
        assert_eq!(report.old.len(), 1);
        assert!(report.old[0].reason.contains("days"));
        assert!(report.weak.is_empty()); // password is strong
    }

    #[test]
    fn strong_password_not_flagged() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ciphers = vec![make_login("00000000-0000-0000-0000-000000000001", "Strong", "k#9mLp$2xQr!", now)];
        let report = analyze(&ciphers);
        assert!(report.weak.is_empty());
        assert!(report.reused.is_empty());
        assert!(report.old.is_empty());
    }

    #[test]
    fn skip_non_login() {
        let mut cipher = make_login("00000000-0000-0000-0000-000000000001", "Note", "anypass", 1700000000);
        cipher.kind = CipherKind::SecureNote;
        let report = analyze(&[cipher]);
        assert!(report.weak.is_empty());
        assert!(report.reused.is_empty());
    }
}
