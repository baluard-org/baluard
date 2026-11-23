//! Policy decisions: query validation, search matching, field-allowlist
//! projections, cap math, and the approval duration ladder. Pure functions
//! and std-only state so the front-ends can call them from any runtime.

use serde_json::Value;

/// One search result row: metadata only, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SearchRow {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
}

pub const SEARCH_RESULT_CAP: usize = 20;
pub const SEARCH_CAP_PER_DAY: u32 = 500;
pub const SEARCH_BURST_PER_MINUTE: u32 = 30;
pub const SECRET_READS_PER_DAY: u32 = 100;
pub const SECRET_BURST_PER_MINUTE: u32 = 10;
const QUERY_MAX_CHARS: usize = 200;

/// Search requires a real query: the non-empty rule is the inventory-dump
/// defense, so a bare `""` or whitespace-only query is refused, not served.
pub fn validate_search_query(query: &str) -> Result<(), &'static str> {
    if query.trim().is_empty() {
        return Err("query must not be empty");
    }
    if query.chars().count() > QUERY_MAX_CHARS {
        return Err("query is too long");
    }
    Ok(())
}

fn row_matches(row: &SearchRow, needle: &str) -> bool {
    let needle = needle.to_lowercase();
    row.name.to_lowercase().contains(&needle)
        || row
            .username
            .as_deref()
            .map(|u| u.to_lowercase().contains(&needle))
            .unwrap_or(false)
        || row.uris.iter().any(|u| u.to_lowercase().contains(&needle))
}

/// Case-insensitive substring match over name, username, and URIs, capped
/// at [`SEARCH_RESULT_CAP`] so no single call dumps the account inventory.
pub fn filter_rows(query: &str, rows: Vec<SearchRow>) -> Vec<SearchRow> {
    rows.into_iter()
        .filter(|row| row_matches(row, query))
        .take(SEARCH_RESULT_CAP)
        .collect()
}

/// Builds the metadata row for one decrypted cipher JSON. Non-login items
/// carry empty usernames/URIs but still match by name.
pub fn project_search_row(cipher_json: &Value) -> Option<SearchRow> {
    let id = cipher_json.get("id")?.as_str()?.to_string();
    let name = cipher_json
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let username = cipher_json
        .get("username")
        .and_then(Value::as_str)
        .map(str::to_string);
    let uris = cipher_json
        .get("uris")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|u| {
                    u.as_str()
                        .map(str::to_string)
                        .or_else(|| u.get("uri").and_then(Value::as_str).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default();
    Some(SearchRow {
        id,
        name,
        username,
        uris,
    })
}

/// A custom field whose name or value looks like key material: the 0083
/// injection set intentionally excludes TOTP seeds, so custom fields named
/// "seed"/"totp" (or carrying an obvious base32 seed blob) never leave the
/// vault over MCP either.
pub fn is_seed_like(name: &str, value: &str) -> bool {
    let n = name.to_lowercase();
    if n.contains("seed") || n.contains("totp") || n.contains("recovery") {
        return true;
    }
    // Base32 seed blobs (A-Z2-7, no padding tolerance): the raw otpauth://
    // secret shape. Values this long with only base32 chars are seeds even
    // when the field is named carelessly.
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    compact.len() >= 16
        && compact.len() % 8 == 0
        && compact.chars().all(|c| {
            c.is_ascii_uppercase()
                || c.is_ascii_digit() && c != '0' && c != '1' && c != '8' && c != '9'
        })
}

/// Strict field-allowlist projection of a decrypted cipher into the 0083
/// injection set: username, password, and non-seed custom fields only.
/// Notes, URIs, TOTP seeds, favicon, passkeys, and every other field are
/// dropped before the response is built.
pub fn project_login(cipher_json: &Value) -> Result<Value, String> {
    let item_type = cipher_json
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !item_type.is_empty() && item_type != "login" {
        return Err(format!("item is a '{item_type}' entry, not a login"));
    }
    let username = cipher_json.get("username").and_then(Value::as_str);
    let password = cipher_json.get("password").and_then(Value::as_str);
    let mut custom_fields = Vec::new();
    if let Some(fields) = cipher_json.get("custom_fields").and_then(Value::as_array) {
        for field in fields {
            let (Some(name), Some(value)) = (
                field.get("name").and_then(Value::as_str),
                field.get("value").and_then(Value::as_str),
            ) else {
                continue;
            };
            if is_seed_like(name, value) {
                continue;
            }
            custom_fields.push(serde_json::json!({"name": name, "value": value}));
        }
    }
    Ok(serde_json::json!({
        "id": cipher_json.get("id"),
        "name": cipher_json.get("name"),
        "username": username,
        "password": password,
        "custom_fields": custom_fields,
    }))
}

/// The approval duration ladder, in minutes. `0` means just this read: the
/// approval activates nothing beyond the single call.
pub const READ_LADDER_MINUTES: &[u64] = &[0, 5, 15, 30, 60];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderChoice {
    JustThisRead,
    Window(u64),
}

/// Resolves a chosen ladder entry. An unlisted duration fails closed.
pub fn resolve_ladder(mins: u64) -> Option<LadderChoice> {
    if !READ_LADDER_MINUTES.contains(&mins) {
        return None;
    }
    if mins == 0 {
        Some(LadderChoice::JustThisRead)
    } else {
        Some(LadderChoice::Window(mins * 60))
    }
}

/// Rolling-window cap meter per pairing. Counters live in memory only, so
/// a daemon restart also resets caps — acceptable: caps throttle a running
/// agent, and a restart already killed every session and grant.
#[derive(Debug, Default)]
pub struct CapMeter {
    daily: Vec<std::time::Instant>,
    burst: Vec<std::time::Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOutcome {
    Allowed,
    /// Deterministic throttle: same verdict in and out of yolo, never a
    /// fallback to prompting, never an auto-revoke.
    Throttled,
}

impl CapMeter {
    const DAY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
    const MINUTE: std::time::Duration = std::time::Duration::from_secs(60);

    fn sweep(
        now: std::time::Instant,
        list: &mut Vec<std::time::Instant>,
        window: std::time::Duration,
    ) {
        list.retain(|t| now.duration_since(*t) < window);
    }

    /// Charges one event against the (daily, burst) limits. A trip returns
    /// [`CapOutcome::Throttled`] and records nothing.
    pub fn charge(&mut self, daily_max: u32, burst_max: u32) -> CapOutcome {
        let now = std::time::Instant::now();
        Self::sweep(now, &mut self.daily, Self::DAY);
        Self::sweep(now, &mut self.burst, Self::MINUTE);
        if self.daily.len() as u32 >= daily_max || self.burst.len() as u32 >= burst_max {
            return CapOutcome::Throttled;
        }
        self.daily.push(now);
        self.burst.push(now);
        CapOutcome::Allowed
    }

    pub fn used_today(&mut self) -> u32 {
        let now = std::time::Instant::now();
        Self::sweep(now, &mut self.daily, Self::DAY);
        self.daily.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn login_row(id: &str, name: &str, user: &str, uri: &str) -> SearchRow {
        SearchRow {
            id: id.into(),
            name: name.into(),
            username: Some(user.into()),
            uris: vec![uri.into()],
        }
    }

    #[test]
    fn empty_and_whitespace_queries_are_refused() {
        assert!(validate_search_query("").is_err());
        assert!(validate_search_query("   ").is_err());
        assert!(validate_search_query("git").is_ok());
        let long = "x".repeat(201);
        assert!(validate_search_query(&long).is_err());
        let ok = "x".repeat(200);
        assert!(validate_search_query(&ok).is_ok());
    }

    #[test]
    fn filtering_matches_case_insensitively_and_caps_results() {
        let rows = vec![
            login_row("1", "GitHub", "me@example.com", "https://github.com"),
            login_row("2", "GitLab", "other@x.org", "https://gitlab.com"),
            login_row("3", "Bank", "", "https://bank.example"),
        ];
        let hit = filter_rows("gitHUB", rows.clone());
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].id, "1");
        let multi = filter_rows("git", rows.clone());
        assert_eq!(multi.len(), 2);
        let uri_hit = filter_rows("bank.example", rows);
        assert_eq!(uri_hit.len(), 1);
    }

    #[test]
    fn filtering_never_exceeds_the_inventory_cap() {
        let rows: Vec<SearchRow> = (0..50)
            .map(|i| login_row(&i.to_string(), "same", "", ""))
            .collect();
        assert_eq!(filter_rows("same", rows).len(), SEARCH_RESULT_CAP);
    }

    #[test]
    fn search_projection_takes_metadata_only() {
        let cipher = json!({
            "id": "uuid-1",
            "name": "GitHub",
            "type": "login",
            "username": "me@example.com",
            "password": "hunter2",
            "uris": [{"uri": "https://github.com", "match_strategy": "Domain"}],
            "totp": "otpauth://totp/x?secret=ABC",
            "notes": "secret note",
        });
        let row = project_search_row(&cipher).unwrap();
        assert_eq!(row.id, "uuid-1");
        assert_eq!(row.username.as_deref(), Some("me@example.com"));
        assert_eq!(row.uris, vec!["https://github.com"]);
        let rendered = serde_json::to_string(&row).unwrap();
        assert!(
            !rendered.contains("hunter2"),
            "search rows never carry secrets"
        );
        assert!(
            !rendered.contains("otpauth"),
            "search rows never carry seeds"
        );
    }

    #[test]
    fn login_projection_is_a_strict_allowlist_with_seeds_stripped() {
        let cipher = json!({
            "id": "uuid-2",
            "name": "Bank",
            "type": "login",
            "username": "user",
            "password": "pass",
            "uris": ["https://bank"],
            "totp": "otpauth://totp/b?secret=SEEDSEED",
            "notes": "private",
            "custom_fields": [
                {"name": "Account", "value": "12345"},
                {"name": "TOTP Seed", "value": "JBSWY3DPEHPK3PXP"},
                {"name": "recovery phrase", "value": "word word word"},
            ],
        });
        let out = project_login(&cipher).unwrap();
        assert_eq!(out["username"], "user");
        assert_eq!(out["password"], "pass");
        let rendered = out.to_string();
        assert!(rendered.contains("12345"), "plain custom fields pass");
        assert!(
            !rendered.contains("JBSWY3DP"),
            "named seed fields are stripped"
        );
        assert!(
            !rendered.contains("word word"),
            "recovery fields are stripped"
        );
        assert!(
            !rendered.contains("otpauth"),
            "totp seed never rides a login read"
        );
        assert!(
            !rendered.contains("private"),
            "notes never ride a login read"
        );
        assert!(
            !rendered.contains("bank.example"),
            "uris never ride a login read"
        );
    }

    #[test]
    fn login_projection_refuses_non_login_items() {
        let card = json!({"id": "u3", "name": "Card", "type": "card", "cardholder_name": "x"});
        let err = project_login(&card).unwrap_err();
        assert!(err.contains("not a login"), "{err}");
    }

    #[test]
    fn base32_blobs_are_seed_like_even_when_misnamed() {
        assert!(is_seed_like("secret", "JBSWY3DPEHPK3PXP"));
        assert!(!is_seed_like("secret", "short"));
        assert!(!is_seed_like("pin", "1234"));
        assert!(is_seed_like("totp backup", "anything"));
    }

    #[test]
    fn ladder_resolves_only_listed_choices() {
        assert_eq!(resolve_ladder(0), Some(LadderChoice::JustThisRead));
        assert_eq!(resolve_ladder(15), Some(LadderChoice::Window(900)));
        assert_eq!(resolve_ladder(7), None);
        assert_eq!(resolve_ladder(61), None);
    }

    #[test]
    fn cap_meter_throttles_at_burst_then_allows_again() {
        let mut meter = CapMeter::default();
        for _ in 0..SECRET_BURST_PER_MINUTE {
            assert_eq!(
                meter.charge(SECRET_READS_PER_DAY, SECRET_BURST_PER_MINUTE),
                CapOutcome::Allowed
            );
        }
        assert_eq!(
            meter.charge(SECRET_READS_PER_DAY, SECRET_BURST_PER_MINUTE),
            CapOutcome::Throttled
        );
    }

    #[test]
    fn cap_meter_throttles_at_the_daily_bound() {
        let mut meter = CapMeter::default();
        // One burst charge per minute is not testable in real time; the
        // daily bound is what a long-lived agent hits, so the burst window
        // is cleared between charges and the daily cap is the live limit.
        for _ in 0..SECRET_READS_PER_DAY {
            assert_eq!(
                meter.charge(SECRET_READS_PER_DAY, SECRET_BURST_PER_MINUTE),
                CapOutcome::Allowed
            );
            meter.burst.clear();
        }
        assert_eq!(
            meter.charge(SECRET_READS_PER_DAY, SECRET_BURST_PER_MINUTE),
            CapOutcome::Throttled
        );
        assert_eq!(meter.used_today(), SECRET_READS_PER_DAY);
    }

    #[test]
    fn tripped_caps_record_nothing_so_a_later_window_is_clean() {
        let mut meter = CapMeter::default();
        for _ in 0..SECRET_BURST_PER_MINUTE {
            let _ = meter.charge(SECRET_READS_PER_DAY, SECRET_BURST_PER_MINUTE);
        }
        assert_eq!(
            meter.charge(SECRET_READS_PER_DAY, SECRET_BURST_PER_MINUTE),
            CapOutcome::Throttled
        );
        assert_eq!(meter.used_today(), SECRET_BURST_PER_MINUTE);
    }
}
