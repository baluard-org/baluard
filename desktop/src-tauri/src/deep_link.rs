//! baluard:// deep links: the browser extension opens
//! baluard://entry/<slug>/<cipher-id> to view the entry here. The URL is
//! untrusted OS input (any local process can fire the scheme), so every
//! segment must match its strict shape or the link is ignored.

use tauri::Emitter;

/// Parse a baluard://entry/<slug>/<cipher-id> URL into (slug, cipher_id),
/// with the id lowercased. Query strings and fragments are stripped.
pub fn parse_entry_url(url: &str) -> Option<(String, String)> {
    let rest = url.trim().strip_prefix("baluard://")?;
    let rest = rest.strip_prefix("entry/")?;
    let rest = rest.split(['?', '#']).next()?;
    let mut parts = rest.split('/');
    let slug = parts.next()?;
    let id = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if !is_valid_slug(slug) {
        return None;
    }
    let id = normalize_uuid(id)?;
    Some((slug.to_string(), id))
}

/// Registry slugs are normalized with the baluard- prefix before they are
/// ever stored, so a link without it cannot name a real vault.
fn is_valid_slug(slug: &str) -> bool {
    let Some(rest) = slug.strip_prefix("baluard-") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn normalize_uuid(id: &str) -> Option<String> {
    let lens = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() != lens.len() {
        return None;
    }
    for (part, len) in parts.iter().zip(lens) {
        if part.len() != len || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
    }
    Some(id.to_ascii_lowercase())
}

/// Forward one incoming URL to the webview. Malformed links are dropped
/// silently: there is no UI to explain them to.
pub fn emit_entry(app: &tauri::AppHandle, url: &str) {
    if let Some((slug, id)) = parse_entry_url(url) {
        let _ = app.emit(
            "deep-link://entry",
            serde_json::json!({ "slug": slug, "id": id }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "c4f62a39-74e8-433b-9fbb-9338a1c3ccf6";

    #[test]
    fn parses_a_valid_link() {
        assert_eq!(
            parse_entry_url(&format!("baluard://entry/baluard-personal/{ID}")),
            Some(("baluard-personal".into(), ID.into()))
        );
    }

    #[test]
    fn lowercases_the_cipher_id() {
        let upper = ID.to_uppercase();
        let (_, id) =
            parse_entry_url(&format!("baluard://entry/baluard-personal/{upper}")).unwrap();
        assert_eq!(id, ID);
    }

    #[test]
    fn strips_query_and_fragment() {
        let url = format!("baluard://entry/baluard-work/{ID}?tab=2");
        assert!(parse_entry_url(&url).is_some());
        let url = format!("baluard://entry/baluard-work/{ID}#x");
        assert!(parse_entry_url(&url).is_some());
    }

    #[test]
    fn rejects_other_schemes_and_paths() {
        assert!(parse_entry_url(&format!("https://entry/baluard-x/{ID}")).is_none());
        assert!(parse_entry_url(&format!("baluard://vault/baluard-x/{ID}")).is_none());
        assert!(parse_entry_url("baluard://entry/baluard-x").is_none());
        assert!(parse_entry_url(&format!("baluard://entry/baluard-x/{ID}/extra")).is_none());
    }

    #[test]
    fn rejects_bad_slugs() {
        assert!(parse_entry_url(&format!("baluard://entry/personal/{ID}")).is_none());
        assert!(parse_entry_url(&format!("baluard://entry/baluard-/{ID}")).is_none());
        assert!(
            parse_entry_url(&format!("baluard://entry/baluard-Per{}/../{ID}", "sonal")).is_none()
        );
        assert!(parse_entry_url(&format!("baluard://entry/baluard-per sonal/{ID}")).is_none());
    }

    #[test]
    fn rejects_bad_uuids() {
        assert!(parse_entry_url("baluard://entry/baluard-x/not-a-uuid").is_none());
        assert!(parse_entry_url("baluard://entry/baluard-x/1234").is_none());
        // Right shape, wrong group lengths.
        assert!(
            parse_entry_url("baluard://entry/baluard-x/1234-456-7890-abcd-ef0123456789").is_none()
        );
        assert!(parse_entry_url(&format!("baluard://entry/baluard-x/{ID}?")).is_some());
    }
}
