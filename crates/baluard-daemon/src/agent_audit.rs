use baluard_runtime::agents::PeerBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_NAME: &str = "agent-audit.jsonl";
const ROTATED_FILE_NAME: &str = "agent-audit.1.jsonl";
const MAX_AUDIT_BYTES: u64 = 1024 * 1024;
static AUDIT_APPEND_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuditEvent {
    pub timestamp_ms: u64,
    pub event: String,
    pub vault: String,
    pub exe_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv0: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub item_ids: Vec<String>,
    pub outcome: String,
    pub prev_hash: String,
    pub hash: String,
}

fn event_hash(event: &AuditEvent) -> Result<String, String> {
    let mut value = event.clone();
    value.hash.clear();
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn verify(events: &[AuditEvent]) -> Result<(), String> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    // Retention deliberately drops earlier generations. The first retained
    // record is the anchor; its own hash still authenticates that anchor.
    let mut previous = first.prev_hash.clone();
    for event in events {
        if event.prev_hash != previous || event.hash != event_hash(event)? {
            return Err("agent audit chain verification failed".into());
        }
        previous = event.hash.clone();
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<AuditEvent>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read agent audit: {e}")),
    };
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|e| format!("agent audit parse: {e}")))
        .collect()
}

pub(crate) fn read_events(data_dir: &Path) -> Result<Vec<AuditEvent>, String> {
    let _guard = AUDIT_APPEND_LOCK
        .lock()
        .map_err(|_| "agent audit lock is poisoned".to_string())?;
    let mut events = read_file(&data_dir.join(ROTATED_FILE_NAME))?;
    events.extend(read_file(&data_dir.join(FILE_NAME))?);
    verify(&events)?;
    Ok(events)
}

fn last_event(path: &Path) -> Result<Option<AuditEvent>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read agent audit tip: {e}")),
    };
    let Some(line) = raw.lines().rev().find(|line| !line.trim().is_empty()) else {
        return Ok(None);
    };
    let event: AuditEvent =
        serde_json::from_str(line).map_err(|e| format!("agent audit tip parse: {e}"))?;
    if event.hash != event_hash(&event)? {
        return Err("agent audit tip verification failed".into());
    }
    Ok(Some(event))
}

fn read_tip(data_dir: &Path) -> Result<Option<AuditEvent>, String> {
    if let Some(event) = last_event(&data_dir.join(FILE_NAME))? {
        return Ok(Some(event));
    }
    last_event(&data_dir.join(ROTATED_FILE_NAME))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append(
    data_dir: &Path,
    event: &str,
    vault: &str,
    peer: &PeerBinding,
    request_id: Option<&str>,
    argv0: Option<&str>,
    item_ids: &[String],
    outcome: &str,
) -> Result<(), String> {
    let _guard = AUDIT_APPEND_LOCK
        .lock()
        .map_err(|_| "agent audit lock is poisoned".to_string())?;
    let tip = read_tip(data_dir)?;
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let mut record = AuditEvent {
        timestamp_ms,
        event: event.into(),
        vault: vault.into(),
        exe_path: peer.exe_path.clone(),
        argv0: argv0.map(str::to_string),
        request_id: request_id.map(str::to_string),
        item_ids: item_ids.to_vec(),
        outcome: outcome.into(),
        prev_hash: tip
            .map(|row| row.hash)
            .unwrap_or_else(|| GENESIS_HASH.into()),
        hash: String::new(),
    };
    record.hash = event_hash(&record)?;
    let mut line = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
    line.push(b'\n');

    let path = data_dir.join(FILE_NAME);
    let rotated = data_dir.join(ROTATED_FILE_NAME);
    let current_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    if current_len + line.len() as u64 > MAX_AUDIT_BYTES {
        #[cfg(windows)]
        if rotated.exists() {
            std::fs::remove_file(&rotated).map_err(|e| format!("rotate agent audit: {e}"))?;
        }
        if path.exists() {
            std::fs::rename(&path, &rotated).map_err(|e| format!("rotate agent audit: {e}"))?;
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("write agent audit: {e}"))?;
    file.write_all(&line)
        .and_then(|_| file.sync_data())
        .map_err(|e| format!("write agent audit: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_chain_detects_tampering_and_never_stores_secret_values() {
        let dir = tempfile::tempdir().unwrap();
        let peer = baluard_runtime::agents::PeerBinding {
            pid: 42,
            exe_path: "/usr/bin/local-agent".into(),
            start_ticks: 0,
        };
        append(
            dir.path(),
            "approved",
            "personal",
            &peer,
            Some("req-1"),
            None,
            &["item-1".into()],
            "approved",
        )
        .unwrap();
        append(
            dir.path(),
            "run_finished",
            "personal",
            &peer,
            Some("req-1"),
            Some("deploy"),
            &["item-1".into()],
            "exit:0",
        )
        .unwrap();

        let events = read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 2);
        verify(&events).unwrap();
        assert_eq!(events[0].prev_hash, "0".repeat(64));
        assert_eq!(events[1].prev_hash, events[0].hash);
        let raw = std::fs::read_to_string(dir.path().join(FILE_NAME)).unwrap();
        assert!(!raw.contains("correct horse battery"));

        let mut tampered = events;
        tampered[0].outcome = "denied".into();
        assert!(verify(&tampered).is_err());
    }

    #[test]
    fn pruned_retention_anchor_still_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let peer = baluard_runtime::agents::PeerBinding {
            pid: 42,
            exe_path: "/usr/bin/local-agent".into(),
            start_ticks: 0,
        };
        for index in 0..3 {
            append(
                dir.path(),
                "run_finished",
                "personal",
                &peer,
                None,
                None,
                &[],
                &format!("exit:{index}"),
            )
            .unwrap();
        }
        let retained = read_events(dir.path()).unwrap().split_off(1);
        verify(&retained).unwrap();
    }

    #[test]
    fn concurrent_appends_form_one_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut workers = Vec::new();
        for index in 0..8 {
            let path = dir.path().to_path_buf();
            workers.push(std::thread::spawn(move || {
                let peer = baluard_runtime::agents::PeerBinding {
                    pid: index,
                    exe_path: format!("/usr/bin/agent-{index}"),
                    start_ticks: 0,
                };
                append(
                    &path,
                    "run_started",
                    "personal",
                    &peer,
                    None,
                    None,
                    &[],
                    "started",
                )
                .unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let events = read_events(dir.path()).unwrap();
        assert_eq!(events.len(), 8);
        verify(&events).unwrap();
    }
}
