fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto_dir = format!("{manifest_dir}/../../proto");
    let proto_file = format!("{proto_dir}/auth.proto");

    if !std::path::Path::new(&proto_file).exists() {
        panic!("Proto file not found: {proto_file}");
    }

    prost_build::Config::new()
        .compile_protos(&[&proto_file], &[&proto_dir])
        .expect("Failed to compile auth.proto");

    // D79 version handshake: the desktop refuses a daemon whose build
    // version differs from the one it shipped with. Read from the daemon's
    // manifest instead of linking the crate (the sidecar is an external
    // binary), so a stale sidecar after an update is detectable. The daemon
    // inherits the workspace version, so fall back to the root manifest.
    let daemon_manifest = std::path::Path::new(&manifest_dir).join("../../crates/baluard-daemon/Cargo.toml");
    let daemon_cargo = std::fs::read_to_string(&daemon_manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", daemon_manifest.display()));
    let version_line = |text: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix("version = \""))
            .and_then(|rest| rest.split('"').next().map(str::to_string))
    };
    let daemon_version = match version_line(&daemon_cargo) {
        Some(v) => v,
        None => {
            assert!(daemon_cargo.contains("version.workspace = true"), "unexpected daemon manifest");
            let root = std::path::Path::new(&manifest_dir).join("../../Cargo.toml");
            let root_cargo = std::fs::read_to_string(&root)
                .unwrap_or_else(|e| panic!("read {}: {e}", root.display()));
            let start = root_cargo.find("[workspace.package]")
                .unwrap_or_else(|| panic!("[workspace.package] missing in {}", root.display()));
            version_line(&root_cargo[start..])
                .unwrap_or_else(|| panic!("workspace version not found in {}", root.display()))
        }
    };
    println!("cargo:rustc-env=BALUARD_DAEMON_VERSION={daemon_version}");
    println!("cargo:rerun-if-changed={}", daemon_manifest.display());
    println!("cargo:rerun-if-changed={}", std::path::Path::new(&manifest_dir).join("../../Cargo.toml").display());

    println!("cargo:rerun-if-changed=icons");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    tauri_build::build()
}
