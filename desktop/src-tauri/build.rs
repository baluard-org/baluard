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

    tauri_build::build()
}
