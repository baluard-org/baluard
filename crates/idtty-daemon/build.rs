fn main() -> anyhow::Result<()> {
    let proto_dir = "../../proto";
    let proto_files = [
        format!("{proto_dir}/vault.proto"),
        format!("{proto_dir}/space.proto"),
        format!("{proto_dir}/auth.proto"),
    ];

    for proto in &proto_files {
        if !std::path::Path::new(proto).exists() {
            anyhow::bail!("Proto file not found: {proto}");
        }
    }

    prost_build::Config::new()
        .compile_protos(&proto_files, &[proto_dir])?;

    Ok(())
}
