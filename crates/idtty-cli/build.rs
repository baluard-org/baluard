fn main() {
    let proto_dir = "../../proto";
    prost_build::Config::new()
        .compile_protos(
            &[format!("{proto_dir}/auth.proto")],
            &[proto_dir],
        )
        .expect("Failed to compile auth.proto");
}
