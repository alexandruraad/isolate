// Build script: generates tonic + prost code from proto/ definitions.
//
// Requires: protoc (brew install protobuf)
// Run `cargo build -p isolate-proto` after modifying any .proto file.
// Generated code lands in OUT_DIR and is re-exported from lib.rs.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::var("OUT_DIR").unwrap();

    // If protoc is not installed, write empty stub files so include!() compiles.
    if which_protoc().is_none() {
        println!("cargo:warning=protoc not found — writing stub proto files. Install with: brew install protobuf");
        for pkg in &["isolate.v1", "isolate.events.v1", "isolate.intel.v1"] {
            let path = format!("{}/{}.rs", out, pkg);
            std::fs::write(&path, "// protoc not installed — stub file\n")?;
        }
        return Ok(());
    }

    let proto_root = std::path::Path::new("../../proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                proto_root.join("isolate.proto"),
                proto_root.join("events.proto"),
                proto_root.join("intelligence.proto"),
            ],
            &[proto_root],
        )?;

    Ok(())
}

fn which_protoc() -> Option<std::path::PathBuf> {
    std::process::Command::new("protoc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| std::path::PathBuf::from("protoc"))
}
