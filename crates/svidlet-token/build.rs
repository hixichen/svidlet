fn main() -> Result<(), Box<dyn std::error::Error>> {
    // As in svidlet: vendor protoc unless the build host provides one.
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(protoc) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", protoc);
        }
    }
    // Both ends: svidlet is the client, svidlet-token-issuer the server.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/token.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/token.proto");
    Ok(())
}
