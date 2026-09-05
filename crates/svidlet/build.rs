fn main() -> Result<(), Box<dyn std::error::Error>> {
    // prost-build shells out to protoc; vendor it so builds do not depend on a
    // protoc being installed on the build host or in the CI image.
    if std::env::var_os("PROTOC").is_none() {
        if let Ok(protoc) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", protoc);
        }
    }

    // svidlet is a server for CSI and the kubelet, and a client of the policy
    // backend, so the two sets are generated with opposite roles.
    // The CSI client is generated as well as the server: nothing in the daemon
    // dials itself, but `svidlet-bench` stands in for the kubelet, and a load
    // generator that speaks the real protocol is the only honest way to measure
    // what the process costs under load.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/csi.proto"], &["proto"])?;

    let served = ["proto/csi.proto", "proto/registration.proto"];
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&["proto/registration.proto"], &["proto"])?;

    // The policy server side is generated too: nothing in the binary uses it,
    // but the integration tests run a real gRPC policy backend against the
    // real client, which is the only way to exercise the streaming path.
    let consumed = ["proto/policy.proto"];
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&consumed, &["proto"])?;

    for proto in served.iter().chain(consumed.iter()) {
        println!("cargo:rerun-if-changed={proto}");
    }
    Ok(())
}
