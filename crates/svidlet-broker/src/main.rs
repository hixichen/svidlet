//! `svidlet-broker` entry point.

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = svidlet_broker::config::Config::from_env()?;
    tracing_subscriber::fmt()
        .with_max_level(match std::env::var("SVIDLET_LOG_LEVEL").as_deref() {
            Ok("debug") => tracing::Level::DEBUG,
            Ok("warn") => tracing::Level::WARN,
            Ok("error") => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        })
        .with_writer(std::io::stderr)
        .init();
    // Blocking work (Kubernetes, Vault) runs on the blocking pool; the
    // reactor only moves bytes, so one thread is enough for it.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(32)
        .thread_name("svidlet-broker")
        .build()?
        .block_on(svidlet_broker::run(cfg))
}
