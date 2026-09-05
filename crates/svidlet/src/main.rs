//! Svidlet binary entry point. The plugin itself lives in the library crate.

use svidlet::config::Config;
use svidlet::{log, rand, server};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::from_env()?;
    log::set_level(cfg.log_level);
    rand::seed();

    // A current-thread reactor with a small blocking pool: everything expensive
    // (key generation, the HTTPS call to the PKI backend) happens on the
    // blocking pool, and the reactor only shuffles gRPC frames.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .thread_name("svidlet")
        .build()?;

    runtime.block_on(server::run(cfg))
}
