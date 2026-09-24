//! `svidlet-token-issuer serve <config.toml>` runs the issuer.
//! `svidlet-token-issuer discovery <config.toml> <dir>` writes the discovery
//! document and JWKS for static hosting.

use std::process::ExitCode;

use svidlet_token_issuer::{config::Config, server};

fn main() -> ExitCode {
    tracing_subscriber::fmt().with_ansi(false).init();
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1..).unwrap_or_default() {
        [cmd, path] if cmd == "serve" => serve(path),
        [cmd, path, dir] if cmd == "discovery" => discovery(path, dir),
        _ => Err("usage: svidlet-token-issuer serve <config> | discovery <config> <dir>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "token.issuer.exit");
            ExitCode::FAILURE
        }
    }
}

fn load(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    Config::parse(&text).map_err(|e| format!("{path}: {e}"))
}

fn serve(path: &str) -> Result<(), String> {
    let cfg = load(path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime
        .block_on(server::run(cfg))
        .map_err(|e| e.to_string())
}

/// Write `.well-known/openid-configuration` and `.well-known/jwks.json` under
/// `dir`, for publishing at the issuer URL from static hosting.
fn discovery(path: &str, dir: &str) -> Result<(), String> {
    let minter = server::load(&load(path)?)?;
    let well_known = std::path::Path::new(dir).join(".well-known");
    std::fs::create_dir_all(&well_known).map_err(|e| e.to_string())?;
    for (name, doc) in [
        ("openid-configuration", server::discovery(&minter)),
        ("jwks.json", minter.jwks()),
    ] {
        std::fs::write(well_known.join(name), format!("{doc:#}\n")).map_err(|e| e.to_string())?;
    }
    Ok(())
}
