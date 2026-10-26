//! `svidlet-catalog`: lint the catalog and render what Vault needs from it.
//!
//! ```text
//! svidlet-catalog lint   catalog.toml
//! svidlet-catalog policy catalog.toml <cluster> [pki_mount] [spiffe_mount]
//! svidlet-catalog roles  catalog.toml <cluster> [spiffe_mount]
//! ```
//!
//! CI runs `lint` on every change and applies `policy` and `roles` per
//! cluster; the broker reads the same file, so the two can only disagree for
//! the length of a rollout.

use std::process::ExitCode;

use svidlet_issue::Catalog;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: svidlet-catalog lint|policy|roles <catalog.toml> [cluster] [mounts…]";
    let (Some(cmd), Some(path)) = (args.first(), args.get(1)) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let catalog = match Catalog::load(std::path::Path::new(path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let cluster = args.get(2).map(String::as_str);
    match (cmd.as_str(), cluster) {
        ("lint", _) => {
            println!("ok: {} identities", catalog.identity.len());
        }
        ("policy", Some(c)) => {
            let pki = args.get(3).map(String::as_str).unwrap_or("pki_int");
            let spiffe = args.get(4).map(String::as_str).unwrap_or("spiffe");
            print!(
                "{}",
                catalog.render_policy(c, pki, &format!("spiffe-{c}"), spiffe)
            );
        }
        ("roles", Some(c)) => {
            let spiffe = args.get(3).map(String::as_str).unwrap_or("spiffe");
            print!("{}", catalog.render_roles(c, spiffe));
        }
        _ => {
            eprintln!("{usage}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
