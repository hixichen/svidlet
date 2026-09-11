//! Structured logging: a thin veneer over `tracing` + `tracing-subscriber`.
//!
//! Every event carries named fields — `info!("published", spiffe_id = id,
//! target = path)` becomes a `tracing` event with real field values, rendered
//! by the subscriber as one line per event:
//! `2026-09-06T…  INFO published spiffe_id=… target=…`. The macros stay at
//! their ~100 call sites; only this module knows about the subscriber.
//!
//! Both binaries call [`init`] once at start-up. Until then, events are
//! dropped: the `tracing` facade is a no-op with no subscriber installed,
//! which is what tests rely on to stay quiet.
//!
//! The level comes from `SVIDLET_LOG_LEVEL` (error | warn | info | debug),
//! exactly as `Config` validates it. One level for the whole process — a
//! DaemonSet does not need per-crate filtering. The subscriber is the minimal
//! build (fmt + registry only, no JSON/EnvFilter features): the memory
//! budget buys the fields, not the format options.

use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" | "trace" => Some(Level::Debug),
            _ => None,
        }
    }

    fn to_tracing(self) -> tracing::level_filters::LevelFilter {
        match self {
            Level::Error => tracing::level_filters::LevelFilter::ERROR,
            Level::Warn => tracing::level_filters::LevelFilter::WARN,
            Level::Info => tracing::level_filters::LevelFilter::INFO,
            Level::Debug => tracing::level_filters::LevelFilter::DEBUG,
        }
    }
}

/// Install the process-wide subscriber: one text line per event on stderr,
/// no ANSI colours (a container runtime or log ingester would otherwise have
/// to strip them), no target prefix.
///
/// A second call is a no-op: the first installed subscriber stays. Neither
/// binary ever needs two, but a re-run start-up path must not crash-loop on
/// logging of all things.
pub fn init(level: Level) {
    // `try_init`, not `init`: installing a subscriber panics if one is already
    // set, and a failed install keeps the first subscriber rather than dying.
    let _ = tracing_subscriber::fmt::fmt()
        .with_max_level(level.to_tracing())
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}

/// Seconds since the Unix epoch. Also the clock the renewal schedule uses:
/// certificate deadlines are wall-clock, so a monotonic clock is wrong here.
pub fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[macro_export]
macro_rules! error {
    ($msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        ::tracing::error!($($k = %$v,)* $msg)
    };
}

#[macro_export]
macro_rules! warn {
    ($msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        ::tracing::warn!($($k = %$v,)* $msg)
    };
}

#[macro_export]
macro_rules! info {
    ($msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        ::tracing::info!($($k = %$v,)* $msg)
    };
}

#[macro_export]
macro_rules! debug {
    ($msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        ::tracing::debug!($($k = %$v,)* $msg)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_parse_the_names_config_allows() {
        assert_eq!(Level::parse("error"), Some(Level::Error));
        assert_eq!(Level::parse(" WARN "), Some(Level::Warn));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("Info"), Some(Level::Info));
        assert_eq!(Level::parse("debug"), Some(Level::Debug));
        assert_eq!(Level::parse("trace"), Some(Level::Debug));
        assert_eq!(Level::parse("verbose"), None);
        assert!(
            Level::Error < Level::Warn && Level::Warn < Level::Info && Level::Info < Level::Debug
        );
    }
}
