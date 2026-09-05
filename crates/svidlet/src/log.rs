//! A ~100-line logfmt logger.
//!
//! A DaemonSet with a 5–8 MB budget does not need a subscriber framework: this
//! writes one line per event to stderr, which is where a container runtime
//! collects it.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" | "trace" => Some(Level::Debug),
            _ => None,
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_level(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    (level as u8) <= LEVEL.load(Ordering::Relaxed)
}

/// Emit one logfmt line. Values containing spaces or quotes are quoted.
pub fn log(level: Level, msg: &str, fields: &[(&str, &dyn std::fmt::Display)]) {
    if !enabled(level) {
        return;
    }
    let mut line = String::with_capacity(128);
    let _ = write!(line, "ts={} level={} msg=", unix_now(), level.as_str());
    write_value(&mut line, msg);
    for (key, value) in fields {
        let _ = write!(line, " {key}=");
        write_value(&mut line, &value.to_string());
    }
    line.push('\n');
    let _ = std::io::stderr().write_all(line.as_bytes());
}

fn write_value(out: &mut String, value: &str) {
    let needs_quotes = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '=' || c == '\\');
    if !needs_quotes {
        out.push_str(value);
        return;
    }
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
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
        $crate::log::log($crate::log::Level::Error, $msg, &[$((stringify!($k), &$v as &dyn std::fmt::Display)),*])
    };
}

#[macro_export]
macro_rules! warn {
    ($msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        $crate::log::log($crate::log::Level::Warn, $msg, &[$((stringify!($k), &$v as &dyn std::fmt::Display)),*])
    };
}

#[macro_export]
macro_rules! info {
    ($msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        $crate::log::log($crate::log::Level::Info, $msg, &[$((stringify!($k), &$v as &dyn std::fmt::Display)),*])
    };
}

#[macro_export]
macro_rules! debug {
    ($msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        $crate::log::log($crate::log::Level::Debug, $msg, &[$((stringify!($k), &$v as &dyn std::fmt::Display)),*])
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_quoted_only_when_needed() {
        let mut out = String::new();
        write_value(&mut out, "plain");
        assert_eq!(out, "plain");

        let mut out = String::new();
        write_value(&mut out, "two words");
        assert_eq!(out, "\"two words\"");

        let mut out = String::new();
        write_value(&mut out, "say \"hi\"");
        assert_eq!(out, "\"say \\\"hi\\\"\"");
    }
}
