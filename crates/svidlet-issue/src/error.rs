//! Error type and the stable error-code taxonomy.
//!
//! Every failure carries an [`ErrorCode`]. The code is a stable, snake_case
//! string that is safe to use as a Prometheus label value and that operators
//! can alert on, so a dashboard does not have to match on log text. Codes are
//! part of the public interface: rename one and you break somebody's alert.

use std::fmt;

/// Stable classification of every way issuance can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    /// Configuration is wrong: an unparsable SPIFFE ID template, a bad regex,
    /// a credential file that cannot be read. Operator error, not transient.
    Config,
    /// The workload's attributes cannot form a valid SPIFFE ID — an empty
    /// namespace, or a value carrying a path separator.
    Identity,
    /// The SPIFFE ID is well formed but the operator's `spiffe_id_pattern`
    /// rejects it. A deliberate refusal, logged loudly and never retried.
    Policy,
    /// Key generation or CSR construction failed.
    Crypto,
    /// The PKI backend could not be reached.
    Transport,
    /// The PKI backend answered with a non-2xx status.
    BackendStatus,
    /// The backend's answer did not have the expected shape.
    Protocol,
    /// A certificate could not be parsed, or did not carry the identity that
    /// was requested.
    Certificate,
    /// Authentication against the PKI backend failed.
    Auth,
    /// A local filesystem operation failed.
    Io,
}

impl ErrorCode {
    /// The stable string form, used in logs and as a metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Config => "config",
            ErrorCode::Identity => "identity",
            ErrorCode::Policy => "policy",
            ErrorCode::Crypto => "crypto",
            ErrorCode::Transport => "transport",
            ErrorCode::BackendStatus => "backend_status",
            ErrorCode::Protocol => "protocol",
            ErrorCode::Certificate => "certificate",
            ErrorCode::Auth => "auth",
            ErrorCode::Io => "io",
        }
    }

    /// Every code, so metrics can pre-declare the full label set. A Prometheus
    /// counter that only appears after its first failure makes `rate()` alerts
    /// silently useless, so all series are exported from process start.
    pub const ALL: [ErrorCode; 10] = [
        ErrorCode::Config,
        ErrorCode::Identity,
        ErrorCode::Policy,
        ErrorCode::Crypto,
        ErrorCode::Transport,
        ErrorCode::BackendStatus,
        ErrorCode::Protocol,
        ErrorCode::Certificate,
        ErrorCode::Auth,
        ErrorCode::Io,
    ];

    /// Index into a fixed-size array of per-code counters.
    pub const fn index(self) -> usize {
        self as usize
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum Error {
    Config(String),
    Identity(String),
    Policy(String),
    Crypto(String),
    Transport(String),
    Backend { status: u16, body: String },
    Protocol(String),
    Certificate(String),
    Auth(String),
    Io(std::io::Error),
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Config(_) => ErrorCode::Config,
            Error::Identity(_) => ErrorCode::Identity,
            Error::Policy(_) => ErrorCode::Policy,
            Error::Crypto(_) => ErrorCode::Crypto,
            Error::Transport(_) => ErrorCode::Transport,
            Error::Backend { .. } => ErrorCode::BackendStatus,
            Error::Protocol(_) => ErrorCode::Protocol,
            Error::Certificate(_) => ErrorCode::Certificate,
            Error::Auth(_) => ErrorCode::Auth,
            Error::Io(_) => ErrorCode::Io,
        }
    }

    /// Whether retrying the same call later could plausibly succeed.
    ///
    /// Renewal backs off and retries on these and gives up loudly on the rest:
    /// retrying a malformed request only burns the PKI backend's rate-limit
    /// quota and buries the real cause in a repeated warning.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Transport(_) | Error::Io(_) => true,
            // 429 and 5xx are transient: Vault answers 503 while sealed or
            // standing by, and 429 when a rate-limit quota is exceeded.
            Error::Backend { status, .. } => *status == 429 || *status >= 500,
            // A rejected token is recoverable — the caller re-logs in first.
            Error::Auth(_) => true,
            Error::Config(_)
            | Error::Identity(_)
            | Error::Policy(_)
            | Error::Crypto(_)
            | Error::Protocol(_)
            | Error::Certificate(_) => false,
        }
    }

    /// Whether the failure is the caller's fault rather than ours. Drives the
    /// gRPC status the CSI plugin returns to the kubelet.
    pub fn is_caller_error(&self) -> bool {
        matches!(self, Error::Identity(_) | Error::Policy(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "configuration is invalid: {m}"),
            Error::Identity(m) => write!(f, "invalid workload identity: {m}"),
            Error::Policy(m) => write!(f, "SPIFFE ID rejected by policy: {m}"),
            Error::Crypto(m) => write!(f, "key or CSR generation failed: {m}"),
            Error::Transport(m) => write!(f, "PKI backend unreachable: {m}"),
            Error::Backend { status, body } => {
                write!(f, "PKI backend returned HTTP {status}: {body}")
            }
            Error::Protocol(m) => write!(f, "unexpected PKI backend response: {m}"),
            Error::Certificate(m) => write!(f, "certificate error: {m}"),
            Error::Auth(m) => write!(f, "PKI backend authentication failed: {m}"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant maps to a code, and every code is reachable. A new
    /// variant added without a code would fail here rather than silently
    /// reporting the wrong label.
    #[test]
    fn every_code_is_produced_by_some_variant() {
        let samples = [
            Error::Config("x".into()),
            Error::Identity("x".into()),
            Error::Policy("x".into()),
            Error::Crypto("x".into()),
            Error::Transport("x".into()),
            Error::Backend {
                status: 500,
                body: "x".into(),
            },
            Error::Protocol("x".into()),
            Error::Certificate("x".into()),
            Error::Auth("x".into()),
            Error::Io(std::io::Error::other("x")),
        ];
        let mut produced: Vec<ErrorCode> = samples.iter().map(Error::code).collect();
        produced.sort();
        produced.dedup();
        assert_eq!(produced, ErrorCode::ALL.to_vec());
    }

    #[test]
    fn codes_are_stable_snake_case_label_values() {
        for code in ErrorCode::ALL {
            let s = code.as_str();
            assert!(!s.is_empty());
            assert!(
                s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{s} is not a safe Prometheus label value"
            );
            assert_eq!(code.to_string(), s);
        }
    }

    #[test]
    fn index_is_dense_and_matches_all() {
        for (i, code) in ErrorCode::ALL.iter().enumerate() {
            assert_eq!(code.index(), i);
        }
    }

    #[test]
    fn retryable_covers_outages_but_not_bad_requests() {
        assert!(Error::Transport("connection refused".into()).is_retryable());
        assert!(Error::Io(std::io::Error::other("disk")).is_retryable());
        assert!(Error::Auth("token expired".into()).is_retryable());
        for status in [429, 500, 502, 503] {
            assert!(Error::Backend {
                status,
                body: String::new()
            }
            .is_retryable());
        }
        for status in [400, 403, 404] {
            assert!(!Error::Backend {
                status,
                body: String::new()
            }
            .is_retryable());
        }
        assert!(!Error::Identity("bad".into()).is_retryable());
        assert!(!Error::Policy("denied".into()).is_retryable());
        assert!(!Error::Config("bad template".into()).is_retryable());
        assert!(!Error::Crypto("rng".into()).is_retryable());
        assert!(!Error::Certificate("mismatch".into()).is_retryable());
        assert!(!Error::Protocol("garbage".into()).is_retryable());
    }

    #[test]
    fn caller_errors_are_the_ones_a_pod_spec_can_cause() {
        assert!(Error::Identity("bad".into()).is_caller_error());
        assert!(Error::Policy("denied".into()).is_caller_error());
        assert!(!Error::Transport("x".into()).is_caller_error());
        assert!(!Error::Auth("x".into()).is_caller_error());
    }

    #[test]
    fn display_names_the_failure_and_source_is_wired() {
        let e = Error::Backend {
            status: 503,
            body: "sealed".into(),
        };
        assert_eq!(e.to_string(), "PKI backend returned HTTP 503: sealed");
        assert!(std::error::Error::source(&e).is_none());

        let io = Error::from(std::io::Error::other("boom"));
        assert_eq!(io.code(), ErrorCode::Io);
        assert!(std::error::Error::source(&io).is_some());
        assert!(io.to_string().contains("boom"));
    }
}
