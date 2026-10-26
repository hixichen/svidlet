//! Why a request was refused, and what status that becomes.

use svidlet_issue::{Error, ErrorCode};

use crate::kube::KubeError;

/// Every way the broker says no. Each refusal names the invariant or rule that
/// fired, so the audit log and the caller's error say *which* check it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `400`: the request is malformed.
    BadRequest { rule: &'static str, message: String },
    /// `401`: a token did not authenticate.
    Unauthenticated { rule: &'static str, message: String },
    /// `403`: well formed, authenticated, and refused by a rule.
    Forbidden { rule: &'static str, message: String },
    /// `429`: a rate limit.
    TooMany { rule: &'static str, message: String },
    /// `503`: a dependency is down; the caller should retry.
    Unavailable { message: String },
    /// `500`: our fault.
    Internal { message: String },
}

impl Refusal {
    pub fn bad(rule: &'static str, message: impl Into<String>) -> Refusal {
        Refusal::BadRequest {
            rule,
            message: message.into(),
        }
    }
    pub fn unauthenticated(rule: &'static str, message: impl Into<String>) -> Refusal {
        Refusal::Unauthenticated {
            rule,
            message: message.into(),
        }
    }
    pub fn forbidden(rule: &'static str, message: impl Into<String>) -> Refusal {
        Refusal::Forbidden {
            rule,
            message: message.into(),
        }
    }
    pub fn too_many(rule: &'static str, message: impl Into<String>) -> Refusal {
        Refusal::TooMany {
            rule,
            message: message.into(),
        }
    }
    pub fn unavailable(message: impl Into<String>) -> Refusal {
        Refusal::Unavailable {
            message: message.into(),
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Refusal::BadRequest { .. } => 400,
            Refusal::Unauthenticated { .. } => 401,
            Refusal::Forbidden { .. } => 403,
            Refusal::TooMany { .. } => 429,
            Refusal::Unavailable { .. } => 503,
            Refusal::Internal { .. } => 500,
        }
    }

    pub fn rule(&self) -> &'static str {
        match self {
            Refusal::BadRequest { rule, .. }
            | Refusal::Unauthenticated { rule, .. }
            | Refusal::Forbidden { rule, .. }
            | Refusal::TooMany { rule, .. } => rule,
            Refusal::Unavailable { .. } | Refusal::Internal { .. } => "",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Refusal::BadRequest { message, .. }
            | Refusal::Unauthenticated { message, .. }
            | Refusal::Forbidden { message, .. }
            | Refusal::TooMany { message, .. }
            | Refusal::Unavailable { message }
            | Refusal::Internal { message } => message,
        }
    }

    /// Stable label value for metrics.
    pub fn outcome(&self) -> &'static str {
        match self {
            Refusal::BadRequest { .. } => "bad_request",
            Refusal::Unauthenticated { .. } => "unauthenticated",
            Refusal::Forbidden { .. } => "forbidden",
            Refusal::TooMany { .. } => "rate_limited",
            Refusal::Unavailable { .. } => "unavailable",
            Refusal::Internal { .. } => "internal",
        }
    }
}

impl From<KubeError> for Refusal {
    fn from(e: KubeError) -> Refusal {
        match e {
            KubeError::Unavailable(m) => Refusal::Unavailable { message: m },
            KubeError::Other(m) => Refusal::Internal { message: m },
        }
    }
}

/// A Vault failure. A policy denial from Vault is a 403 the broker's own
/// rules should have caught first; it is still a refusal, not an outage.
pub fn from_vault(e: Error) -> Refusal {
    match e {
        Error::Backend { status: 403, body } => {
            Refusal::forbidden("vault", format!("Vault denied: {body}"))
        }
        Error::Backend { status: 400, body } => {
            Refusal::bad("vault", format!("Vault refused: {body}"))
        }
        e if e.is_retryable() => Refusal::unavailable(format!("Vault: {e}")),
        e if e.code() == ErrorCode::Identity || e.code() == ErrorCode::Policy => {
            Refusal::forbidden("I7", e.to_string())
        }
        e => Refusal::Internal {
            message: format!("Vault: {e}"),
        },
    }
}
