//! The authentication seam.
//!
//! Obtaining a credential and using it to sign are separate concerns, and they
//! change for different reasons: a new PKI vendor replaces [`Issuer`], a new way
//! of proving who the node is replaces [`TokenSource`]. Keeping them apart is
//! what lets Vault AppRole be swapped for Vault Kubernetes auth, for cloud IAM,
//! or for whatever a future backend wants, without touching issuance.
//!
//! [`TokenCache`] holds the part every bearer-token backend needs anyway —
//! when to renew, when to give up and log in again — so an implementation only
//! has to answer "how do I log in".
//!
//! [`Issuer`]: crate::issuer::Issuer

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Refresh this long before a lease ends, so a slow renewal never leaves the
/// plugin holding an expired credential mid-issuance.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// A bearer credential and what the backend said about its lifetime.
#[derive(Debug, Clone)]
pub struct Token {
    pub value: String,
    /// Seconds the token is valid for. Zero means "no expiry advertised",
    /// which the cache treats as a long-lived token it still re-checks daily.
    pub lease_secs: u64,
    /// Whether the backend will extend this token in place.
    pub renewable: bool,
}

impl Token {
    pub fn new(value: impl Into<String>, lease_secs: u64, renewable: bool) -> Token {
        Token {
            value: value.into(),
            lease_secs,
            renewable,
        }
    }

    /// A credential the backend never expires — a static token from a file.
    pub fn permanent(value: impl Into<String>) -> Token {
        Token {
            value: value.into(),
            lease_secs: 0,
            renewable: false,
        }
    }
}

/// A way of proving to a PKI backend who this node is.
///
/// Implementations are shared across threads and called from a blocking pool.
pub trait TokenSource: Send + Sync {
    /// Obtain a fresh credential. Called at start-up, and again whenever the
    /// current one can no longer be renewed.
    ///
    /// Implementations should re-read whatever material they authenticate with
    /// on every call rather than caching it, so rotating a mounted secret takes
    /// effect without restarting the process.
    fn login(&self) -> Result<Token>;

    /// Extend the current credential in place.
    ///
    /// The default gives up, which makes the cache log in again — correct for
    /// any method whose credentials cannot be extended.
    fn renew(&self, _token: &str) -> Result<Token> {
        Err(Error::Auth(
            "this authentication method cannot renew; logging in again".into(),
        ))
    }

    /// Short name for logs and metric labels, e.g. `approle`.
    fn name(&self) -> &'static str;
}

/// Holds the current credential and decides when to renew or re-login.
///
/// This is the part every bearer-token backend would otherwise reimplement, and
/// it is where the "log in once, keep a periodic token" behaviour the design
/// calls for actually lives — issuance never triggers a login of its own.
pub struct TokenCache<S: TokenSource> {
    source: S,
    state: Mutex<Option<Held>>,
}

struct Held {
    token: Token,
    refresh_at: Instant,
}

impl<S: TokenSource> TokenCache<S> {
    pub fn new(source: S) -> TokenCache<S> {
        TokenCache {
            source,
            state: Mutex::new(None),
        }
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    /// Return a usable credential, renewing or re-logging in as needed.
    pub fn token(&self) -> Result<String> {
        let mut guard = self.state.lock().expect("token cache poisoned");

        if let Some(held) = guard.as_ref() {
            if Instant::now() < held.refresh_at {
                return Ok(held.token.value.clone());
            }
            if held.token.renewable {
                match self.source.renew(&held.token.value) {
                    Ok(renewed) => {
                        let value = renewed.value.clone();
                        *guard = Some(Held {
                            refresh_at: refresh_deadline(renewed.lease_secs),
                            token: renewed,
                        });
                        return Ok(value);
                    }
                    // A credential that cannot be renewed is replaced, not
                    // retried: it may have hit its maximum TTL, or the backend
                    // may have restarted and forgotten it.
                    Err(_) => *guard = None,
                }
            }
        }

        let fresh = self.source.login()?;
        let value = fresh.value.clone();
        *guard = Some(Held {
            refresh_at: refresh_deadline(fresh.lease_secs),
            token: fresh,
        });
        Ok(value)
    }

    /// Drop the cached credential so the next call authenticates again.
    ///
    /// Called when the backend rejects a token that the cache still believed
    /// was good — the other half of surviving a credential rotation without a
    /// restart.
    pub fn invalidate(&self) {
        *self.state.lock().expect("token cache poisoned") = None;
    }
}

/// Refresh at two thirds of the lease, and never later than [`REFRESH_MARGIN`]
/// before it ends.
fn refresh_deadline(lease_secs: u64) -> Instant {
    if lease_secs == 0 {
        // No advertised expiry. Re-check daily rather than never, so a token
        // revoked out from under us is noticed without a restart.
        return Instant::now() + Duration::from_secs(86_400);
    }
    let lease = Duration::from_secs(lease_secs);
    let two_thirds = lease.mul_f32(2.0 / 3.0);
    let margin = lease.saturating_sub(REFRESH_MARGIN);
    Instant::now() + two_thirds.min(margin).max(Duration::from_secs(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Fake {
        logins: AtomicUsize,
        renewals: AtomicUsize,
        lease_secs: u64,
        renewable: bool,
        renew_fails: bool,
        login_fails: bool,
    }

    impl TokenSource for Fake {
        fn login(&self) -> Result<Token> {
            if self.login_fails {
                return Err(Error::Auth("rejected".into()));
            }
            let n = self.logins.fetch_add(1, Ordering::SeqCst);
            Ok(Token::new(
                format!("token-{n}"),
                self.lease_secs,
                self.renewable,
            ))
        }

        fn renew(&self, _token: &str) -> Result<Token> {
            if self.renew_fails {
                return Err(Error::Auth("cannot renew".into()));
            }
            let n = self.renewals.fetch_add(1, Ordering::SeqCst);
            Ok(Token::new(
                format!("renewed-{n}"),
                self.lease_secs,
                self.renewable,
            ))
        }

        fn name(&self) -> &'static str {
            "fake"
        }
    }

    #[test]
    fn a_valid_token_is_reused_rather_than_re_fetched() {
        let cache = TokenCache::new(Fake {
            lease_secs: 3600,
            ..Default::default()
        });
        assert_eq!(cache.token().unwrap(), "token-0");
        assert_eq!(cache.token().unwrap(), "token-0");
        assert_eq!(cache.token().unwrap(), "token-0");
        assert_eq!(cache.source().logins.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_expired_renewable_token_is_renewed_in_place() {
        let cache = TokenCache::new(Fake {
            lease_secs: 3600,
            renewable: true,
            ..Default::default()
        });
        assert_eq!(cache.token().unwrap(), "token-0");
        // Force the deadline into the past.
        cache.state.lock().unwrap().as_mut().unwrap().refresh_at =
            Instant::now() - Duration::from_secs(1);

        assert_eq!(cache.token().unwrap(), "renewed-0");
        assert_eq!(cache.source().logins.load(Ordering::SeqCst), 1);
        assert_eq!(cache.source().renewals.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_token_that_cannot_be_renewed_is_replaced_by_a_fresh_login() {
        let cache = TokenCache::new(Fake {
            lease_secs: 3600,
            renewable: true,
            renew_fails: true,
            ..Default::default()
        });
        assert_eq!(cache.token().unwrap(), "token-0");
        cache.state.lock().unwrap().as_mut().unwrap().refresh_at =
            Instant::now() - Duration::from_secs(1);

        assert_eq!(cache.token().unwrap(), "token-1");
        assert_eq!(cache.source().logins.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_non_renewable_token_goes_straight_to_a_new_login() {
        let cache = TokenCache::new(Fake {
            lease_secs: 60,
            renewable: false,
            ..Default::default()
        });
        assert_eq!(cache.token().unwrap(), "token-0");
        cache.state.lock().unwrap().as_mut().unwrap().refresh_at =
            Instant::now() - Duration::from_secs(1);

        assert_eq!(cache.token().unwrap(), "token-1");
        assert_eq!(cache.source().renewals.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn invalidate_forces_the_next_call_to_authenticate_again() {
        let cache = TokenCache::new(Fake {
            lease_secs: 3600,
            ..Default::default()
        });
        assert_eq!(cache.token().unwrap(), "token-0");
        cache.invalidate();
        assert_eq!(cache.token().unwrap(), "token-1");
    }

    #[test]
    fn a_failed_login_surfaces_as_an_auth_error() {
        let cache = TokenCache::new(Fake {
            login_fails: true,
            ..Default::default()
        });
        let err = cache.token().unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::Auth);
        assert!(err.is_retryable());
    }

    #[test]
    fn the_default_renew_implementation_declines() {
        struct NoRenew;
        impl TokenSource for NoRenew {
            fn login(&self) -> Result<Token> {
                Ok(Token::permanent("static"))
            }
            fn name(&self) -> &'static str {
                "no-renew"
            }
        }
        let source = NoRenew;
        assert!(source.renew("x").is_err());
        assert_eq!(source.name(), "no-renew");

        let cache = TokenCache::new(NoRenew);
        assert_eq!(cache.token().unwrap(), "static");
    }

    #[test]
    fn refresh_always_lands_before_the_lease_ends() {
        let now = Instant::now();
        let in_secs = |at: Instant| at.duration_since(now).as_secs();

        assert!((2300..=2400).contains(&in_secs(refresh_deadline(3600))));
        // Short leases still refresh strictly before expiry.
        assert!(in_secs(refresh_deadline(30)) < 30);
        assert!(in_secs(refresh_deadline(1)) < 2);
        // No advertised expiry: re-check daily rather than never.
        assert_eq!(in_secs(refresh_deadline(0)), 86_400);
    }

    #[test]
    fn token_constructors_carry_their_lease() {
        let t = Token::new("v", 10, true);
        assert_eq!(
            (t.value.as_str(), t.lease_secs, t.renewable),
            ("v", 10, true)
        );
        let p = Token::permanent("v");
        assert_eq!((p.lease_secs, p.renewable), (0, false));
    }
}
