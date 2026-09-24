//! The payload of a JWT-SVID.

use std::fmt;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The claims the issuer puts in every token.
///
/// `aud` is always a single string: one token per audience keeps a leaked
/// token useful to one relying party only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// The issuer URL, one per security boundary (prod, non-prod).
    pub iss: String,
    /// The pod's SPIFFE ID.
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub nbf: i64,
    /// Never later than the pod certificate's `notAfter`.
    pub exp: i64,
    /// Unique per token, for audit and for relying parties that track replay.
    pub jti: String,
}

impl Claims {
    /// Read the claims of a compact JWS without verifying its signature.
    ///
    /// For svidlet reading back tokens it wrote itself — restart recovery
    /// learns a volume's audiences and expiries this way. Never a basis for
    /// trusting a token: anyone can write a payload.
    ///
    /// # Errors
    ///
    /// [`ClaimsError`] when `token` is not three dot-separated base64url parts
    /// whose middle one is these claims in JSON.
    pub fn read_unverified(token: &str) -> Result<Claims, ClaimsError> {
        let mut parts = token.trim().split('.');
        let (Some(_), Some(payload), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ClaimsError("not a compact JWS".into()));
        };
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| ClaimsError(format!("payload is not base64url: {e}")))?;
        serde_json::from_slice(&json)
            .map_err(|e| ClaimsError(format!("payload is not JWT-SVID claims: {e}")))
    }
}

/// A token whose claims cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimsError(String);

impl fmt::Display for ClaimsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ClaimsError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn claims_round_trip_through_a_token() {
        let claims = Claims {
            iss: "https://example.org".into(),
            sub: "spiffe://example.org/cluster/a/ns/p/sa/api".into(),
            aud: "api://AzureADTokenExchange".into(),
            iat: 100,
            nbf: 100,
            exp: 200,
            jti: "abc".into(),
        };
        let token = format!(
            "{}.{}.{}",
            b64(br#"{"alg":"ES256"}"#),
            b64(&serde_json::to_vec(&claims).unwrap()),
            b64(b"sig")
        );
        assert_eq!(Claims::read_unverified(&token).unwrap(), claims);
        assert_eq!(
            Claims::read_unverified(&format!(" {token}\n")).unwrap(),
            claims
        );
    }

    #[test]
    fn anything_else_is_an_error() {
        for bad in [
            "",
            "a.b",
            "a.b.c.d",
            "a.!!.c",
            &format!("a.{}.c", b64(b"{}")),
        ] {
            let _ = Claims::read_unverified(bad).expect_err(&format!("{bad:?}"));
        }
    }
}
