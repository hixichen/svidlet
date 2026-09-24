//! Audiences a pod asks for, and the file each token lands in.
//!
//! A pod declares its audiences in the volume, not in code, mirroring
//! projected `ServiceAccount` tokens:
//!
//! ```yaml
//! csi:
//!   driver: csi.svidlet.io
//!   volumeAttributes:
//!     audiences: "azure=api://AzureADTokenExchange,snowflake"
//! ```
//!
//! Each entry is `name=audience` or a bare `audience`. The name is the file
//! the token is written to, `jwt/<name>`; a bare audience must itself be a
//! valid name. Names exist because real audiences are URIs — Azure's is
//! `api://AzureADTokenExchange` — and a URI is not a file name.
//!
//! Declaring an audience is a request, not a grant. The issuer decides, per
//! SPIFFE ID, which audiences a workload may have.

use std::fmt;

/// The most audiences one volume may declare. Each costs a signature per
/// certificate renewal, and a pod needing more than a handful is more likely a
/// mistake than a design.
pub const MAX_AUDIENCES: usize = 8;

/// The longest audience accepted. Generous for a URI, and small enough that a
/// token request stays one packet.
const MAX_AUDIENCE_LEN: usize = 256;

/// The longest file name: a DNS label, so it is also safe as a Kubernetes name.
const MAX_NAME_LEN: usize = 63;

/// One audience a pod asked for, and the file its token is written to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Audience {
    name: String,
    value: String,
}

impl Audience {
    /// Build an audience, checking both parts.
    ///
    /// # Errors
    ///
    /// [`AudienceError`] when `name` is not a DNS label (lowercase letters,
    /// digits and inner hyphens, at most 63), or `value` is empty, longer
    /// than 256 bytes, or contains whitespace, a comma or non-ASCII.
    pub fn new(name: &str, value: &str) -> Result<Audience, AudienceError> {
        if !is_name(name) {
            return Err(AudienceError(format!(
                "{name:?} is not a token file name: use lowercase letters, digits and \
                 inner hyphens, at most {MAX_NAME_LEN}"
            )));
        }
        if value.is_empty()
            || value.len() > MAX_AUDIENCE_LEN
            || !value.bytes().all(|b| b.is_ascii_graphic() && b != b',')
        {
            return Err(AudienceError(format!(
                "{value:?} is not an audience: printable ASCII without commas, \
                 1 to {MAX_AUDIENCE_LEN} bytes"
            )));
        }
        Ok(Audience {
            name: name.to_string(),
            value: value.to_string(),
        })
    }

    /// The file name under `jwt/`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `aud` claim.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.name == self.value {
            f.write_str(&self.value)
        } else {
            write!(f, "{}={}", self.name, self.value)
        }
    }
}

/// Parse a volume's `audiences` attribute.
///
/// Blank means none. Entries are separated by commas and trimmed.
///
/// # Errors
///
/// [`AudienceError`] for a malformed entry, two entries with the same name, or
/// more than [`MAX_AUDIENCES`] entries.
pub fn parse_audiences(text: &str) -> Result<Vec<Audience>, AudienceError> {
    let mut out: Vec<Audience> = Vec::new();
    for entry in text.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let audience = match entry.split_once('=') {
            Some((name, value)) => Audience::new(name.trim(), value.trim())?,
            None => Audience::new(entry, entry)?,
        };
        if out.iter().any(|a| a.name == audience.name) {
            return Err(AudienceError(format!(
                "the token file name {:?} is used twice",
                audience.name
            )));
        }
        out.push(audience);
    }
    if out.len() > MAX_AUDIENCES {
        return Err(AudienceError(format!(
            "{} audiences requested; at most {MAX_AUDIENCES}",
            out.len()
        )));
    }
    Ok(out)
}

fn is_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_NAME_LEN
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

/// An `audiences` attribute, or one entry of it, that cannot be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceError(String);

impl fmt::Display for AudienceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid audiences: {}", self.0)
    }
}

impl std::error::Error for AudienceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_and_bare_entries_both_parse() {
        let got = parse_audiences(" azure=api://AzureADTokenExchange , snowflake ").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name(), "azure");
        assert_eq!(got[0].value(), "api://AzureADTokenExchange");
        assert_eq!(got[1].name(), "snowflake");
        assert_eq!(got[1].value(), "snowflake");
        assert_eq!(got[0].to_string(), "azure=api://AzureADTokenExchange");
        assert_eq!(got[1].to_string(), "snowflake");
    }

    #[test]
    fn blank_means_none() {
        assert_eq!(parse_audiences("").unwrap(), vec![]);
        assert_eq!(parse_audiences(" , ").unwrap(), vec![]);
    }

    #[test]
    fn a_uri_needs_a_name_because_it_is_not_a_file_name() {
        let err = parse_audiences("api://AzureADTokenExchange").unwrap_err();
        assert!(err.to_string().contains("not a token file name"), "{err}");
    }

    #[test]
    fn names_cannot_escape_the_jwt_directory() {
        for bad in [
            "../x=a",
            ".hidden=a",
            "a/b=a",
            "UPPER=a",
            "-lead=a",
            "trail-=a",
            "=a",
        ] {
            let _ = parse_audiences(bad).expect_err(&format!("{bad:?}"));
        }
        let _ = parse_audiences(&format!("{}=a", "x".repeat(64))).unwrap_err();
        parse_audiences(&format!("{}=a", "x".repeat(63))).unwrap();
    }

    #[test]
    fn audiences_are_printable_and_bounded() {
        for bad in ["n=", "n=has space", "n=tab\there", "n=é"] {
            let _ = parse_audiences(bad).expect_err(&format!("{bad:?}"));
        }
        let _ = parse_audiences(&format!("n={}", "a".repeat(257))).unwrap_err();
        parse_audiences(&format!("n={}", "a".repeat(256))).unwrap();
    }

    #[test]
    fn a_name_may_be_used_once() {
        let err = parse_audiences("a=x,a=y").unwrap_err();
        assert!(err.to_string().contains("used twice"), "{err}");
    }

    #[test]
    fn the_count_is_bounded() {
        let at_limit: Vec<String> = (0..MAX_AUDIENCES).map(|i| format!("a{i}")).collect();
        assert_eq!(
            parse_audiences(&at_limit.join(",")).unwrap().len(),
            MAX_AUDIENCES
        );
        let over: Vec<String> = (0..=MAX_AUDIENCES).map(|i| format!("a{i}")).collect();
        let _ = parse_audiences(&over.join(",")).unwrap_err();
    }
}
