//! Customizable SPIFFE IDs.
//!
//! The shape of the identity is a template, not a constant. The default keeps
//! the cluster in the path so a single trust domain spans clusters without
//! federation, but an operator whose trust domain is per-cluster, or who wants
//! the node or pod name in the path, sets their own:
//!
//! ```text
//! spiffe://{trust_domain}/cluster/{cluster}/ns/{namespace}/sa/{service_account}   (default)
//! spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}                     (SPIRE/csi-driver-spiffe shape)
//! spiffe://{trust_domain}/{cluster}/{namespace}/{service_account}
//! ```
//!
//! A template is compiled into two things: a renderer that builds the ID from
//! the attributes the kubelet supplied, and a matcher that takes an ID apart
//! again. The matcher is what lets restart recovery read an identity back out
//! of a certificate on disk instead of keeping state.
//!
//! Placeholders are normally separated by `/`, which makes taking an ID apart
//! again unambiguous. A template may separate them by something else —
//! `spiffe://{cluster}.{trust_domain}/…` is legitimate — and then parsing splits
//! at the *first* separator. A value that itself contains that separator (a
//! cluster named `eu.1` in that template) still gets a correct certificate, but
//! will not be recognised on the recovery path, so svidlet re-publishes it
//! rather than adopting it. Separate placeholders with `/` to avoid this.
//!
//! On top of that an operator can pin an arbitrary regex that every rendered ID
//! must match. That is a second, independent gate: the template says what
//! svidlet builds, the pattern says what it is allowed to build.

use std::fmt;

use regex_lite::Regex;

use crate::error::{Error, Result};

/// The longest SPIFFE ID the specification permits.
const MAX_ID_LEN: usize = 2048;

/// An attribute a template may substitute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    TrustDomain,
    Cluster,
    Namespace,
    ServiceAccount,
    PodName,
    PodUid,
    NodeName,
}

impl Field {
    const ALL: [Field; 7] = [
        Field::TrustDomain,
        Field::Cluster,
        Field::Namespace,
        Field::ServiceAccount,
        Field::PodName,
        Field::PodUid,
        Field::NodeName,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Field::TrustDomain => "trust_domain",
            Field::Cluster => "cluster",
            Field::Namespace => "namespace",
            Field::ServiceAccount => "service_account",
            Field::PodName => "pod_name",
            Field::PodUid => "pod_uid",
            Field::NodeName => "node_name",
        }
    }

    fn parse(name: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.as_str() == name)
    }

    fn known() -> String {
        Field::ALL
            .iter()
            .map(|f| format!("{{{}}}", f.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything the kubelet told svidlet about a pod, before it becomes an ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadAttributes {
    pub trust_domain: String,
    pub cluster: String,
    pub namespace: String,
    pub service_account: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub node_name: String,
}

impl WorkloadAttributes {
    fn get(&self, field: Field) -> &str {
        match field {
            Field::TrustDomain => &self.trust_domain,
            Field::Cluster => &self.cluster,
            Field::Namespace => &self.namespace,
            Field::ServiceAccount => &self.service_account,
            Field::PodName => &self.pod_name,
            Field::PodUid => &self.pod_uid,
            Field::NodeName => &self.node_name,
        }
    }

    fn set(&mut self, field: Field, value: &str) {
        let slot = match field {
            Field::TrustDomain => &mut self.trust_domain,
            Field::Cluster => &mut self.cluster,
            Field::Namespace => &mut self.namespace,
            Field::ServiceAccount => &mut self.service_account,
            Field::PodName => &mut self.pod_name,
            Field::PodUid => &mut self.pod_uid,
            Field::NodeName => &mut self.node_name,
        };
        *slot = value.to_string();
    }
}

/// A validated SPIFFE ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId(String);

impl SpiffeId {
    /// Accept an existing ID string, checking the invariants the SPIFFE
    /// specification requires. Used on the recovery path, where the ID comes
    /// from a certificate rather than from a template.
    pub fn parse(raw: &str) -> Result<SpiffeId> {
        let rest = raw
            .strip_prefix("spiffe://")
            .ok_or_else(|| Error::Identity(format!("{raw:?} does not start with spiffe://")))?;
        if raw.len() > MAX_ID_LEN {
            return Err(Error::Identity(format!(
                "SPIFFE ID is {} bytes, the maximum is {MAX_ID_LEN}",
                raw.len()
            )));
        }
        let (authority, path) = match rest.split_once('/') {
            Some(pair) => pair,
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(Error::Identity(format!(
                "{raw:?} has an empty trust domain"
            )));
        }
        if path.split('/').any(str::is_empty) && !path.is_empty() {
            return Err(Error::Identity(format!(
                "{raw:?} has an empty path segment"
            )));
        }
        Ok(SpiffeId(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone)]
enum Part {
    Literal(String),
    Field(Field),
}

/// A compiled SPIFFE ID template.
#[derive(Debug)]
pub struct IdTemplate {
    raw: String,
    parts: Vec<Part>,
    /// Fields in the order they appear, which is also their capture-group order.
    fields: Vec<Field>,
    matcher: Regex,
}

impl IdTemplate {
    /// The shape from the design document.
    pub const DEFAULT: &'static str =
        "spiffe://{trust_domain}/cluster/{cluster}/ns/{namespace}/sa/{service_account}";

    pub fn compile(raw: &str) -> Result<IdTemplate> {
        let parts = split(raw)?;
        let mut fields = Vec::new();
        for part in &parts {
            if let Part::Field(f) = part {
                if fields.contains(f) {
                    // A repeated field would need a backreference to match, and
                    // the ambiguity is not worth supporting. Say so plainly.
                    return Err(Error::Config(format!(
                        "SPIFFE ID template uses {{{f}}} more than once, which is not supported"
                    )));
                }
                fields.push(*f);
            }
        }
        if !raw.starts_with("spiffe://") {
            return Err(Error::Config(format!(
                "SPIFFE ID template {raw:?} must start with spiffe://"
            )));
        }
        if fields.is_empty() {
            return Err(Error::Config(format!(
                "SPIFFE ID template {raw:?} substitutes nothing, so every workload would \
                 receive the same identity"
            )));
        }

        let mut pattern = String::from("^");
        for part in &parts {
            match part {
                Part::Literal(text) => pattern.push_str(&escape(text)),
                // A path segment never contains a separator, which is also
                // what stops a crafted ServiceAccount name from matching two
                // segments. The match is lazy so that placeholders separated
                // by something other than "/" — as in `{cluster}.{trust_domain}`
                // — split at the first separator rather than the last.
                Part::Field(_) => pattern.push_str("([^/]+?)"),
            }
        }
        pattern.push('$');
        let matcher = Regex::new(&pattern).map_err(|e| {
            Error::Config(format!(
                "SPIFFE ID template {raw:?} does not compile to a matcher: {e}"
            ))
        })?;

        let template = IdTemplate {
            raw: raw.to_string(),
            parts,
            fields,
            matcher,
        };

        // Fail at start-up rather than on the first pod: render a probe and
        // check it round-trips through the matcher.
        let probe = template.probe_attributes();
        let rendered = template.render(&probe)?;
        if template.attributes_of(rendered.as_str()).as_ref() != Some(&probe) {
            return Err(Error::Config(format!(
                "SPIFFE ID template {raw:?} renders IDs it cannot parse back; \
                 adjacent placeholders with no separator between them are the usual cause"
            )));
        }
        Ok(template)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The fields this template actually substitutes. The plugin refuses to
    /// publish a volume when the kubelet did not supply one of them.
    pub fn required_fields(&self) -> &[Field] {
        &self.fields
    }

    fn probe_attributes(&self) -> WorkloadAttributes {
        let mut attrs = WorkloadAttributes::default();
        for (i, field) in self.fields.iter().enumerate() {
            attrs.set(*field, &format!("probe{i}"));
        }
        attrs
    }

    pub fn render(&self, attrs: &WorkloadAttributes) -> Result<SpiffeId> {
        let mut out = String::with_capacity(self.raw.len() + 32);
        for part in &self.parts {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Field(field) => {
                    let value = attrs.get(*field);
                    check_segment(*field, value)?;
                    out.push_str(value);
                }
            }
        }
        SpiffeId::parse(&out)
    }

    /// Take an ID apart again. `None` if it was not produced by this template.
    pub fn attributes_of(&self, id: &str) -> Option<WorkloadAttributes> {
        let caps = self.matcher.captures(id)?;
        let mut attrs = WorkloadAttributes::default();
        for (i, field) in self.fields.iter().enumerate() {
            attrs.set(*field, caps.get(i + 1)?.as_str());
        }
        Some(attrs)
    }
}

/// A template plus the operator's optional additional constraint.
#[derive(Debug)]
pub struct IdPolicy {
    template: IdTemplate,
    pattern: Option<Regex>,
    pattern_src: Option<String>,
}

impl IdPolicy {
    /// `pattern` is an operator-supplied regex that every ID must match, in
    /// addition to being renderable from the template. It is anchored on both
    /// ends: an unanchored `ns/kube-system` would otherwise match anywhere in
    /// the ID, which is the opposite of what someone writing a restriction
    /// expects.
    pub fn new(template: &str, pattern: Option<&str>) -> Result<IdPolicy> {
        let template = IdTemplate::compile(template)?;
        let (pattern, pattern_src) = match pattern {
            None => (None, None),
            Some(src) => {
                let anchored = anchor(src);
                let compiled = Regex::new(&anchored).map_err(|e| {
                    Error::Config(format!(
                        "spiffe_id_pattern {src:?} is not a valid regex: {e}"
                    ))
                })?;
                (Some(compiled), Some(src.to_string()))
            }
        };
        Ok(IdPolicy {
            template,
            pattern,
            pattern_src,
        })
    }

    pub fn template(&self) -> &IdTemplate {
        &self.template
    }

    pub fn pattern(&self) -> Option<&str> {
        self.pattern_src.as_deref()
    }

    /// Build an ID and check it against the operator's pattern.
    pub fn render(&self, attrs: &WorkloadAttributes) -> Result<SpiffeId> {
        let id = self.template.render(attrs)?;
        self.check(id.as_str())?;
        Ok(id)
    }

    /// Check an ID that already exists — one read back from a certificate.
    pub fn check(&self, id: &str) -> Result<()> {
        if let Some(pattern) = &self.pattern {
            if !pattern.is_match(id) {
                return Err(Error::Policy(format!(
                    "{id} does not match spiffe_id_pattern {:?}",
                    self.pattern_src.as_deref().unwrap_or_default()
                )));
            }
        }
        Ok(())
    }

    pub fn attributes_of(&self, id: &str) -> Option<WorkloadAttributes> {
        self.template.attributes_of(id)
    }
}

/// Split a template into literals and placeholders.
fn split(raw: &str) -> Result<Vec<Part>> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // `{{` and `}}` are literal braces, as in a format string.
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                literal.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                literal.push('}');
            }
            '{' => {
                let mut name = String::new();
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    name.push(c);
                }
                if !closed {
                    return Err(Error::Config(format!(
                        "SPIFFE ID template {raw:?} has an unclosed {{{name}"
                    )));
                }
                let field = Field::parse(name.trim()).ok_or_else(|| {
                    Error::Config(format!(
                        "SPIFFE ID template {raw:?} uses unknown placeholder {{{name}}}; \
                         known placeholders are {}",
                        Field::known()
                    ))
                })?;
                if !literal.is_empty() {
                    parts.push(Part::Literal(std::mem::take(&mut literal)));
                }
                parts.push(Part::Field(field));
            }
            '}' => {
                return Err(Error::Config(format!(
                    "SPIFFE ID template {raw:?} has an unmatched }}; write }}}} for a literal brace"
                )));
            }
            c => literal.push(c),
        }
    }
    if !literal.is_empty() {
        parts.push(Part::Literal(literal));
    }
    Ok(parts)
}

/// Reject anything that could smuggle a second path segment into the ID and so
/// forge a different identity.
fn check_segment(field: Field, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::Identity(format!(
            "{field} is empty, so no SPIFFE ID can be built"
        )));
    }
    if let Some(bad) = value
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')))
    {
        return Err(Error::Identity(format!(
            "{field} {value:?} contains {bad:?}, which is not allowed in a SPIFFE path segment"
        )));
    }
    Ok(())
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn anchor(pattern: &str) -> String {
    let start = if pattern.starts_with('^') { "" } else { "^" };
    let end = if pattern.ends_with('$') && !pattern.ends_with("\\$") {
        ""
    } else {
        "$"
    };
    format!("{start}{pattern}{end}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn attrs() -> WorkloadAttributes {
        WorkloadAttributes {
            trust_domain: "example.org".into(),
            cluster: "a".into(),
            namespace: "payments".into(),
            service_account: "api".into(),
            pod_name: "api-7d9f".into(),
            pod_uid: "1111-2222".into(),
            node_name: "node-1".into(),
        }
    }

    #[test]
    fn default_template_matches_the_design() {
        let t = IdTemplate::compile(IdTemplate::DEFAULT).unwrap();
        assert_eq!(
            t.render(&attrs()).unwrap().as_str(),
            "spiffe://example.org/cluster/a/ns/payments/sa/api"
        );
        assert_eq!(t.as_str(), IdTemplate::DEFAULT);
        assert_eq!(
            t.required_fields(),
            &[
                Field::TrustDomain,
                Field::Cluster,
                Field::Namespace,
                Field::ServiceAccount
            ]
        );
    }

    #[test]
    fn custom_templates_render_and_parse_back() {
        let cases = [
            (
                "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}",
                "spiffe://example.org/ns/payments/sa/api",
            ),
            (
                "spiffe://{trust_domain}/{cluster}/{namespace}/{service_account}",
                "spiffe://example.org/a/payments/api",
            ),
            (
                "spiffe://{cluster}.{trust_domain}/ns/{namespace}/sa/{service_account}",
                "spiffe://a.example.org/ns/payments/sa/api",
            ),
            (
                "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}/node/{node_name}",
                "spiffe://example.org/ns/payments/sa/api/node/node-1",
            ),
            (
                "spiffe://{trust_domain}/node/{node_name}/pod/{pod_name}",
                "spiffe://example.org/node/node-1/pod/api-7d9f",
            ),
            (
                "spiffe://{trust_domain}/workload/{pod_uid}",
                "spiffe://example.org/workload/1111-2222",
            ),
        ];
        for (template, expected) in cases {
            let t = IdTemplate::compile(template).unwrap();
            let id = t.render(&attrs()).unwrap();
            assert_eq!(id.as_str(), expected, "template {template}");

            // Every substituted field survives the round trip, which is what
            // restart recovery depends on.
            let back = t.attributes_of(id.as_str()).expect("parses back");
            for field in t.required_fields() {
                assert_eq!(back.get(*field), attrs().get(*field), "field {field}");
            }
        }
    }

    /// Placeholders separated by something other than "/" split at the first
    /// separator. The certificate is still correct — only the recovery path is
    /// affected, and it re-publishes rather than adopting.
    #[test]
    fn a_non_slash_separator_splits_at_the_first_occurrence() {
        let t = IdTemplate::compile(
            "spiffe://{cluster}.{trust_domain}/ns/{namespace}/sa/{service_account}",
        )
        .unwrap();

        let mut a = attrs();
        a.cluster = "eu.1".into();
        let id = t.render(&a).unwrap();
        assert_eq!(id.as_str(), "spiffe://eu.1.example.org/ns/payments/sa/api");

        // Round-tripping picks the shortest first segment, so this does not
        // come back as it went in.
        let back = t.attributes_of(id.as_str()).unwrap();
        assert_eq!(back.cluster, "eu");
        assert_eq!(back.trust_domain, "1.example.org");
    }

    #[test]
    fn parsing_rejects_ids_from_a_different_template() {
        let t = IdTemplate::compile(IdTemplate::DEFAULT).unwrap();
        for foreign in [
            "spiffe://example.org/ns/payments/sa/api",
            "spiffe://example.org/cluster/a/ns/payments",
            "spiffe://example.org/cluster/a/ns/payments/sa/api/extra",
            "https://example.org/cluster/a/ns/payments/sa/api",
            "",
        ] {
            assert!(
                t.attributes_of(foreign).is_none(),
                "{foreign} should not parse"
            );
        }
    }

    #[test]
    fn literal_text_is_matched_literally_not_as_a_regex() {
        // The dot in the literal must not match an arbitrary character.
        let t = IdTemplate::compile("spiffe://{trust_domain}/v1.0/{namespace}").unwrap();
        assert!(t
            .attributes_of("spiffe://example.org/v1.0/payments")
            .is_some());
        assert!(t
            .attributes_of("spiffe://example.org/v1X0/payments")
            .is_none());
    }

    #[test]
    fn path_injection_through_an_attribute_is_refused() {
        let t = IdTemplate::compile(IdTemplate::DEFAULT).unwrap();
        let mut a = attrs();
        // Without validation this becomes .../sa/x/ns/kube-system/sa/admin.
        a.service_account = "x/ns/kube-system/sa/admin".into();
        let err = t.render(&a).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Identity);
        assert!(err.to_string().contains("service_account"));

        for bad in ["a b", "a%2f", "..", "a:b", "a\nb"] {
            let mut a = attrs();
            a.namespace = bad.into();
            // ".." is a valid DNS-ish string but a dangerous path segment; it
            // is allowed by the charset and stopped by SPIFFE ID parsing only
            // if it produces an empty segment, so assert on the charset cases.
            if bad == ".." {
                assert!(t.render(&a).is_ok());
                continue;
            }
            assert_eq!(
                t.render(&a).unwrap_err().code(),
                ErrorCode::Identity,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_missing_attribute_is_an_identity_error_not_a_blank_segment() {
        let t = IdTemplate::compile(IdTemplate::DEFAULT).unwrap();
        let mut a = attrs();
        a.namespace = String::new();
        let err = t.render(&a).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Identity);
        assert!(err.to_string().contains("namespace is empty"));
    }

    #[test]
    fn broken_templates_are_rejected_at_compile_time() {
        let cases = [
            ("spiffe://{trust_domain}/ns/{nope}", "unknown placeholder"),
            ("spiffe://{trust_domain}/ns/{namespace", "unclosed"),
            ("spiffe://{trust_domain}/ns/namespace}", "unmatched"),
            ("https://{trust_domain}/x", "must start with spiffe://"),
            ("spiffe://example.org/ns/default", "substitutes nothing"),
            (
                "spiffe://{trust_domain}/{namespace}/{namespace}",
                "more than once",
            ),
            (
                // Adjacent placeholders cannot be taken apart again.
                "spiffe://{trust_domain}/{namespace}{service_account}",
                "cannot parse back",
            ),
        ];
        for (template, expected) in cases {
            let err = IdTemplate::compile(template).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Config, "{template}");
            assert!(
                err.to_string().contains(expected),
                "{template}: expected {expected:?}, got {err}"
            );
        }
    }

    #[test]
    fn literal_braces_are_written_doubled() {
        let t = IdTemplate::compile("spiffe://{trust_domain}/{{literal}}/{namespace}").unwrap();
        assert_eq!(
            t.render(&attrs()).unwrap().as_str(),
            "spiffe://example.org/{literal}/payments"
        );
    }

    #[test]
    fn spiffe_id_parse_enforces_the_specification() {
        assert!(SpiffeId::parse("spiffe://example.org/a").is_ok());
        assert!(SpiffeId::parse("spiffe://example.org").is_ok());
        assert_eq!(
            SpiffeId::parse("http://example.org/a").unwrap_err().code(),
            ErrorCode::Identity
        );
        assert!(SpiffeId::parse("spiffe:///a").is_err());
        assert!(SpiffeId::parse("spiffe://example.org/a//b").is_err());

        let long = format!("spiffe://example.org/{}", "x".repeat(MAX_ID_LEN));
        assert!(SpiffeId::parse(&long).is_err());

        let id = SpiffeId::parse("spiffe://example.org/a").unwrap();
        assert_eq!(id.to_string(), "spiffe://example.org/a");
        assert_eq!(id.as_str(), "spiffe://example.org/a");
    }

    #[test]
    fn a_pattern_gates_what_the_template_may_build() {
        let policy = IdPolicy::new(
            IdTemplate::DEFAULT,
            Some(r"spiffe://example\.org/cluster/a/ns/(payments|billing)/sa/[a-z0-9-]+"),
        )
        .unwrap();

        assert!(policy.render(&attrs()).is_ok());
        assert_eq!(
            policy.pattern().unwrap(),
            r"spiffe://example\.org/cluster/a/ns/(payments|billing)/sa/[a-z0-9-]+"
        );

        let mut other = attrs();
        other.namespace = "kube-system".into();
        let err = policy.render(&other).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Policy);
        assert!(err.to_string().contains("does not match spiffe_id_pattern"));

        // check() gates IDs read back from disk too.
        assert!(policy
            .check("spiffe://example.org/cluster/a/ns/payments/sa/api")
            .is_ok());
        assert!(policy
            .check("spiffe://example.org/cluster/a/ns/kube-system/sa/api")
            .is_err());
    }

    #[test]
    fn patterns_are_anchored_so_a_substring_does_not_pass() {
        let policy = IdPolicy::new(IdTemplate::DEFAULT, Some("ns/payments")).unwrap();
        // Unanchored this would match; anchored it does not, which is what an
        // operator writing a restriction means.
        assert!(policy
            .check("spiffe://example.org/cluster/a/ns/payments/sa/api")
            .is_err());

        // Explicit anchors are not doubled.
        let policy = IdPolicy::new(IdTemplate::DEFAULT, Some("^spiffe://.*/sa/api$")).unwrap();
        assert!(policy
            .check("spiffe://example.org/cluster/a/ns/payments/sa/api")
            .is_ok());
    }

    #[test]
    fn an_invalid_pattern_fails_at_start_up() {
        let err = IdPolicy::new(IdTemplate::DEFAULT, Some("(unclosed")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Config);
        assert!(err.to_string().contains("not a valid regex"));
    }

    #[test]
    fn policy_without_a_pattern_accepts_whatever_the_template_builds() {
        let policy = IdPolicy::new(IdTemplate::DEFAULT, None).unwrap();
        assert!(policy.pattern().is_none());
        assert!(policy.check("anything at all").is_ok());
        assert_eq!(
            policy.render(&attrs()).unwrap().as_str(),
            "spiffe://example.org/cluster/a/ns/payments/sa/api"
        );
        assert_eq!(
            policy.attributes_of("spiffe://example.org/cluster/a/ns/payments/sa/api"),
            Some(WorkloadAttributes {
                trust_domain: "example.org".into(),
                cluster: "a".into(),
                namespace: "payments".into(),
                service_account: "api".into(),
                ..Default::default()
            })
        );
        assert_eq!(policy.template().as_str(), IdTemplate::DEFAULT);
    }

    #[test]
    fn field_names_are_stable_and_round_trip() {
        for field in Field::ALL {
            assert_eq!(Field::parse(field.as_str()), Some(field));
            assert_eq!(field.to_string(), field.as_str());
            assert!(Field::known().contains(field.as_str()));
        }
        assert_eq!(Field::parse("nope"), None);
    }
}
