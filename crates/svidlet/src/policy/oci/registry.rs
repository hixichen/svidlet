//! A read-only OCI distribution client.
//!
//! Only what pulling a signed artifact needs: fetch a manifest by tag with an
//! ETag so an unchanged manifest costs one 304, and fetch a blob by digest.
//! Nothing is ever pushed.

use std::time::Duration;

use serde::Deserialize;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;

use super::Error;

/// A parsed `registry/repository:tag` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    /// `https` unless the registry is plainly local.
    pub scheme: &'static str,
}

impl Reference {
    /// Parse `registry.example.com/policy/rollout:current`.
    ///
    /// The tag defaults to `latest`, matching every other OCI tool. `http` is
    /// used only for `localhost` and `127.0.0.1`, so a typo cannot silently
    /// downgrade a production pull to plaintext.
    pub fn parse(raw: &str) -> Result<Reference, Error> {
        let raw = raw.trim();
        let raw = raw.strip_prefix("oci://").unwrap_or(raw);
        if raw.is_empty() {
            return Err(Error::Config("the registry reference is empty".into()));
        }

        let (registry, rest) = raw.split_once('/').ok_or_else(|| {
            Error::Config(format!(
                "{raw:?} is not a registry reference; expected registry/repository:tag"
            ))
        })?;
        if registry.is_empty() || rest.is_empty() {
            return Err(Error::Config(format!(
                "{raw:?} is not a registry reference"
            )));
        }

        // A colon after the last slash is a tag; one before it is a port.
        let (repository, tag) = match rest.rsplit_once(':') {
            Some((repo, tag)) if !tag.contains('/') && !tag.is_empty() => (repo, tag),
            _ => (rest, "latest"),
        };
        if repository.is_empty() {
            return Err(Error::Config(format!("{raw:?} has no repository")));
        }

        let host = registry.split(':').next().unwrap_or(registry);
        let scheme = if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            "http"
        } else {
            "https"
        };

        Ok(Reference {
            registry: registry.to_string(),
            repository: repository.to_string(),
            tag: tag.to_string(),
            scheme,
        })
    }

    /// The same repository, addressed by digest instead of tag.
    pub fn blob_url(&self, digest: &str) -> String {
        format!(
            "{}://{}/v2/{}/blobs/{digest}",
            self.scheme, self.registry, self.repository
        )
    }

    pub fn manifest_url(&self) -> String {
        format!(
            "{}://{}/v2/{}/manifests/{}",
            self.scheme, self.registry, self.repository, self.tag
        )
    }
}

/// An OCI image manifest, reduced to the parts an artifact pull needs.
#[derive(Debug, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
pub struct Descriptor {
    pub digest: String,
    #[serde(default)]
    pub size: u64,
}

/// What a conditional manifest fetch returned.
pub enum Fetched {
    /// The registry confirmed nothing changed.
    Unchanged,
    Changed {
        manifest: Manifest,
        etag: Option<String>,
    },
}

pub struct Registry {
    agent: Agent,
    /// A bearer token for registries that want one, read from a file on every
    /// use so a rotated token needs no restart.
    token_path: Option<std::path::PathBuf>,
    max_blob_bytes: usize,
}

impl Registry {
    pub fn new(
        ca_cert_pem: Option<String>,
        token_path: Option<std::path::PathBuf>,
        timeout: Duration,
        max_blob_bytes: usize,
    ) -> Result<Registry, Error> {
        let mut tls = TlsConfig::builder();
        if let Some(pem) = &ca_cert_pem {
            let cert = Certificate::from_pem(pem.as_bytes()).map_err(|e| {
                Error::Config(format!("the registry CA certificate is not valid PEM: {e}"))
            })?;
            tls = tls.root_certs(RootCerts::new_with_certs(&[cert]));
        }
        let config = Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .tls_config(tls.build())
            .build();

        Ok(Registry {
            agent: config.into(),
            token_path,
            max_blob_bytes,
        })
    }

    fn token(&self) -> Option<String> {
        let path = self.token_path.as_ref()?;
        std::fs::read_to_string(path)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    }

    /// Fetch a manifest, returning [`Fetched::Unchanged`] on a 304.
    pub fn manifest(&self, reference: &Reference, etag: Option<&str>) -> Result<Fetched, Error> {
        let url = reference.manifest_url();
        let mut request = self.agent.get(&url).header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, \
                 application/vnd.docker.distribution.manifest.v2+json",
        );
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }
        if let Some(token) = self.token() {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }

        let mut response = request
            .call()
            .map_err(|e| Error::Fetch(format!("GET {url}: {e}")))?;

        let status = response.status().as_u16();
        if status == 304 {
            return Ok(Fetched::Unchanged);
        }
        if !(200..300).contains(&status) {
            return Err(Error::Fetch(format!(
                "GET {url}: HTTP {status} {}",
                first_line(&response.body_mut().read_to_string().unwrap_or_default())
            )));
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Fetch(format!("GET {url}: {e}")))?;
        let manifest: Manifest = serde_json::from_str(&body)
            .map_err(|e| Error::Malformed(format!("{url} is not an OCI manifest: {e}")))?;

        Ok(Fetched::Changed { manifest, etag })
    }

    /// Fetch a blob by digest, refusing anything over the size limit.
    pub fn blob(&self, reference: &Reference, digest: &str) -> Result<Vec<u8>, Error> {
        let url = reference.blob_url(digest);
        let mut request = self.agent.get(&url);
        if let Some(token) = self.token() {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }

        let mut response = request
            .call()
            .map_err(|e| Error::Fetch(format!("GET {url}: {e}")))?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Fetch(format!(
                "GET {url}: HTTP {status} {}",
                first_line(&response.body_mut().read_to_string().unwrap_or_default())
            )));
        }

        // Read through a limited reader rather than trusting Content-Length: a
        // registry that lies about the size must not be able to fill the node's
        // memory.
        use std::io::Read as _;
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(self.max_blob_bytes as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| Error::Fetch(format!("GET {url}: {e}")))?;

        if body.len() > self.max_blob_bytes {
            return Err(Error::Rejected(format!(
                "{digest} is larger than the {} byte limit",
                self.max_blob_bytes
            )));
        }
        Ok(body)
    }

    /// Pull the single layer of an artifact, checking it against its digest.
    ///
    /// Artifacts svidlet consumes have exactly one layer: an ambiguous artifact
    /// is a packaging mistake, and picking one layer arbitrarily would make it
    /// a silent one.
    pub fn single_layer(
        &self,
        reference: &Reference,
        manifest: &Manifest,
    ) -> Result<Vec<u8>, Error> {
        let [descriptor] = manifest.layers.as_slice() else {
            return Err(Error::Malformed(format!(
                "{} has {} layers; a svidlet artifact has exactly one",
                reference.manifest_url(),
                manifest.layers.len()
            )));
        };
        let blob = self.blob(reference, &descriptor.digest)?;
        super::verify::check_digest(&blob, &descriptor.digest)?;
        Ok(blob)
    }
}

fn first_line(body: &str) -> String {
    body.lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_parse_the_way_other_oci_tools_parse_them() {
        let r = Reference::parse("registry.example.com/policy/rollout:current").unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.repository, "policy/rollout");
        assert_eq!(r.tag, "current");
        assert_eq!(r.scheme, "https");
        assert_eq!(
            r.manifest_url(),
            "https://registry.example.com/v2/policy/rollout/manifests/current"
        );
        assert_eq!(
            r.blob_url("sha256:abc"),
            "https://registry.example.com/v2/policy/rollout/blobs/sha256:abc"
        );
    }

    #[test]
    fn a_missing_tag_defaults_to_latest_and_a_port_is_not_a_tag() {
        assert_eq!(Reference::parse("r.example.com/p/b").unwrap().tag, "latest");

        let r = Reference::parse("registry.example.com:5000/policy/rollout").unwrap();
        assert_eq!(r.registry, "registry.example.com:5000");
        assert_eq!(r.repository, "policy/rollout");
        assert_eq!(r.tag, "latest");

        let r = Reference::parse("registry.example.com:5000/policy/rollout:v2").unwrap();
        assert_eq!(r.registry, "registry.example.com:5000");
        assert_eq!(r.tag, "v2");
    }

    #[test]
    fn only_a_local_registry_is_reached_over_plain_http() {
        for local in ["localhost:5000/p/b", "127.0.0.1:5000/p/b"] {
            assert_eq!(Reference::parse(local).unwrap().scheme, "http");
        }
        // A typo must not silently downgrade a production pull.
        assert_eq!(
            Reference::parse("localhost.evil.com/p/b").unwrap().scheme,
            "https"
        );
    }

    #[test]
    fn an_oci_scheme_prefix_is_accepted() {
        let r = Reference::parse("oci://registry.example.com/policy/rollout:current").unwrap();
        assert_eq!(r.registry, "registry.example.com");
    }

    #[test]
    fn nonsense_references_are_configuration_errors() {
        for bad in ["", "   ", "no-slash", "/leading", "registry.example.com/"] {
            assert!(
                matches!(Reference::parse(bad), Err(Error::Config(_))),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn an_artifact_must_have_exactly_one_layer() {
        let registry = Registry::new(None, None, Duration::from_secs(1), 1024).unwrap();
        let reference = Reference::parse("r.example.com/p/b:t").unwrap();

        for layers in [0, 2] {
            let manifest = Manifest {
                layers: (0..layers)
                    .map(|i| Descriptor {
                        digest: format!("sha256:{i}"),
                        size: 0,
                    })
                    .collect(),
            };
            let err = registry.single_layer(&reference, &manifest).unwrap_err();
            assert!(matches!(err, Error::Malformed(_)), "{layers} layers: {err}");
        }
    }

    #[test]
    fn an_unreachable_registry_is_a_fetch_error() {
        let registry = Registry::new(None, None, Duration::from_millis(500), 1024).unwrap();
        // Port 1 is reserved and refuses immediately.
        let reference = Reference::parse("127.0.0.1:1/p/b:t").unwrap();
        assert!(matches!(
            registry.manifest(&reference, None),
            Err(Error::Fetch(_))
        ));
        assert!(matches!(
            registry.blob(&reference, "sha256:abc"),
            Err(Error::Fetch(_))
        ));
    }

    #[test]
    fn a_bad_registry_ca_is_a_configuration_error() {
        let err = match Registry::new(
            Some("not a certificate".into()),
            None,
            Duration::from_secs(1),
            1024,
        ) {
            Ok(_) => panic!("a bad CA certificate must not be ignored"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::Config(_)));
    }
}
