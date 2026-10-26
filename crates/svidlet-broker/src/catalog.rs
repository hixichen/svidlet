//! The catalog as the broker holds it: loaded at start-up, reloaded when the
//! mounted ConfigMap changes, and kept as it was when a new version is bad.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use svidlet_issue::Catalog;

#[derive(Clone)]
pub struct CatalogHandle {
    path: Option<PathBuf>,
    current: Arc<RwLock<(Arc<Catalog>, String)>>,
}

impl CatalogHandle {
    pub fn load(path: PathBuf) -> Result<CatalogHandle, String> {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read the catalog {}: {e}", path.display()))?;
        let catalog = Catalog::parse(&text).map_err(|e| e.to_string())?;
        Ok(CatalogHandle {
            path: Some(path),
            current: Arc::new(RwLock::new((Arc::new(catalog), text))),
        })
    }

    /// A fixed catalog, for tests.
    pub fn fixed(catalog: Catalog) -> CatalogHandle {
        CatalogHandle {
            path: None,
            current: Arc::new(RwLock::new((Arc::new(catalog), String::new()))),
        }
    }

    pub fn current(&self) -> Arc<Catalog> {
        self.current.read().expect("catalog poisoned").0.clone()
    }

    /// Re-read the file. `Ok(true)` if it changed and was applied; an invalid
    /// new version is an error and the previous catalog stays in force.
    pub fn reload(&self) -> Result<bool, String> {
        let Some(path) = &self.path else {
            return Ok(false);
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read the catalog {}: {e}", path.display()))?;
        if self.current.read().expect("catalog poisoned").1 == text {
            return Ok(false);
        }
        let catalog = Catalog::parse(&text).map_err(|e| e.to_string())?;
        *self.current.write().expect("catalog poisoned") = (Arc::new(catalog), text);
        Ok(true)
    }
}
