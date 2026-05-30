use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type LayerResult<T> = std::result::Result<T, LayerError>;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sbom {
    pub containers: Vec<ContainerSbom>,
}

impl Sbom {
    pub fn empty() -> Self {
        Self {
            containers: Vec::new(),
        }
    }

    pub fn for_container(container: ContainerSbom) -> Self {
        Self {
            containers: vec![container],
        }
    }

    pub fn extend(&mut self, other: Sbom) {
        self.containers.extend(other.containers);
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerSbom {
    pub container: String,
    pub image: Option<String>,
    pub layers: Vec<LayerSbom>,
}

impl ContainerSbom {
    pub fn empty(container: impl Into<String>, image: Option<String>) -> Self {
        Self {
            container: container.into(),
            image,
            layers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LayerSbom {
    pub digest: String,
    pub depth: usize,
    pub packages: Vec<Package>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source_path: String,
    #[serde(default)]
    pub binaries: Vec<String>,
}

#[derive(Debug, Error)]
pub enum LayerError {
    #[error("failed to read SBOM file {path:?}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse SBOM file {path:?}")]
    ParseFile {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

pub fn load_container_sbom(
    path: &Path,
    container: &str,
    image: Option<String>,
) -> LayerResult<ContainerSbom> {
    let contents = fs::read_to_string(path).map_err(|source| LayerError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let fixture: LocalContainerSbom =
        serde_json::from_str(&contents).map_err(|source| LayerError::ParseFile {
            path: path.to_path_buf(),
            source,
        })?;

    Ok(ContainerSbom {
        container: fixture.container.unwrap_or_else(|| container.to_owned()),
        image: fixture.image.or(image),
        layers: fixture.layers,
    })
}

#[derive(Debug, Deserialize)]
struct LocalContainerSbom {
    container: Option<String>,
    image: Option<String>,
    layers: Vec<LayerSbom>,
}

#[cfg(test)]
mod tests {
    use super::{Package, load_container_sbom};

    #[test]
    fn loads_container_sbom_with_fallback_metadata() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("app.sbom.json");
        std::fs::write(
            &path,
            r#"
{
  "layers": [
    {
      "digest": "sha256:base",
      "depth": 0,
      "packages": [
        {
          "name": "openssl",
          "version": "3.1.0-r0",
          "ecosystem": "alpine",
          "source_path": "/lib/apk/db/installed",
          "binaries": ["/usr/bin/openssl"]
        }
      ]
    }
  ]
}
"#,
        )
        .expect("sbom");

        let sbom = load_container_sbom(&path, "app", Some("app:latest".to_owned()))
            .expect("load sbom");

        assert_eq!(sbom.container, "app");
        assert_eq!(sbom.image.as_deref(), Some("app:latest"));
        assert_eq!(
            sbom.layers[0].packages[0],
            Package {
                name: "openssl".to_owned(),
                version: "3.1.0-r0".to_owned(),
                ecosystem: "alpine".to_owned(),
                source_path: "/lib/apk/db/installed".to_owned(),
                binaries: vec!["/usr/bin/openssl".to_owned()],
            }
        );
    }
}
