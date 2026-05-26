use crate::{
    error::{EngineError, Result},
    manifest::Manifest,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sbom {
    pub packages: Vec<String>,
}

pub trait SbomExtractor {
    fn extract(&self, manifest: &Manifest) -> Result<Sbom>;
}

#[derive(Debug, Default)]
pub struct StubSbomExtractor;

impl SbomExtractor for StubSbomExtractor {
    fn extract(&self, _manifest: &Manifest) -> Result<Sbom> {
        Err(EngineError::Unimplemented {
            component: "SBOM extractor",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SbomExtractor, StubSbomExtractor};
    use crate::{error::EngineError, manifest::Manifest};

    #[test]
    fn stub_extractor_reports_unimplemented() {
        let manifest = Manifest::new("sample.yaml");
        let err = StubSbomExtractor
            .extract(&manifest)
            .expect_err("stub should fail");

        assert!(matches!(
            err,
            EngineError::Unimplemented { component } if component == "SBOM extractor"
        ));
    }
}
