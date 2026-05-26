use std::path::{Path, PathBuf};

use crate::error::{EngineError, Result};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Manifest {
    pub path: PathBuf,
}

impl Manifest {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

pub trait Parser {
    fn parse(&self, path: &Path) -> Result<Manifest>;
}

#[derive(Debug, Default)]
pub struct StubParser;

impl Parser for StubParser {
    fn parse(&self, _path: &Path) -> Result<Manifest> {
        Err(EngineError::Unimplemented {
            component: "manifest parser",
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{Parser, StubParser};
    use crate::error::EngineError;

    #[test]
    fn stub_parser_reports_unimplemented() {
        let err = StubParser
            .parse(Path::new("sample.yaml"))
            .expect_err("stub should fail");

        assert!(matches!(
            err,
            EngineError::Unimplemented { component } if component == "manifest parser"
        ));
    }
}
