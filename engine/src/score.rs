use crate::{
    error::{EngineError, Result},
    report::Report,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Score {
    pub value: u8,
}

pub trait Scorer {
    fn score(&self, report: &Report) -> Result<Score>;
}

#[derive(Debug, Default)]
pub struct StubScorer;

impl Scorer for StubScorer {
    fn score(&self, _report: &Report) -> Result<Score> {
        Err(EngineError::Unimplemented {
            component: "scorer",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Scorer, StubScorer};
    use crate::{error::EngineError, report::Report};

    #[test]
    fn stub_scorer_reports_unimplemented() {
        let report = Report::empty("sample.yaml");
        let err = StubScorer.score(&report).expect_err("stub should fail");

        assert!(matches!(
            err,
            EngineError::Unimplemented { component } if component == "scorer"
        ));
    }
}
