use serde::{Deserialize, Serialize};

use crate::{cli::OutputFormat, error::Result};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub target: String,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn empty(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            findings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub message: String,
}

pub fn render(report: &Report, output: OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        OutputFormat::Text => Ok(format!(
            "ManifestVault report\nTarget: {}\nFindings: {}",
            report.target,
            report.findings.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{Report, render};
    use crate::cli::OutputFormat;

    #[test]
    fn renders_empty_report_as_json() {
        let report = Report::empty("sample.yaml");

        let rendered = render(&report, OutputFormat::Json).expect("json render");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(parsed["target"], "sample.yaml");
        assert_eq!(parsed["findings"], serde_json::json!([]));
    }

    #[test]
    fn renders_empty_report_as_text() {
        let report = Report::empty("sample.yaml");

        let rendered = render(&report, OutputFormat::Text).expect("text render");

        assert!(rendered.contains("Target: sample.yaml"));
        assert!(rendered.contains("Findings: 0"));
    }
}
