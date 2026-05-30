use serde::{Deserialize, Serialize};

use crate::{cli::OutputFormat, error::Result, manifest::WorkloadKind, score::Severity};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub workloads: Vec<WorkloadReport>,
}

impl Report {
    pub fn empty() -> Self {
        Self {
            workloads: Vec::new(),
        }
    }

    pub fn new(mut workloads: Vec<WorkloadReport>) -> Self {
        workloads.sort_by(|left, right| {
            right
                .cii_total
                .total_cmp(&left.cii_total)
                .then_with(|| left.workload_ref.name.cmp(&right.workload_ref.name))
        });
        Self { workloads }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadReport {
    pub workload_ref: WorkloadRef,
    pub findings: Vec<Finding>,
    pub cii_total: f64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkloadRef {
    pub kind: WorkloadKind,
    pub name: String,
    pub namespace: Option<String>,
}

impl WorkloadRef {
    pub fn display_name(&self) -> String {
        match self.namespace.as_deref() {
            Some(namespace) => format!("{namespace}/{}", self.name),
            None => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub workload: String,
    pub container: String,
    pub package: PackageFinding,
    pub cve: CveFinding,
    pub severity: Severity,
    pub contributing_factors: Vec<String>,
    pub score: f64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageFinding {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub source_path: String,
    pub layer_depth: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveFinding {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub cvss_score: Option<f64>,
}

pub fn render(report: &Report, output: OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        OutputFormat::Text => Ok(render_text(report)),
    }
}

fn render_text(report: &Report) -> String {
    let mut output = String::from("ManifestVault report\n");
    output.push_str(&format!("Workloads: {}\n", report.workloads.len()));

    for workload in &report.workloads {
        output.push_str(&format!(
            "\n{} ({:?})\nCII: {:.2}\nFindings: {}\n",
            workload.workload_ref.display_name(),
            workload.workload_ref.kind,
            workload.cii_total,
            workload.findings.len()
        ));

        for finding in &workload.findings {
            output.push_str(&format!(
                "- {} {} in {}: {} ({:.2})\n",
                finding.package.name,
                finding.package.version,
                finding.container,
                finding.cve.id,
                finding.score
            ));
        }
    }

    output.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Report, WorkloadRef, WorkloadReport, render};
    use crate::{cli::OutputFormat, manifest::WorkloadKind};

    #[test]
    fn renders_empty_report_as_json() {
        let report = Report::empty();

        let rendered = render(&report, OutputFormat::Json).expect("json render");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(parsed["workloads"], serde_json::json!([]));
    }

    #[test]
    fn renders_text_sorted_by_cii() {
        let report = Report::new(vec![
            workload("low", 1.0),
            workload("high", 10.0),
            workload("medium", 3.0),
        ]);

        let rendered = render(&report, OutputFormat::Text).expect("text render");
        let high = rendered.find("high").expect("high workload");
        let medium = rendered.find("medium").expect("medium workload");
        let low = rendered.find("low").expect("low workload");

        assert!(high < medium);
        assert!(medium < low);
    }

    fn workload(name: &str, cii_total: f64) -> WorkloadReport {
        WorkloadReport {
            workload_ref: WorkloadRef {
                kind: WorkloadKind::Pod,
                name: name.to_owned(),
                namespace: None,
            },
            findings: Vec::new(),
            cii_total,
        }
    }
}
