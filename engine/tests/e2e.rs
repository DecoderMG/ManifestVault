use std::{fmt::Write as _, path::PathBuf, process::Command};

use manifestvault_engine::{
    Finding, Report,
    scan::{ScanOptions, scan},
};
use serde::Serialize;

#[tokio::test]
async fn full_pipeline_matches_golden_report() {
    let report = scan(ScanOptions::new(manifests(), cve_feed()))
        .await
        .expect("scan e2e fixtures");
    let actual = render_canonical_report(report);
    let golden = golden_report();

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&golden, actual).expect("update golden report");
        return;
    }

    let expected = std::fs::read_to_string(&golden).expect("read golden report");
    assert!(
        expected == actual,
        "e2e golden report mismatch\n{}",
        unified_diff(&expected, &actual)
    );
}

#[test]
fn cli_scan_smoke_outputs_non_empty_workloads() {
    let output = Command::new(env!("CARGO_BIN_EXE_manifestvault"))
        .arg("scan")
        .arg(manifests())
        .arg("--cve-feed")
        .arg(cve_feed())
        .arg("--output")
        .arg("json")
        .output()
        .expect("run manifestvault scan");

    assert!(
        output.status.success(),
        "manifestvault scan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI stdout is valid json");
    assert!(
        parsed
            .get("workloads")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|workloads| !workloads.is_empty()),
        "CLI report should include at least one workload"
    );
}

fn render_canonical_report(mut report: Report) -> String {
    report.workloads.sort_by(|left, right| {
        right
            .cii_total
            .total_cmp(&left.cii_total)
            .then_with(|| left.workload_ref.name.cmp(&right.workload_ref.name))
            .then_with(|| left.workload_ref.kind.cmp(&right.workload_ref.kind))
    });
    for workload in &mut report.workloads {
        workload.findings.sort_by(finding_key_cmp);
    }

    let mut output = String::new();
    output.push_str("{\n  \"workloads\": [");
    if !report.workloads.is_empty() {
        output.push('\n');
    }

    for (index, workload) in report.workloads.iter().enumerate() {
        if index > 0 {
            output.push_str(",\n");
        }

        output.push_str("    {\n");
        output.push_str("      \"workload_ref\": {\n");
        write_field(&mut output, 8, "kind", &json(&workload.workload_ref.kind), true);
        write_field(&mut output, 8, "name", &json(&workload.workload_ref.name), true);
        write_field(
            &mut output,
            8,
            "namespace",
            &json(&workload.workload_ref.namespace),
            false,
        );
        output.push_str("      },\n");

        output.push_str("      \"findings\": [");
        if !workload.findings.is_empty() {
            output.push('\n');
        }

        for (finding_index, finding) in workload.findings.iter().enumerate() {
            if finding_index > 0 {
                output.push_str(",\n");
            }
            render_finding(&mut output, finding);
        }

        if !workload.findings.is_empty() {
            output.push('\n');
        }
        output.push_str("      ],\n");
        write_field(
            &mut output,
            6,
            "cii_total",
            &format_fixed(workload.cii_total),
            false,
        );
        output.push_str("    }");
    }

    if !report.workloads.is_empty() {
        output.push('\n');
    }
    output.push_str("  ]\n}\n");
    output
}

fn render_finding(output: &mut String, finding: &Finding) {
    output.push_str("        {\n");
    write_field(output, 10, "workload", &json(&finding.workload), true);
    write_field(output, 10, "container", &json(&finding.container), true);

    output.push_str("          \"package\": {\n");
    write_field(output, 12, "name", &json(&finding.package.name), true);
    write_field(output, 12, "version", &json(&finding.package.version), true);
    write_field(
        output,
        12,
        "ecosystem",
        &json(&finding.package.ecosystem),
        true,
    );
    write_field(
        output,
        12,
        "source_path",
        &json(&finding.package.source_path),
        true,
    );
    write_field(
        output,
        12,
        "layer_depth",
        &finding.package.layer_depth.to_string(),
        false,
    );
    output.push_str("          },\n");

    output.push_str("          \"cve\": {\n");
    write_field(output, 12, "id", &json(&finding.cve.id), true);
    render_string_array(output, 12, "aliases", &finding.cve.aliases, true);
    write_field(output, 12, "summary", &json(&finding.cve.summary), true);
    write_field(
        output,
        12,
        "cvss_score",
        &finding
            .cve
            .cvss_score
            .map(format_fixed)
            .unwrap_or_else(|| "null".to_owned()),
        false,
    );
    output.push_str("          },\n");

    write_field(output, 10, "severity", &json(&finding.severity), true);
    render_string_array(
        output,
        10,
        "contributing_factors",
        &finding.contributing_factors,
        true,
    );
    write_field(output, 10, "score", &format_fixed(finding.score), false);
    output.push_str("        }");
}

fn render_string_array(
    output: &mut String,
    indent: usize,
    field: &str,
    values: &[String],
    trailing_comma: bool,
) {
    write!(
        output,
        "{}\"{}\": [",
        " ".repeat(indent),
        field
    )
    .expect("write string array header");

    if values.is_empty() {
        output.push(']');
        if trailing_comma {
            output.push(',');
        }
        output.push('\n');
        return;
    }

    output.push('\n');
    for (index, value) in values.iter().enumerate() {
        write!(output, "{}{}", " ".repeat(indent + 2), json(value))
            .expect("write string array item");
        if index + 1 != values.len() {
            output.push(',');
        }
        output.push('\n');
    }
    write!(output, "{}]", " ".repeat(indent)).expect("write string array footer");
    if trailing_comma {
        output.push(',');
    }
    output.push('\n');
}

fn write_field(
    output: &mut String,
    indent: usize,
    field: &str,
    value: &str,
    trailing_comma: bool,
) {
    write!(output, "{}\"{field}\": {value}", " ".repeat(indent)).expect("write json field");
    if trailing_comma {
        output.push(',');
    }
    output.push('\n');
}

fn finding_key_cmp(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    left.workload
        .cmp(&right.workload)
        .then_with(|| left.container.cmp(&right.container))
        .then_with(|| left.cve.id.cmp(&right.cve.id))
}

fn format_fixed(value: f64) -> String {
    format!("{value:.4}")
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("serialize json value")
}

fn unified_diff(expected: &str, actual: &str) -> String {
    let expected_lines = expected.lines().collect::<Vec<_>>();
    let actual_lines = actual.lines().collect::<Vec<_>>();
    let mut table = vec![vec![0usize; actual_lines.len() + 1]; expected_lines.len() + 1];

    for expected_index in (0..expected_lines.len()).rev() {
        for actual_index in (0..actual_lines.len()).rev() {
            table[expected_index][actual_index] = if expected_lines[expected_index]
                == actual_lines[actual_index]
            {
                table[expected_index + 1][actual_index + 1] + 1
            } else {
                table[expected_index + 1][actual_index].max(table[expected_index][actual_index + 1])
            };
        }
    }

    let mut diff = String::from("--- golden/report.json\n+++ actual/report.json\n@@\n");
    let mut expected_index = 0;
    let mut actual_index = 0;
    while expected_index < expected_lines.len() && actual_index < actual_lines.len() {
        if expected_lines[expected_index] == actual_lines[actual_index] {
            writeln!(diff, " {}", expected_lines[expected_index]).expect("write equal line");
            expected_index += 1;
            actual_index += 1;
        } else if table[expected_index + 1][actual_index] >= table[expected_index][actual_index + 1]
        {
            writeln!(diff, "-{}", expected_lines[expected_index]).expect("write removed line");
            expected_index += 1;
        } else {
            writeln!(diff, "+{}", actual_lines[actual_index]).expect("write added line");
            actual_index += 1;
        }
    }

    for line in &expected_lines[expected_index..] {
        writeln!(diff, "-{line}").expect("write trailing removed line");
    }
    for line in &actual_lines[actual_index..] {
        writeln!(diff, "+{line}").expect("write trailing added line");
    }

    diff
}

fn manifests() -> PathBuf {
    fixtures().join("manifests")
}

fn cve_feed() -> PathBuf {
    fixtures().join("cve-feed")
}

fn golden_report() -> PathBuf {
    fixtures().join("golden").join("report.json")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("e2e")
        .join("fixtures")
}
