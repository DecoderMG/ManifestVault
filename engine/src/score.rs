use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::{EngineError, Result},
    layer::{Package, Sbom},
    manifest::{ContainerRef, Workload},
    report::{CveFinding, Finding, PackageFinding, WorkloadRef, WorkloadReport},
};

const PRIVILEGED_MULTIPLIER: f64 = 2.0;
const ROOT_MULTIPLIER: f64 = 1.5;
const HOST_NAMESPACE_MULTIPLIER: f64 = 1.5;
const ENTRYPOINT_MULTIPLIER: f64 = 2.0;
const BASE_LAYER_MULTIPLIER: f64 = 0.7;
const INTERMEDIATE_LAYER_MULTIPLIER: f64 = 1.0;
const TOP_LAYER_MULTIPLIER: f64 = 1.3;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub cvss_score: Option<OrderedScore>,
    pub severity: Severity,
    affected: Vec<AffectedPackage>,
}

impl Cve {
    pub fn new(
        id: impl Into<String>,
        aliases: Vec<String>,
        summary: Option<String>,
        cvss_score: Option<f64>,
        severity: Severity,
        affected: Vec<AffectedPackage>,
    ) -> Self {
        Self {
            id: id.into(),
            aliases,
            summary,
            cvss_score: cvss_score.map(OrderedScore),
            severity,
            affected,
        }
    }

    fn report_ref(&self) -> CveFinding {
        CveFinding {
            id: self.id.clone(),
            aliases: self.aliases.clone(),
            summary: self.summary.clone(),
            cvss_score: self.cvss_score.map(|score| score.0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveDatabase {
    cves: Vec<Cve>,
}

impl CveDatabase {
    pub fn load_from_dir(path: &Path) -> Result<Self> {
        let files = collect_json_files(path)?;
        let mut cves = Vec::new();

        for file in files {
            let contents =
                fs::read_to_string(&file).map_err(|source| EngineError::ReadCveFeed {
                    path: file.clone(),
                    source,
                })?;
            let value: Value =
                serde_json::from_str(&contents).map_err(|source| EngineError::ParseCveFeed {
                    path: file.clone(),
                    source,
                })?;

            match value {
                Value::Array(items) => {
                    for item in items {
                        let advisory: OsvAdvisory =
                            serde_json::from_value(item).map_err(|source| {
                                EngineError::ParseCveFeed {
                                    path: file.clone(),
                                    source,
                                }
                            })?;
                        cves.push(advisory.into_cve());
                    }
                }
                Value::Object(_) => {
                    let advisory: OsvAdvisory =
                        serde_json::from_value(value).map_err(|source| {
                            EngineError::ParseCveFeed {
                                path: file.clone(),
                                source,
                            }
                        })?;
                    cves.push(advisory.into_cve());
                }
                _ => {
                    return Err(EngineError::InvalidCveFeed {
                        path: file,
                        reason: "expected a JSON object or array",
                    });
                }
            }
        }

        cves.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Self { cves })
    }

    pub fn from_cves(cves: Vec<Cve>) -> Self {
        Self { cves }
    }

    pub fn find(&self, package: &Package) -> Vec<Cve> {
        self.cves
            .iter()
            .filter(|cve| cve.affects(package))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AffectedPackage {
    pub ecosystem: String,
    pub name: String,
    pub versions: Vec<String>,
    pub ranges: Vec<AffectedRange>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AffectedRange {
    pub events: Vec<RangeEvent>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum RangeEvent {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_cvss_score(score: f64) -> Self {
        match score {
            score if score <= 0.0 => Self::None,
            score if score < 4.0 => Self::Low,
            score if score < 7.0 => Self::Medium,
            score if score < 9.0 => Self::High,
            _ => Self::Critical,
        }
    }

    pub fn weight(self) -> f64 {
        match self {
            Self::None => 0.0,
            Self::Low => 1.0,
            Self::Medium => 3.0,
            Self::High => 7.0,
            Self::Critical => 10.0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OrderedScore(pub f64);

impl Eq for OrderedScore {}

pub trait Scorer {
    fn score(&self, workload: &Workload, sbom: &Sbom, cves: &CveDatabase) -> WorkloadReport;
}

#[derive(Debug, Default)]
pub struct CiiScorer;

impl Scorer for CiiScorer {
    fn score(&self, workload: &Workload, sbom: &Sbom, cves: &CveDatabase) -> WorkloadReport {
        score(workload, sbom, cves)
    }
}

pub fn score(workload: &Workload, sbom: &Sbom, cves: &CveDatabase) -> WorkloadReport {
    let workload_ref = WorkloadRef {
        kind: workload.kind,
        name: workload.name.clone(),
        namespace: workload.namespace.clone(),
    };
    let workload_name = workload_ref.display_name();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for container in &workload.containers {
        let Some(container_sbom) = sbom.containers.iter().find(|candidate| {
            candidate.container == container.name
                || candidate
                    .image
                    .as_deref()
                    .zip(container.image.as_deref())
                    .is_some_and(|(left, right)| left == right)
        }) else {
            continue;
        };
        let max_depth = container_sbom
            .layers
            .iter()
            .map(|layer| layer.depth)
            .max()
            .unwrap_or(0);
        let mut layers = container_sbom.layers.iter().collect::<Vec<_>>();
        layers.sort_by_key(|layer| std::cmp::Reverse(layer.depth));

        for layer in layers {
            for package in &layer.packages {
                for cve in cves.find(package) {
                    let key = (
                        container.name.clone(),
                        normalize_name(&package.name),
                        cve.id.clone(),
                    );
                    if !seen.insert(key) {
                        continue;
                    }

                    let (privilege_multiplier, mut factors) =
                        privilege_multiplier(workload, container, package);
                    let (depth_multiplier, depth_factor) = depth_multiplier(layer.depth, max_depth);
                    factors.push(format!("severity:{}", cve.severity.as_str()));
                    factors.push(depth_factor.to_owned());

                    let finding_score = round_score(
                        cve.severity.weight() * privilege_multiplier * depth_multiplier,
                    );
                    findings.push(Finding {
                        workload: workload_name.clone(),
                        container: container.name.clone(),
                        package: PackageFinding {
                            name: package.name.clone(),
                            version: package.version.clone(),
                            ecosystem: normalize_ecosystem(&package.ecosystem),
                            source_path: package.source_path.clone(),
                            layer_depth: layer.depth,
                        },
                        cve: cve.report_ref(),
                        severity: cve.severity,
                        contributing_factors: factors,
                        score: finding_score,
                    });
                }
            }
        }
    }

    findings.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.container.cmp(&right.container))
            .then_with(|| left.package.name.cmp(&right.package.name))
            .then_with(|| left.cve.id.cmp(&right.cve.id))
    });
    let cii_total = round_score(findings.iter().map(|finding| finding.score).sum());

    WorkloadReport {
        workload_ref,
        findings,
        cii_total,
    }
}

impl Cve {
    fn affects(&self, package: &Package) -> bool {
        let package_ecosystem = normalize_ecosystem(&package.ecosystem);
        let package_name = normalize_name(&package.name);

        self.affected.iter().any(|affected| {
            normalize_ecosystem(&affected.ecosystem) == package_ecosystem
                && normalize_name(&affected.name) == package_name
                && affected.matches_version(&package.version)
        })
    }
}

impl AffectedPackage {
    fn matches_version(&self, version: &str) -> bool {
        if self.versions.iter().any(|affected| affected == version) {
            return true;
        }

        if self
            .ranges
            .iter()
            .any(|range| range.matches_version(version))
        {
            return true;
        }

        self.versions.is_empty() && self.ranges.is_empty()
    }
}

impl AffectedRange {
    fn matches_version(&self, version: &str) -> bool {
        let mut active = false;
        let mut matched = false;

        for event in &self.events {
            match event {
                RangeEvent::Introduced(introduced) => {
                    active = version_cmp(version, introduced) != Ordering::Less;
                }
                RangeEvent::Fixed(fixed) => {
                    if active && version_cmp(version, fixed) == Ordering::Less {
                        matched = true;
                    }
                    active = false;
                }
                RangeEvent::LastAffected(last_affected) => {
                    if active && version_cmp(version, last_affected) != Ordering::Greater {
                        matched = true;
                    }
                    active = false;
                }
                RangeEvent::Limit(limit) => {
                    if active && version_cmp(version, limit) == Ordering::Less {
                        matched = true;
                    }
                    active = false;
                }
            }
        }

        matched || active
    }
}

fn collect_json_files(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata = fs::metadata(path).map_err(|source| EngineError::ReadCveFeed {
        path: path.to_path_buf(),
        source,
    })?;
    let mut files = Vec::new();

    if metadata.is_file() {
        files.push(path.to_path_buf());
    } else if metadata.is_dir() {
        collect_json_files_inner(path, &mut files)?;
    } else {
        return Err(EngineError::InvalidCveFeed {
            path: path.to_path_buf(),
            reason: "path is neither a file nor a directory",
        });
    }

    files.sort();
    Ok(files)
}

fn collect_json_files_inner(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).map_err(|source| EngineError::ReadCveFeed {
        path: path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| EngineError::ReadCveFeed {
            path: path.to_path_buf(),
            source,
        })?;
        let entry_path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(|source| EngineError::ReadCveFeed {
                path: entry_path.clone(),
                source,
            })?;

        if metadata.is_dir() {
            if entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "sbom")
            {
                continue;
            }
            collect_json_files_inner(&entry_path, files)?;
        } else if metadata.is_file()
            && entry_path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension == "json")
        {
            files.push(entry_path);
        }
    }

    Ok(())
}

fn privilege_multiplier(
    workload: &Workload,
    container: &ContainerRef,
    package: &Package,
) -> (f64, Vec<String>) {
    let mut multiplier = 1.0;
    let mut factors = Vec::new();

    if container_is_privileged(container) {
        multiplier *= PRIVILEGED_MULTIPLIER;
        factors.push("privileged".to_owned());
    }

    if runs_as_root(container) {
        multiplier *= ROOT_MULTIPLIER;
        factors.push("root_user".to_owned());
    }

    if workload.host_network || workload.host_pid {
        multiplier *= HOST_NAMESPACE_MULTIPLIER;
        factors.push("host_namespace".to_owned());
    }

    if entrypoint_matches_package(container, package) {
        multiplier *= ENTRYPOINT_MULTIPLIER;
        factors.push("entrypoint_binary".to_owned());
    }

    if factors.is_empty() {
        factors.push("standard_privilege".to_owned());
    }

    (multiplier, factors)
}

fn container_is_privileged(container: &ContainerRef) -> bool {
    container.security_context.as_ref().is_some_and(|context| {
        context.privileged == Some(true)
            || context.add_capabilities.iter().any(|capability| {
                let capability = capability.trim().to_ascii_uppercase();
                capability == "SYS_ADMIN" || capability == "CAP_SYS_ADMIN"
            })
    })
}

fn runs_as_root(container: &ContainerRef) -> bool {
    let Some(context) = container.security_context.as_ref() else {
        return true;
    };

    if context.run_as_non_root == Some(true) {
        return false;
    }

    match context.run_as_user {
        Some(0) => true,
        Some(_) => false,
        None => true,
    }
}

fn entrypoint_matches_package(container: &ContainerRef, package: &Package) -> bool {
    let mut candidates = Vec::new();
    if let Some(command) = container.command.first() {
        candidates.push(command.as_str());
    }
    if let Some(arg) = container.args.first() {
        candidates.push(arg.as_str());
    }

    candidates.into_iter().any(|candidate| {
        binary_matches(candidate, &package.name)
            || package
                .binaries
                .iter()
                .any(|binary| binary_matches(candidate, binary))
    })
}

fn binary_matches(candidate: &str, expected: &str) -> bool {
    let candidate = binary_name(candidate);
    let expected = binary_name(expected);
    !candidate.is_empty() && candidate == expected
}

fn binary_name(value: &str) -> String {
    value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn depth_multiplier(depth: usize, max_depth: usize) -> (f64, &'static str) {
    if depth == 0 {
        (BASE_LAYER_MULTIPLIER, "base_layer")
    } else if depth == max_depth {
        (TOP_LAYER_MULTIPLIER, "top_layer")
    } else {
        (INTERMEDIATE_LAYER_MULTIPLIER, "intermediate_layer")
    }
}

fn round_score(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

pub fn normalize_ecosystem(ecosystem: &str) -> String {
    let lower = ecosystem
        .trim()
        .split_once(':')
        .map_or(ecosystem.trim(), |(base, _)| base)
        .to_ascii_lowercase();

    match lower.as_str() {
        "apk" | "alpine" => "alpine".to_owned(),
        "deb" | "debian" | "dpkg" => "debian".to_owned(),
        "python" | "pypi" => "pypi".to_owned(),
        _ => lower,
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

fn version_cmp(left: &str, right: &str) -> Ordering {
    let left = tokenize_version(left);
    let right = tokenize_version(right);

    for index in 0..left.len().max(right.len()) {
        match (left.get(index), right.get(index)) {
            (Some(VersionToken::Number(left)), Some(VersionToken::Number(right))) => {
                match left.cmp(right) {
                    Ordering::Equal => {}
                    ordering => return ordering,
                }
            }
            (Some(VersionToken::Text(left)), Some(VersionToken::Text(right))) => {
                match left.cmp(right) {
                    Ordering::Equal => {}
                    ordering => return ordering,
                }
            }
            (Some(VersionToken::Number(_)), Some(VersionToken::Text(_))) => {
                return Ordering::Greater;
            }
            (Some(VersionToken::Text(_)), Some(VersionToken::Number(_))) => {
                return Ordering::Less;
            }
            (Some(token), None) => {
                if token.is_zero() {
                    continue;
                }
                return Ordering::Greater;
            }
            (None, Some(token)) => {
                if token.is_zero() {
                    continue;
                }
                return Ordering::Less;
            }
            (None, None) => return Ordering::Equal,
        }
    }

    Ordering::Equal
}

#[derive(Debug, Eq, PartialEq)]
enum VersionToken {
    Number(u128),
    Text(String),
}

impl VersionToken {
    fn is_zero(&self) -> bool {
        match self {
            Self::Number(value) => *value == 0,
            Self::Text(value) => value.is_empty(),
        }
    }
}

fn tokenize_version(version: &str) -> Vec<VersionToken> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut current_is_digit = None;

    for character in version.chars() {
        if !character.is_ascii_alphanumeric() {
            flush_version_token(&mut tokens, &mut current, &mut current_is_digit);
            continue;
        }

        let is_digit = character.is_ascii_digit();
        if current_is_digit.is_some_and(|was_digit| was_digit != is_digit) {
            flush_version_token(&mut tokens, &mut current, &mut current_is_digit);
        }

        current_is_digit = Some(is_digit);
        current.push(character.to_ascii_lowercase());
    }

    flush_version_token(&mut tokens, &mut current, &mut current_is_digit);
    tokens
}

fn flush_version_token(
    tokens: &mut Vec<VersionToken>,
    current: &mut String,
    current_is_digit: &mut Option<bool>,
) {
    if current.is_empty() {
        *current_is_digit = None;
        return;
    }

    let value = std::mem::take(current);
    if *current_is_digit == Some(true) {
        tokens.push(VersionToken::Number(value.parse().unwrap_or(u128::MAX)));
    } else {
        tokens.push(VersionToken::Text(value));
    }

    *current_is_digit = None;
}

fn parse_cvss_score(raw: &str) -> Option<f64> {
    raw.parse::<f64>()
        .ok()
        .or_else(|| parse_cvss_v3_vector(raw))
}

fn parse_cvss_v3_vector(raw: &str) -> Option<f64> {
    let mut metrics = HashMap::new();
    let mut scope = "U";

    for part in raw.split('/') {
        let Some((key, value)) = part.split_once(':') else {
            continue;
        };
        if key == "CVSS" {
            continue;
        }
        if key == "S" {
            scope = value;
        }
        metrics.insert(key, value);
    }

    let av = match *metrics.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.20,
        _ => return None,
    };
    let ac = match *metrics.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*metrics.get("PR")?, scope) {
        ("N", _) => 0.85,
        ("L", "U") => 0.62,
        ("L", "C") => 0.68,
        ("H", "U") => 0.27,
        ("H", "C") => 0.50,
        _ => return None,
    };
    let ui = match *metrics.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let c = cvss_impact_metric(metrics.get("C")?)?;
    let i = cvss_impact_metric(metrics.get("I")?)?;
    let a = cvss_impact_metric(metrics.get("A")?)?;
    let impact = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope == "C" {
        let impact_sub_score = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02).powi(15);
        1.08 * (impact_sub_score + exploitability).min(10.0)
    } else {
        let impact_sub_score = 6.42 * impact;
        (impact_sub_score + exploitability).min(10.0)
    };

    Some((base * 10.0).ceil() / 10.0)
}

fn cvss_impact_metric(value: &str) -> Option<f64> {
    match value {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct OsvAdvisory {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    database_specific: serde_json::Map<String, Value>,
}

impl OsvAdvisory {
    fn into_cve(self) -> Cve {
        let cvss_score = self
            .severity
            .iter()
            .filter_map(|severity| parse_cvss_score(&severity.score))
            .max_by(f64::total_cmp);
        let severity = cvss_score
            .map(Severity::from_cvss_score)
            .or_else(|| database_specific_severity(&self.database_specific))
            .unwrap_or(Severity::None);
        let affected = self
            .affected
            .into_iter()
            .filter_map(OsvAffected::into_affected_package)
            .collect();

        Cve::new(
            self.id,
            self.aliases,
            self.summary,
            cvss_score,
            severity,
            affected,
        )
    }
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

impl OsvAffected {
    fn into_affected_package(self) -> Option<AffectedPackage> {
        let package = self.package?;
        Some(AffectedPackage {
            ecosystem: package.ecosystem,
            name: package.name,
            versions: self.versions,
            ranges: self
                .ranges
                .into_iter()
                .map(OsvRange::into_affected_range)
                .collect(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

impl OsvRange {
    fn into_affected_range(self) -> AffectedRange {
        AffectedRange {
            events: self
                .events
                .into_iter()
                .filter_map(OsvEvent::into_range_event)
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

impl OsvEvent {
    fn into_range_event(self) -> Option<RangeEvent> {
        if let Some(version) = self.introduced {
            Some(RangeEvent::Introduced(version))
        } else if let Some(version) = self.fixed {
            Some(RangeEvent::Fixed(version))
        } else if let Some(version) = self.last_affected {
            Some(RangeEvent::LastAffected(version))
        } else {
            self.limit.map(RangeEvent::Limit)
        }
    }
}

fn database_specific_severity(
    database_specific: &serde_json::Map<String, Value>,
) -> Option<Severity> {
    database_specific
        .get("severity")
        .and_then(Value::as_str)
        .and_then(|severity| match severity.to_ascii_lowercase().as_str() {
            "none" => Some(Severity::None),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AffectedPackage, AffectedRange, Cve, CveDatabase, RangeEvent, Severity, score, version_cmp,
    };
    use crate::{
        layer::{ContainerSbom, LayerSbom, Package, Sbom},
        manifest::{ContainerRef, ContainerSecurityContext, Workload, WorkloadKind},
    };

    #[test]
    fn osv_loader_matches_three_ecosystems_and_ranges() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(
            dir.path().join("alpine.json"),
            r#"
{
  "id": "CVE-ALPINE-1",
  "summary": "openssl issue",
  "severity": [{"type": "CVSS_V3", "score": "8.1"}],
  "affected": [{
    "package": {"ecosystem": "Alpine:v3.18", "name": "openssl"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.4-r0"}]}]
  }]
}
"#,
        )
        .expect("alpine feed");
        std::fs::write(
            dir.path().join("debian.json"),
            r#"
{
  "id": "CVE-DEBIAN-1",
  "severity": [{"type": "CVSS_V3", "score": "5.0"}],
  "affected": [{
    "package": {"ecosystem": "Debian", "name": "libssl3"},
    "versions": ["3.0.11-1"]
  }]
}
"#,
        )
        .expect("debian feed");
        std::fs::write(
            dir.path().join("pypi.json"),
            r#"
{
  "id": "CVE-PYPI-1",
  "database_specific": {"severity": "critical"},
  "affected": [{
    "package": {"ecosystem": "PyPI", "name": "requests"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.32.0"}]}]
  }]
}
"#,
        )
        .expect("pypi feed");

        let database = CveDatabase::load_from_dir(dir.path()).expect("load feed");

        assert_eq!(
            database.find(&package("openssl", "3.1.0-r0", "apk"))[0].id,
            "CVE-ALPINE-1"
        );
        assert_eq!(
            database.find(&package("libssl3", "3.0.11-1", "dpkg"))[0].id,
            "CVE-DEBIAN-1"
        );
        assert_eq!(
            database.find(&package("requests", "2.31.0", "pypi"))[0].id,
            "CVE-PYPI-1"
        );
        assert!(
            database
                .find(&package("openssl", "3.1.5-r0", "apk"))
                .is_empty()
        );
    }

    #[test]
    fn privileged_container_multiplier_scores_branch() {
        let mut workload = workload();
        workload.containers[0]
            .security_context
            .as_mut()
            .unwrap()
            .privileged = Some(true);

        let report = score(&workload, &sbom_at_depth(1), &database(Severity::High));

        assert_eq!(report.findings[0].score, 14.0);
        assert!(
            report.findings[0]
                .contributing_factors
                .contains(&"privileged".to_owned())
        );
    }

    #[test]
    fn cap_sys_admin_uses_privileged_multiplier() {
        let mut workload = workload();
        workload.containers[0]
            .security_context
            .as_mut()
            .unwrap()
            .add_capabilities = vec!["SYS_ADMIN".to_owned()];

        let report = score(&workload, &sbom_at_depth(1), &database(Severity::High));

        assert_eq!(report.findings[0].score, 14.0);
    }

    #[test]
    fn root_container_multiplier_scores_branch() {
        let mut workload = workload();
        workload.containers[0]
            .security_context
            .as_mut()
            .unwrap()
            .run_as_non_root = None;
        workload.containers[0]
            .security_context
            .as_mut()
            .unwrap()
            .run_as_user = Some(0);

        let report = score(&workload, &sbom_at_depth(1), &database(Severity::High));

        assert_eq!(report.findings[0].score, 10.5);
        assert!(
            report.findings[0]
                .contributing_factors
                .contains(&"root_user".to_owned())
        );
    }

    #[test]
    fn host_namespace_multiplier_scores_branch() {
        let mut workload = workload();
        workload.host_network = true;

        let report = score(&workload, &sbom_at_depth(1), &database(Severity::High));

        assert_eq!(report.findings[0].score, 10.5);
        assert!(
            report.findings[0]
                .contributing_factors
                .contains(&"host_namespace".to_owned())
        );
    }

    #[test]
    fn entrypoint_multiplier_scores_branch() {
        let mut workload = workload();
        workload.containers[0].command = vec!["/usr/bin/openssl".to_owned()];

        let report = score(&workload, &sbom_at_depth(1), &database(Severity::High));

        assert_eq!(report.findings[0].score, 14.0);
        assert!(
            report.findings[0]
                .contributing_factors
                .contains(&"entrypoint_binary".to_owned())
        );
    }

    #[test]
    fn depth_multiplier_scores_base_intermediate_and_top_layers() {
        let workload = workload();
        let database = database(Severity::High);

        let base = score(&workload, &sbom_at_depth(0), &database);
        let intermediate = score(&workload, &sbom_at_depth(1), &database);
        let top = score(&workload, &sbom_at_depth(2), &database);

        assert_eq!(base.findings[0].score, 4.9);
        assert_eq!(intermediate.findings[0].score, 7.0);
        assert_eq!(top.findings[0].score, 9.1);
    }

    #[test]
    fn deduplicates_same_container_package_and_cve() {
        let workload = workload();
        let sbom = Sbom {
            containers: vec![ContainerSbom {
                container: "app".to_owned(),
                image: Some("app:latest".to_owned()),
                layers: vec![
                    layer(0, package("openssl", "3.1.0-r0", "alpine")),
                    layer(2, package("openssl", "3.1.0-r0", "alpine")),
                ],
            }],
        };

        let report = score(&workload, &sbom, &database(Severity::High));

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].package.layer_depth, 2);
    }

    #[test]
    fn version_comparison_handles_revision_numbers() {
        assert_eq!(
            version_cmp("3.1.0-r1", "3.1.0-r0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(version_cmp("2.31.0", "2.32.0"), std::cmp::Ordering::Less);
    }

    fn workload() -> Workload {
        Workload {
            kind: WorkloadKind::Pod,
            name: "api".to_owned(),
            namespace: Some("platform".to_owned()),
            containers: vec![ContainerRef {
                name: "app".to_owned(),
                image: Some("app:latest".to_owned()),
                image_pull_policy: None,
                security_context: Some(ContainerSecurityContext {
                    allow_privilege_escalation: None,
                    add_capabilities: Vec::new(),
                    privileged: Some(false),
                    read_only_root_filesystem: None,
                    run_as_group: None,
                    run_as_non_root: Some(true),
                    run_as_user: Some(1000),
                }),
                command: Vec::new(),
                args: Vec::new(),
            }],
            service_account: None,
            host_network: false,
            host_pid: false,
            privileged: false,
        }
    }

    fn database(severity: Severity) -> CveDatabase {
        CveDatabase::from_cves(vec![Cve::new(
            "CVE-TEST-1",
            Vec::new(),
            Some("test vulnerability".to_owned()),
            Some(match severity {
                Severity::None => 0.0,
                Severity::Low => 3.0,
                Severity::Medium => 5.0,
                Severity::High => 8.0,
                Severity::Critical => 9.8,
            }),
            severity,
            vec![AffectedPackage {
                ecosystem: "alpine".to_owned(),
                name: "openssl".to_owned(),
                versions: Vec::new(),
                ranges: vec![AffectedRange {
                    events: vec![
                        RangeEvent::Introduced("0".to_owned()),
                        RangeEvent::Fixed("3.1.4-r0".to_owned()),
                    ],
                }],
            }],
        )])
    }

    fn sbom_at_depth(depth: usize) -> Sbom {
        let mut layers = vec![
            layer(0, package("base-files", "1.0.0", "alpine")),
            layer(1, package("openssl", "3.1.0-r0", "alpine")),
            layer(2, package("app", "1.0.0", "pypi")),
        ];
        layers[1] = layer(depth, package("openssl", "3.1.0-r0", "alpine"));

        Sbom {
            containers: vec![ContainerSbom {
                container: "app".to_owned(),
                image: Some("app:latest".to_owned()),
                layers,
            }],
        }
    }

    fn layer(depth: usize, package: Package) -> LayerSbom {
        LayerSbom {
            digest: format!("sha256:{depth}"),
            depth,
            packages: vec![package],
        }
    }

    fn package(name: &str, version: &str, ecosystem: &str) -> Package {
        Package {
            name: name.to_owned(),
            version: version.to_owned(),
            ecosystem: ecosystem.to_owned(),
            source_path: "/lib/apk/db/installed".to_owned(),
            binaries: vec![format!("/usr/bin/{name}")],
        }
    }
}
