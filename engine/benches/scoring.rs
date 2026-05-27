use std::{hint::black_box, time::Instant};

use manifestvault_engine::{
    AffectedPackage, AffectedRange, ContainerRef, ContainerSbom, ContainerSecurityContext, Cve,
    CveDatabase, LayerSbom, Package, RangeEvent, Sbom, Severity, Workload, WorkloadKind, score,
};

const WORKLOAD_COUNT: usize = 100;
const FINDINGS_PER_WORKLOAD: usize = 50;

fn main() {
    let cves = cve_database();
    let mut inputs = Vec::with_capacity(WORKLOAD_COUNT);
    for index in 0..WORKLOAD_COUNT {
        inputs.push((workload(index), sbom(index)));
    }

    let start = Instant::now();
    let mut total = 0.0;
    for (workload, sbom) in &inputs {
        let report = score(black_box(workload), black_box(sbom), black_box(&cves));
        total += report.cii_total;
    }
    let elapsed = start.elapsed();

    println!(
        "scored {WORKLOAD_COUNT} workloads x {FINDINGS_PER_WORKLOAD} findings in {elapsed:?}; total={total:.2}"
    );
    assert!(
        elapsed.as_millis() < 100,
        "scoring exceeded 100ms target: {elapsed:?}"
    );
}

fn workload(index: usize) -> Workload {
    Workload {
        kind: WorkloadKind::Deployment,
        name: format!("workload-{index}"),
        namespace: Some("bench".to_owned()),
        containers: vec![ContainerRef {
            name: "app".to_owned(),
            image: Some(format!("bench:{index}")),
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

fn sbom(index: usize) -> Sbom {
    Sbom {
        containers: vec![ContainerSbom {
            container: "app".to_owned(),
            image: Some(format!("bench:{index}")),
            layers: vec![LayerSbom {
                digest: "sha256:bench".to_owned(),
                depth: 1,
                packages: (0..FINDINGS_PER_WORKLOAD)
                    .map(|package_index| Package {
                        name: format!("pkg-{package_index}"),
                        version: "1.0.0".to_owned(),
                        ecosystem: "alpine".to_owned(),
                        source_path: "/lib/apk/db/installed".to_owned(),
                        binaries: Vec::new(),
                    })
                    .collect(),
            }],
        }],
    }
}

fn cve_database() -> CveDatabase {
    CveDatabase::from_cves(
        (0..FINDINGS_PER_WORKLOAD)
            .map(|index| {
                Cve::new(
                    format!("CVE-BENCH-{index}"),
                    Vec::new(),
                    None,
                    Some(8.0),
                    Severity::High,
                    vec![AffectedPackage {
                        ecosystem: "alpine".to_owned(),
                        name: format!("pkg-{index}"),
                        versions: Vec::new(),
                        ranges: vec![AffectedRange {
                            events: vec![
                                RangeEvent::Introduced("0".to_owned()),
                                RangeEvent::Fixed("2.0.0".to_owned()),
                            ],
                        }],
                    }],
                )
            })
            .collect(),
    )
}
