# Component Importance Index Scoring

ManifestVault computes the Component Importance Index (CII) per workload:

```text
CII(workload) = sum(severity_weight * privilege_multiplier * depth_multiplier)
```

Each finding is de-duplicated by `(container, package_name, cve_id)` before scoring so a package seen in multiple layers is counted once. When duplicates exist, the topmost layer wins because it is the runtime-visible package.

## Severity Weight

Severity comes from the CVSS base score in the OSV advisory. Numeric scores and CVSS v3 vectors are supported.

| CVSS base score | Severity | Weight |
| --- | --- | ---: |
| 0.0 | None | 0 |
| 0.1-3.9 | Low | 1 |
| 4.0-6.9 | Medium | 3 |
| 7.0-8.9 | High | 7 |
| 9.0-10.0 | Critical | 10 |

## Privilege Multiplier

Privilege factors stack when more than one applies:

| Factor | Multiplier |
| --- | ---: |
| Container is `privileged: true` or adds `SYS_ADMIN` / `CAP_SYS_ADMIN` | 2.0 |
| Container runs as UID 0, or omits `runAsNonRoot: true` and does not set a non-root UID | 1.5 |
| Workload sets `hostNetwork: true` or `hostPID: true` | 1.5 |
| Vulnerable package is the container command/args binary | 2.0 |
| No privilege factor applies | 1.0 |

## Depth Multiplier

Layer depth reflects where the vulnerable package was found in the SBOM.

| Layer position | Multiplier |
| --- | ---: |
| Base layer, depth `0` | 0.7 |
| Intermediate layer | 1.0 |
| Top layer | 1.3 |

## Example

A workload runs `openssl` from a non-root container. The SBOM finds vulnerable `openssl` in the base layer, and the OSV advisory has CVSS `8.1` (`High`, weight `7`).

```text
finding score = 7 * 2.0 * 0.7 = 9.8
```

If the same container were privileged, the finding would stack the privileged and entrypoint factors:

```text
finding score = 7 * 2.0 * 2.0 * 0.7 = 19.6
```
