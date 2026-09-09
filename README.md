# Cloud Logging Detection Lab

A recruiter-facing cloud detection engineering project that demonstrates how normalized AWS-, Azure-, and GCP-style audit telemetry can be converted into explainable defensive findings, evidence-preserving reports, and repeatable remediation validation.

> All data in this repository is synthetic. The project performs no live cloud API calls, contains no real credentials, and makes no claims about production compromise.

## Problem statement

Cloud audit logs are rich but provider-specific. Detection teams need consistent schemas, deterministic analytics, evidence retention, meaningful severity/confidence separation, and a workflow that connects detection to triage, remediation, and validation. This lab implements that lifecycle with safe synthetic telemetry.

## Architecture

```text
Synthetic cloud audit events
          |
          v
  Ingestion + validation
          |
          v
  Normalized CloudEvent model
          |
          v
  Defensive detection analytics
          |
          v
  Evidence-preserving Findings
          |
          v
  Posture metrics + Markdown report
```

See [`docs/architecture.md`](docs/architecture.md) for component detail.

## Implemented detections

| Rule | Detection | Severity | ATT&CK context |
|---|---|---:|---|
| CLD-001 | Privileged cloud sign-in without MFA | Critical | T1078.004 |
| CLD-002 | Cloud audit logging impairment | Critical | T1562.008 |
| CLD-003 | Privileged API activity across multiple regions | High | T1078.004 |
| CLD-004 | Storage resource changed to public access | High | T1530 |

MITRE ATT&CK mappings are used as defensive engineering context only. A rule match is an investigation hypothesis, not proof of malicious activity.

## Repository structure

```text
.github/workflows/security-quality.yml  CI quality gates
data/synthetic_events.json              Safe multi-cloud audit fixtures
docs/architecture.md                    Technical design
docs/methodology.md                     Detection, triage and validation method
reports/example-assessment.md           Executive-style synthetic report
src/models.py                            Canonical telemetry/finding models
src/io.py                                Ingestion and fail-closed validation
src/detections.py                        Explainable analytics
src/reporting.py                         Posture metrics and report rendering
src/cli.py                               Repeatable command-line runner
tests/test_detections.py                 Positive, negative and validation tests
```

## Usage

Python 3.12+ is sufficient; no third-party packages are required.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_events.json --output reports/generated-assessment.md
```

## Detection engineering design

### Normalization
Provider-specific records are reduced to a canonical model while retaining actor, provider, source IP, region, resource, outcome, privilege context, MFA state, timestamp and evidence ID.

### Validation
Malformed records, unsupported providers and duplicate event identifiers fail closed. Timestamps are normalized to UTC.

### Explainability
Every finding records the rule ID, title, severity, confidence, identity, provider, evidence event IDs, ATT&CK context, rationale and remediation guidance.

### Risk handling
Severity represents potential impact; confidence represents analytic certainty. They are intentionally separate so a high-impact but lower-confidence lead is not misrepresented as confirmed compromise.

### Revalidation
Each control has a closure path. For example, an MFA gap should be remediated through privileged MFA enforcement and then retested with a synthetic compliant event. Public storage findings should clear after policy correction and assessment rerun.

See [`docs/methodology.md`](docs/methodology.md).

## Example output

The bundled synthetic scenario demonstrates an administrative sequence with:

- a privileged sign-in without MFA;
- activity spanning three cloud regions within a short window;
- a storage policy changed to public access;
- audit logging disabled.

The resulting report preserves the source event IDs and recommends investigation and remediation steps without asserting that compromise occurred. See [`reports/example-assessment.md`](reports/example-assessment.md).

## CI/CD security checks

The least-privilege GitHub Actions workflow uses read-only repository permissions and runs:

1. Python source/test compilation;
2. unit tests;
3. a synthetic assessment smoke test;
4. report-output validation.

Workflow presence does not imply success until the specific commit run is verified.

## Skills demonstrated

- Cloud security engineering
- Detection engineering
- Multi-cloud telemetry normalization
- Python security automation
- Evidence-preserving incident triage
- MITRE ATT&CK mapping
- Risk scoring and reporting
- Unit-test design
- CI quality gates
- Remediation and validation workflow design

## Limitations

This repository is intentionally bounded. It is not a SIEM, does not ingest live CloudTrail/Azure Activity Log/GCP Audit Log feeds, does not perform tenant discovery, and does not include provider credentials or automated containment. Detection thresholds are illustrative and require tuning against an authorized environment before operational use.

## Roadmap

- Add provider-specific adapter modules while retaining the canonical event contract.
- Add identity-baseline and impossible-travel style analytics using synthetic fixtures.
- Add rule metadata/versioning and coverage reporting.
- Add JSON/SARIF-style machine-readable output.
- Add synthetic regression datasets for expected administrative automation.

## Security and ethics

This project is designed for defensive learning, portfolio demonstration, and authorized security engineering. It includes no exploit payloads, credential theft, persistence, destructive actions, or production targeting.

## License

Use for learning and authorized defensive security work. Add a formal license if this project is redistributed beyond the portfolio context.
