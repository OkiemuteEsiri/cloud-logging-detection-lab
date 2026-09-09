# Architecture

## Objective

Provide a safe, provider-neutral cloud logging and detection engineering lab using synthetic AWS-, Azure-, and GCP-style audit events.

## Data flow

`synthetic JSON -> ingestion/validation -> normalized CloudEvent -> detection analytics -> Finding objects -> posture metrics/report`

## Components

- `src/models.py` — immutable normalized event/finding models and UTC timestamp normalization.
- `src/io.py` — JSON ingestion, duplicate-event rejection and schema enforcement.
- `src/detections.py` — deterministic defensive analytics.
- `src/reporting.py` — severity-weighted posture score and evidence-preserving Markdown report.
- `src/cli.py` — repeatable assessment entry point.
- `tests/` — behavior, negative-path and validation tests.

## Design controls

1. Evidence event IDs are preserved in findings.
2. Severity and confidence are separate attributes.
3. Detection matches indicate investigation hypotheses, not proof of compromise.
4. Unsupported providers and malformed records fail closed.
5. The lab performs no live cloud API calls and stores no credentials.

## Detection coverage

| Rule | Behavior | ATT&CK context |
|---|---|---|
| CLD-001 | Privileged sign-in without MFA | T1078.004 |
| CLD-002 | Audit logging impairment | T1562.008 |
| CLD-003 | Privileged multi-region API fan-out | T1078.004 |
| CLD-004 | Public storage policy change | T1530 |

ATT&CK mappings are defensive context for detection engineering and do not assert malicious activity.
