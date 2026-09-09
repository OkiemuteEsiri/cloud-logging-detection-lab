# Example Cloud Detection Assessment

> Synthetic example only. No production tenant or client data is represented.

## Executive summary

The sample telemetry produces a concentrated cluster of high-risk administrative activity involving a privileged AWS-style identity. The evidence includes a successful sign-in without MFA, a public storage policy change, administrative activity spanning multiple regions, and audit logging impairment.

## Priority findings

| Priority | Rule | Risk | Validation focus |
|---|---|---|---|
| P0 | CLD-001 | Privileged authentication without MFA | Identity, session, source and change approval |
| P0 | CLD-002 | Audit logging impairment | Logging restoration and initiating actor |
| P1 | CLD-003 | Multi-region privileged API activity | Expected automation vs anomalous session |
| P1 | CLD-004 | Public storage policy change | Public exposure and object-access history |

## Recommended response sequence

1. Preserve available audit evidence and validate event integrity.
2. Review the privileged identity session and enforce MFA.
3. Restore/verify cloud audit logging and destination protections.
4. Remove unintended public storage access.
5. Review adjacent administrative actions and affected resources.
6. Re-run the assessment after remediation and confirm expected findings no longer match.

## Interpretation

These detections are intentionally explainable investigation leads. A match is not, by itself, evidence that an account was compromised or data was accessed maliciously.
