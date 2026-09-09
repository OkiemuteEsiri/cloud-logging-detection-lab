# Detection Engineering Methodology

## 1. Define telemetry contract
Normalize provider-specific audit events into a small canonical schema. Preserve provider, actor, source IP, region, resource, outcome, privilege context, MFA state and event ID.

## 2. Establish analytic intent
Each rule answers a bounded defensive question. Rules should be explainable, map to evidence, and avoid treating a single weak signal as confirmed compromise.

## 3. Validate safely
Use only synthetic records in this repository. Positive fixtures prove a rule can match its intended behavior; negative fixtures prove expected benign variants do not match.

## 4. Triage workflow
For a matched finding:
1. Confirm event integrity and time normalization.
2. Validate identity privilege and expected administrative change windows.
3. Review source IP, region and neighboring audit activity.
4. Identify affected resources and any downstream access.
5. Escalate based on evidence, confidence and business context.

## 5. Remediation and validation
- MFA gap: enforce phishing-resistant MFA for privileged identities; retest with synthetic MFA=true telemetry.
- Logging impairment: restore audit logging, protect destinations and alert on configuration change; validate logs remain available.
- Regional fan-out: validate automation/service behavior, constrain permissions and investigate anomalous sessions; replay approved-pattern fixtures.
- Public storage: restore least privilege, review access logs and enforce preventive policy-as-code; rerun the assessment and confirm CLD-004 clears.

## 6. Quality gates
- malformed and duplicate event IDs fail closed;
- tests cover positive and negative behavior;
- source compiles in CI;
- the synthetic dataset must generate a report without external services.

## Limitations
This lab is not a SIEM, does not query real cloud tenants, and does not model every provider-specific event schema. Thresholds are illustrative and require tuning against real authorized environments before operational use.
