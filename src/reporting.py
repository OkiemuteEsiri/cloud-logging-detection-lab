from __future__ import annotations

from collections import Counter

from .models import Finding, SEVERITY_WEIGHTS


def posture_score(findings: list[Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return max(0, 100 - min(100, penalty * 4))


def render_markdown(findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [
        "# Cloud Detection Assessment",
        "",
        f"Posture score: **{posture_score(findings)}/100**",
        "",
        "## Summary",
        "",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No configured detections matched the supplied synthetic telemetry.")
    for finding in findings:
        lines.extend([
            f"### {finding.rule_id} — {finding.title}",
            "",
            f"- Severity: **{finding.severity.upper()}**",
            f"- Confidence: {finding.confidence}%",
            f"- Provider: {finding.provider}",
            f"- Actor: `{finding.actor}`",
            f"- Evidence: {', '.join(finding.evidence_event_ids)}",
            f"- ATT&CK: {', '.join(finding.mitre_attack)}",
            f"- Rationale: {finding.rationale}",
            f"- Remediation: {finding.remediation}",
            "",
        ])
    return "\n".join(lines)
