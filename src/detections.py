from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .models import CloudEvent, Finding


def detect_privileged_login_without_mfa(events: list[CloudEvent]) -> list[Finding]:
    findings = []
    for event in events:
        if event.privileged and event.outcome == "success" and event.mfa is False and event.action.lower() in {"login", "signin", "consolelogin"}:
            findings.append(Finding(
                "CLD-001", "Privileged cloud sign-in without MFA", "critical", 95,
                event.actor, event.provider, (event.event_id,), ("T1078.004",),
                "A privileged identity authenticated successfully without MFA.",
                "Require phishing-resistant MFA for privileged identities and review the session and source context.",
            ))
    return findings


def detect_audit_logging_impairment(events: list[CloudEvent]) -> list[Finding]:
    risky_actions = {"stoplogging", "deleteauditlog", "disablelogging", "updateauditconfig:disable"}
    return [Finding(
        "CLD-002", "Cloud audit logging impairment", "critical", 90,
        event.actor, event.provider, (event.event_id,), ("T1562.008",),
        "An administrative action disabled or removed cloud audit logging.",
        "Restore logging, preserve available telemetry, validate log destinations and investigate the initiating identity.",
    ) for event in events if event.outcome == "success" and event.action.lower() in risky_actions]


def detect_privileged_api_fanout(events: list[CloudEvent], window_minutes: int = 15, region_threshold: int = 3) -> list[Finding]:
    grouped: dict[tuple[str, str], list[CloudEvent]] = defaultdict(list)
    for event in events:
        if event.privileged and event.outcome == "success":
            grouped[(event.provider, event.actor)].append(event)
    findings = []
    for (provider, actor), actor_events in grouped.items():
        ordered = sorted(actor_events, key=lambda e: e.timestamp)
        for i, first in enumerate(ordered):
            window = [e for e in ordered[i:] if e.timestamp - first.timestamp <= timedelta(minutes=window_minutes)]
            regions = {e.region for e in window}
            if len(regions) >= region_threshold:
                findings.append(Finding(
                    "CLD-003", "Privileged API activity across multiple regions", "high", 80,
                    actor, provider, tuple(e.event_id for e in window), ("T1078.004",),
                    f"Privileged activity touched {len(regions)} regions within {window_minutes} minutes.",
                    "Validate the administrative change window, identity session, source addresses and affected resources.",
                ))
                break
    return findings


def detect_public_storage_change(events: list[CloudEvent]) -> list[Finding]:
    actions = {"putbucketpolicy:public", "setblobcontainerpublic", "setbucketiam:allusers"}
    return [Finding(
        "CLD-004", "Storage resource changed to public access", "high", 88,
        event.actor, event.provider, (event.event_id,), ("T1530",),
        "A storage policy change introduced public access to a cloud data resource.",
        "Remove unintended public access, review object access logs, validate ownership and enforce preventive policy controls.",
    ) for event in events if event.outcome == "success" and event.action.lower() in actions]


def run_detections(events: list[CloudEvent]) -> list[Finding]:
    findings = []
    for detector in (detect_privileged_login_without_mfa, detect_audit_logging_impairment, detect_privileged_api_fanout, detect_public_storage_change):
        findings.extend(detector(events))
    return sorted(findings, key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[f.severity], f.rule_id))
