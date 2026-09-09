from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 6, "critical": 10}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class CloudEvent:
    event_id: str
    timestamp: datetime
    provider: str
    actor: str
    action: str
    source_ip: str
    region: str
    resource: str
    outcome: str
    mfa: bool | None = None
    privileged: bool = False
    metadata: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> "CloudEvent":
        required = ["event_id", "timestamp", "provider", "actor", "action", "source_ip", "region", "resource", "outcome"]
        missing = [key for key in required if not record.get(key)]
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        provider = str(record["provider"]).lower()
        if provider not in {"aws", "azure", "gcp"}:
            raise ValueError(f"unsupported provider: {provider}")
        return cls(
            event_id=str(record["event_id"]),
            timestamp=parse_timestamp(str(record["timestamp"])),
            provider=provider,
            actor=str(record["actor"]),
            action=str(record["action"]),
            source_ip=str(record["source_ip"]),
            region=str(record["region"]),
            resource=str(record["resource"]),
            outcome=str(record["outcome"]).lower(),
            mfa=record.get("mfa"),
            privileged=bool(record.get("privileged", False)),
            metadata=dict(record.get("metadata", {})),
        )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: int
    actor: str
    provider: str
    evidence_event_ids: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    rationale: str
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"invalid severity: {self.severity}")
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
