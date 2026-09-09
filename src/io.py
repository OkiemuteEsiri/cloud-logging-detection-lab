from __future__ import annotations

import json
from pathlib import Path

from .models import CloudEvent


def load_events(path: str | Path) -> list[CloudEvent]:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("input must be a JSON array")
    events = [CloudEvent.from_dict(record) for record in records]
    ids = [event.event_id for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event_id detected")
    return sorted(events, key=lambda item: item.timestamp)
