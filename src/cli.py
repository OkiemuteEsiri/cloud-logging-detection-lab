from __future__ import annotations

import argparse
from pathlib import Path

from .detections import run_detections
from .io import load_events
from .reporting import render_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Assess synthetic cloud audit telemetry with defensive detection analytics.")
    parser.add_argument("input", help="Path to JSON event array")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args = parser.parse_args()
    findings = run_detections(load_events(args.input))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(findings), encoding="utf-8")
    print(f"wrote {len(findings)} findings to {output}")


if __name__ == "__main__":
    main()
