#!/usr/bin/env python3
"""Validate every entry: schema, id/URL match and publication gate.

Run before merging any manual edit; the site build applies the same rules.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from llmgram_assets.model import validate_record  # noqa: E402


def main() -> int:
    failures = 0
    paths = sorted((ROOT / "entries").glob("*.json"))
    for path in paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"{path.name}: invalid JSON: {exc}")
            failures += 1
            continue
        errors = validate_record(record)
        if path.stem != record.get("id"):
            errors.append("file name does not match id")
        for error in errors:
            print(f"{path.name}: {error}")
        failures += bool(errors)
    print(f"{len(paths)} entries, {failures} invalid")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
