"""Append-only JSONL ledger of everything the demo generated.

The verification step reads this to tell the presenter exactly which assets, domains and
time window to look for in the Infoblox portal.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Iterator


class RunLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, sort_keys=True, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        return list(self._iter())

    def _iter(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue

    def since(self, iso_ts: str) -> list[dict[str, Any]]:
        return [e for e in self._iter() if e.get("started", e.get("timestamp", "")) >= iso_ts]
