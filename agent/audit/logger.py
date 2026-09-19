from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


class AuditLogger:
    def __init__(self, audit_dir: Path):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        self.path = self.audit_dir / f"audit-{day}.jsonl"

    def log(self, event: str, **payload: Any) -> dict[str, Any]:
        rec = {
            "id": str(uuid4()),
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **payload,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        return rec

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        files = sorted(self.audit_dir.glob("audit-*.jsonl"))
        rows: list[dict[str, Any]] = []
        for path in files[-5:]:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        return rows[-limit:]
