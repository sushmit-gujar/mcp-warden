"""Human approvals bound to an exact (tool, arguments) pair, single-use and expiring.

Following the OWASP AI-agent guidance: an approval for ``send_email(to=a)`` must not
authorise ``send_email(to=b)``, and must not be replayable.
"""

from __future__ import annotations

import json
import time
from pathlib import Path


class ApprovalStore:
    def __init__(self, path: str | None, ttl_s: float = 600.0) -> None:
        self.path = Path(path) if path else None
        self.ttl_s = ttl_s
        self._mem: list[dict[str, object]] = []

    def _load(self) -> list[dict[str, object]]:
        if self.path is None:
            return self._mem
        if not self.path.exists():
            return []
        return [json.loads(x) for x in self.path.read_text().splitlines() if x.strip()]

    def _store(self, items: list[dict[str, object]]) -> None:
        if self.path is None:
            self._mem = items
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("".join(json.dumps(i) + "\n" for i in items))

    def grant(self, tool: str, args_sha256: str, approver: str = "human") -> None:
        items = self._load()
        items.append({"tool": tool, "args_sha256": args_sha256, "approver": approver,
                      "expires": time.time() + self.ttl_s})
        self._store(items)

    def consume(self, tool: str, args_sha256: str) -> str | None:
        """Return the approver and delete the grant if a live matching one exists."""
        now = time.time()
        items = [i for i in self._load() if float(i["expires"]) > now]  # type: ignore[arg-type]
        for i, it in enumerate(items):
            if it["tool"] == tool and it["args_sha256"] == args_sha256:
                del items[i]
                self._store(items)
                return str(it.get("approver", "human"))
        self._store(items)
        return None
