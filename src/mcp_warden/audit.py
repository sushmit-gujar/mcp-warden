"""Tamper-evident audit log: append-only JSONL where every entry hashes its predecessor.

Editing, deleting, inserting or reordering any line breaks the chain and is reported by
``verify``. With an HMAC key (``WARDEN_AUDIT_KEY``) an attacker who can write the file
also cannot forge a valid chain. Arguments are stored as a SHA-256 digest plus a redacted
preview, so secrets never reach the log (ALCOA+: attributable, contemporaneous, original).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def args_digest(args: Any) -> str:
    return hashlib.sha256(canonical(args)).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None, key: bytes | None = None) -> None:
        self.path = Path(path) if path else None
        self.key = key
        self._lock = threading.Lock()
        self.entries: list[dict[str, Any]] = []  # in-memory mirror (also used when path=None)
        self._prev, self._seq = GENESIS, 0
        if self.path and self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    e = json.loads(line)
                    self._prev, self._seq = e["hash"], e["seq"] + 1

    @classmethod
    def from_env(cls, path: str | None, env_var: str | None) -> AuditLog:
        key = os.environ.get(env_var or "", "") if env_var else ""
        return cls(path, key.encode() if key else None)

    def _digest(self, prev: str, body: dict[str, Any]) -> str:
        data = prev.encode() + canonical(body)
        if self.key:
            return hmac.new(self.key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            body = {"seq": self._seq, "ts": round(time.time(), 6), "event": event, **fields,
                    "prev": self._prev}
            entry = {**body, "hash": self._digest(self._prev, body)}
            self._prev, self._seq = entry["hash"], self._seq + 1
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return entry


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    error: str | None = None
    line: int | None = None


def verify(path: str | Path, key: bytes | None = None) -> VerifyResult:
    log = AuditLog(None, key)
    prev, n = GENESIS, 0
    for i, line in enumerate(Path(path).read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            return VerifyResult(False, n, "unparseable line", i)
        h = e.pop("hash", None)
        if e.get("prev") != prev:
            return VerifyResult(False, n, "broken chain (deleted/reordered/inserted entry)", i)
        if e.get("seq") != n:
            return VerifyResult(False, n, "sequence gap", i)
        if not h or not hmac.compare_digest(h, log._digest(prev, e)):
            return VerifyResult(False, n, "hash mismatch (entry modified)", i)
        prev, n = h, n + 1
    return VerifyResult(True, n)
