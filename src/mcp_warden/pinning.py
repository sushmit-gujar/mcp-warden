"""Tool-definition integrity: scan descriptions for poisoning, pin full definitions by hash.

Per the OWASP MCP Security Cheat Sheet, the *whole* definition (description, inputSchema,
outputSchema, annotations) is hashed, so flipping ``readOnlyHint`` is detected too.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .audit import canonical
from .detectors import Finding, heuristic_injection

_DEF_KEYS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def fingerprint(tool: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({k: tool.get(k) for k in _DEF_KEYS})).hexdigest()


def scan_definition(tool: dict[str, Any], other_tools: set[str] | None = None) -> list[Finding]:
    """Flag hidden instructions anywhere in a tool definition, incl. schema text."""
    text = json.dumps({k: tool.get(k) for k in _DEF_KEYS if k != "name"}, ensure_ascii=False)
    text = text.encode().decode("unicode_escape", errors="ignore")  # surface \\u escapes
    findings: list[Finding] = []
    score, hits = heuristic_injection(text)
    if score >= 0.5:
        findings.append(Finding("tool_poisoning", ",".join(hits), score))
    if other_tools:
        name = tool.get("name")
        desc = str(tool.get("description") or "")
        shadowed = [t for t in other_tools if t != name and t in desc]
        if shadowed:
            findings.append(Finding("tool_shadowing", f"mentions other tools: {shadowed}", 0.6))
    return findings


class PinStore:
    """Trust-on-first-use lockfile of tool fingerprints, keyed by server + tool name."""

    def __init__(self, path: str | None) -> None:
        self.path = Path(path) if path else None
        self.pins: dict[str, str] = {}
        if self.path and self.path.exists():
            self.pins = json.loads(self.path.read_text())

    def check(self, server: str, tool: dict[str, Any]) -> tuple[str, str | None]:
        """Return ("new"|"ok"|"changed", previous_fp)."""
        key = f"{server}::{tool.get('name')}"
        fp = fingerprint(tool)
        prev = self.pins.get(key)
        if prev is None:
            self.pins[key] = fp
            self._save()
            return "new", None
        return ("ok", prev) if prev == fp else ("changed", prev)

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.pins, indent=2, sort_keys=True))
