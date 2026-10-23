"""End-to-end scenario evaluation through the real stdio proxy (needs the `mcp` SDK).

For every scenario a fresh MCP client session is opened against either
(a) the upstream server directly (baseline: what an unguarded agent would get), or
(b) ``mcp-warden run --policy ... -- <server>``.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .approvals import ApprovalStore
from .policy import Policy

_DIGEST = re.compile(r"mcp-warden approve (\S+) ([0-9a-f]{64})")


@dataclass
class ScenarioResult:
    id: str
    category: str
    attack: bool
    expect: str
    outcome: str
    passed: bool
    latencies_ms: list[float] = field(default_factory=list)


def classify(result: Any) -> str:
    text = " ".join(getattr(c, "text", "") for c in (result.content or []))
    if result.is_error:
        if "needs human approval" in text:
            return "require_approval"
        if "was withheld" in text:
            return "withheld"
        if "blocked by policy" in text:
            return "deny"
        return "error"
    return "redacted" if "[REDACTED:" in text else "allow"


def _expand(v: Any) -> Any:
    if isinstance(v, str):
        m = re.fullmatch(r"\{\{(.)\*(\d+)\}\}", v)
        return m.group(1) * int(m.group(2)) if m else v
    if isinstance(v, dict):
        return {k: _expand(x) for k, x in v.items()}
    return v


async def _session(cmd: list[str], env: dict[str, str], steps: list[dict[str, Any]],
                   approvals: ApprovalStore | None) -> tuple[str, list[float]]:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=env)
    outcome, lat = "allow", []
    async with Client(params) as c:
        listed = {t.name for t in (await c.list_tools()).tools}
        last_text = ""
        for st in steps:
            if st.get("approve_last"):
                m = _DIGEST.search(last_text)
                if m and approvals is not None:
                    approvals.grant(m.group(1), m.group(2), "eval-harness")
                continue
            if st["tool"] not in listed and st["tool"] in _KNOWN_DEMO_TOOLS:
                outcome = "hidden"
                continue
            t = time.perf_counter()
            r = await c.call_tool(st["tool"], _expand(st.get("args") or {}))
            lat.append((time.perf_counter() - t) * 1000)
            last_text = " ".join(getattr(x, "text", "") for x in (r.content or []))
            outcome = classify(r)
    return outcome, lat


_KNOWN_DEMO_TOOLS = {"search_sops", "read_document", "read_record", "send_email",
                     "post_to_ticket", "run_sql", "read_file"}


def run_suite(scenarios_path: str | Path, policy_path: str | Path, server: list[str],
              guarded: bool = True, detector: str | None = None) -> list[ScenarioResult]:
    scenarios = yaml.safe_load(Path(scenarios_path).read_text())
    results = []
    for sc in scenarios:
        with tempfile.TemporaryDirectory() as td:
            pol = Path(td) / "policy.yaml"
            shutil.copy(policy_path, pol)
            if detector:
                pol.write_text(re.sub(r"detector: \w+", f"detector: {detector}",
                                      pol.read_text()))
            policy = Policy.load(pol)
            approvals = ApprovalStore(policy.approvals_path, policy.approval_ttl_s)
            warden = [sys.executable, "-m", "mcp_warden.cli", "run", "--policy", str(pol),
                      "--server-name", "demo", "--"]
            base_env = {k: v for k, v in os.environ.items() if not k.startswith("WARDEN_DEMO")}
            if guarded and sc.get("prepin"):  # first, a clean session pins the definitions
                asyncio.run(_session(warden + server, base_env, [], approvals))
            env = {**base_env, **(sc.get("server_env") or {})}
            cmd = warden + server if guarded else server
            outcome, lat = asyncio.run(_session(cmd, env, sc["steps"], approvals))
        exp = sc["expect"]
        passed = outcome == exp
        results.append(ScenarioResult(sc["id"], sc["category"], bool(sc["attack"]), exp,
                                      outcome, passed, lat))
    return results


_BLOCKING = {"deny", "withheld", "require_approval", "hidden"}


def _stopped(r: ScenarioResult) -> bool:
    """An attack counts as stopped if it got its expected outcome or was blocked outright.
    Redaction alone does not count as stopping e.g. a prompt injection."""
    return r.passed or r.outcome in _BLOCKING


def summarize(results: list[ScenarioResult]) -> dict[str, Any]:
    attacks = [r for r in results if r.attack]
    benign = [r for r in results if not r.attack]
    stopped = [r for r in attacks if _stopped(r)]
    cats: dict[str, list[int]] = {}
    for r in attacks:
        c = cats.setdefault(r.category, [0, 0, 0])
        c[0] += 1
        c[1] += _stopped(r)
        c[2] += r.passed
    return {
        "attacks": len(attacks), "attacks_stopped": len(stopped),
        "attacks_expected_outcome": sum(r.passed for r in attacks),
        "benign": len(benign), "benign_passed": sum(r.passed for r in benign),
        "false_positives": [r.id for r in benign if not r.passed],
        "missed_attacks": [r.id for r in attacks if not _stopped(r)],
        "by_category": {k: {"n": v[0], "stopped": v[1], "expected": v[2]}
                        for k, v in cats.items()},
    }


async def _latency(cmd: list[str], n: int) -> list[float]:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    out = []
    async with Client(StdioServerParameters(command=cmd[0], args=cmd[1:])) as c:
        await c.list_tools()
        for i in range(n + 10):
            t = time.perf_counter()
            await c.call_tool("read_record", {"patient_id": "P-1001"}) if i % 2 else \
                await c.call_tool("search_sops", {"query": "deviation"})
            if i >= 10:  # warm-up
                out.append((time.perf_counter() - t) * 1000)
    return out


def latency_overhead(policy_path: str | Path, server: list[str], n: int = 300
                     ) -> dict[str, float]:
    with tempfile.TemporaryDirectory() as td:
        pol = Path(td) / "policy.yaml"
        text = Path(policy_path).read_text().replace("rate_limit: {calls: 5, per_seconds: 60}",
                                                      "rate_limit: {calls: 100000, per_seconds: 1}")
        pol.write_text(text)
        warden = [sys.executable, "-m", "mcp_warden.cli", "run", "--policy", str(pol), "--"]
        direct = asyncio.run(_latency(server, n))
        guarded = asyncio.run(_latency(warden + server, n))

    def q(xs: list[float], p: float) -> float:
        return statistics.quantiles(xs, n=100)[int(p) - 1]

    return {"n_calls": n, "direct_p50_ms": round(q(direct, 50), 2),
            "direct_p95_ms": round(q(direct, 95), 2), "warden_p50_ms": round(q(guarded, 50), 2),
            "warden_p95_ms": round(q(guarded, 95), 2),
            "overhead_p50_ms": round(q(guarded, 50) - q(direct, 50), 2)}
