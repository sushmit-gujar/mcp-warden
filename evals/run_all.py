"""Reproduce every number in the README:  python evals/run_all.py  (≈5 min on a laptop CPU)."""

from __future__ import annotations

import json
import platform
import sys
from dataclasses import asdict
from pathlib import Path

from injection_benchmark import main as injection_benchmark

from mcp_warden.evalsuite import latency_overhead, run_suite, summarize

ROOT = Path(__file__).resolve().parent.parent
SERVER = [sys.executable, str(ROOT / "examples" / "clinical_ops_server.py")]
POLICY = ROOT / "examples" / "policy.yaml"


def suite(name: str, **kw: object) -> dict[str, object]:
    res = run_suite(ROOT / "evals" / name, POLICY, SERVER, **kw)  # type: ignore[arg-type]
    return {"summary": summarize(res), "scenarios": [asdict(r) for r in res]}


def main() -> None:
    out = {
        "env": {"python": platform.python_version(), "machine": platform.machine(),
                "system": platform.system()},
        "suite_guarded_rules": suite("scenarios.yaml"),
        "suite_unguarded_baseline": suite("scenarios.yaml", guarded=False),
        "suite_guarded_ensemble": suite("scenarios.yaml", detector="ensemble"),
        "holdout_guarded_rules": suite("holdout.yaml"),
        "holdout_guarded_ensemble": suite("holdout.yaml", detector="ensemble"),
        "latency": latency_overhead(POLICY, SERVER, n=300),
        "injection_benchmark": injection_benchmark(),
    }
    (ROOT / "evals" / "results.json").write_text(json.dumps(out, indent=2))
    for k, v in out.items():
        if isinstance(v, dict) and "summary" in v:
            s = v["summary"]
            print(f"{k}: attacks stopped {s['attacks_stopped']}/{s['attacks']}, benign passed "
                  f"{s['benign_passed']}/{s['benign']}, missed={s['missed_attacks']}, "
                  f"fp={s['false_positives']}")
    print("latency", out["latency"])
    print(json.dumps(out["injection_benchmark"], indent=1))


if __name__ == "__main__":
    main()
