"""Score the prompt-injection detectors on public, held-out test splits.

Datasets (downloaded from the HF Hub at run time, not redistributed):
  * deepset/prompt-injections  (Apache-2.0)  test split, 116 texts (EN + some DE)
  * xTRam1/safe-guard-prompt-injection        test split, 2,060 texts (cross-domain)
The shipped classifier was trained on deepset *train* only. As an in-domain reference we
also train a throw-away model on safe-guard *train* (evaluation only, never shipped).
"""

from __future__ import annotations

import json
from typing import Any

import numpy as np

from mcp_warden.detectors import HashedNgramClassifier, heuristic_injection
from mcp_warden.train import fit

SETS = {
    "deepset": ("deepset/prompt-injections",
                "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
                "data/test-00000-of-00001-701d16158af87368.parquet"),
    "safeguard": ("xTRam1/safe-guard-prompt-injection", "data/train-00000-of-00001.parquet",
                  "data/test-00000-of-00001.parquet"),
}


def _load(repo: str, f: str) -> tuple[list[str], np.ndarray]:
    import pyarrow.parquet as pq
    from huggingface_hub import hf_hub_download

    rows = pq.read_table(hf_hub_download(repo, f, repo_type="dataset")).to_pylist()
    return [r["text"] for r in rows], np.array([int(r["label"]) for r in rows])


def prf(scores: np.ndarray, y: np.ndarray, thr: float) -> dict[str, float]:
    p = scores >= thr
    tp, fp = int((p & (y == 1)).sum()), int((p & (y == 0)).sum())
    fn = int((~p & (y == 1)).sum())
    return {"precision": round(tp / max(tp + fp, 1), 3), "recall": round(tp / max(tp + fn, 1), 3),
            "f1": round(2 * tp / max(2 * tp + fp + fn, 1), 3),
            "fpr": round(fp / max(int((y == 0).sum()), 1), 3)}


def main() -> dict[str, Any]:
    shipped = HashedNgramClassifier.load_default()
    xs_tr, ys_tr = _load(SETS["safeguard"][0], SETS["safeguard"][1])
    w, b = fit(xs_tr, list(ys_tr))
    sg_model = HashedNgramClassifier(w, b, 2**15)
    out: dict[str, Any] = {}
    for name, (repo, _, test) in SETS.items():
        x, y = _load(repo, test)
        rules = np.array([heuristic_injection(t)[0] for t in x])
        model = shipped.predict_proba(x)
        sg = sg_model.predict_proba(x)
        out[name] = {"n": len(y), "positives": int(y.sum()),
                     "rules@0.6": prf(rules, y, 0.6),
                     "model(deepset-train)@0.5": prf(model, y, 0.5),
                     "ensemble=max(rules,model)@0.6": prf(np.maximum(rules, model), y, 0.6),
                     "ref: model(safeguard-train)@0.5": prf(sg, y, 0.5)}
    return out


if __name__ == "__main__":
    print(json.dumps(main(), indent=2))
