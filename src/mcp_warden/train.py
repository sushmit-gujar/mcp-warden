"""Train the shipped injection classifier (reproducible; numpy only).

    python -m mcp_warden.train --train data/train.parquet --out src/mcp_warden/injection_model.npz

The shipped weights were trained on the *train* split of deepset/prompt-injections
(Apache-2.0) only; test splits are reserved for evaluation.
"""

from __future__ import annotations

import argparse

import numpy as np

from .detectors import HashedNgramClassifier


def fit(texts: list[str], labels: list[int], dim: int = 2**15, epochs: int = 300,
        lr: float = 0.5, l2: float = 1e-4, seed: int = 0) -> tuple[np.ndarray, float]:
    import scipy.sparse as sp

    rows, cols, vals = [], [], []
    for i, t in enumerate(texts):
        for k, v in HashedNgramClassifier.hashed_counts(t, dim).items():
            rows.append(i)
            cols.append(k)
            vals.append(v)
    x = sp.csr_matrix((vals, (rows, cols)), shape=(len(texts), dim), dtype=np.float32)
    xt = x.T.tocsr()
    y = np.asarray(labels, dtype=np.float32)
    rng = np.random.default_rng(seed)
    w = rng.normal(0, 1e-3, dim).astype(np.float32)
    b = 0.0
    pos_w = (len(y) - y.sum()) / max(y.sum(), 1)  # balance classes
    sw = np.where(y == 1, pos_w, 1.0).astype(np.float32)
    sw /= sw.mean()
    m_w, v_w, m_b, v_b = np.zeros_like(w), np.zeros_like(w), 0.0, 0.0
    for t in range(1, epochs + 1):  # full-batch Adam
        p = 1 / (1 + np.exp(-(x @ w + b)))
        g = (p - y) * sw / len(y)
        gw = xt @ g + l2 * w
        gb = float(g.sum())
        m_w = 0.9 * m_w + 0.1 * gw
        v_w = 0.999 * v_w + 0.001 * gw**2
        m_b = 0.9 * m_b + 0.1 * gb
        v_b = 0.999 * v_b + 0.001 * gb**2
        w -= lr * 0.01 * (m_w / (1 - 0.9**t)) / (np.sqrt(v_w / (1 - 0.999**t)) + 1e-8)
        b -= lr * 0.01 * (m_b / (1 - 0.9**t)) / (np.sqrt(v_b / (1 - 0.999**t)) + 1e-8)
    return w, b


def main() -> None:
    import pyarrow.parquet as pq

    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dim", type=int, default=2**15)
    a = ap.parse_args()
    rows = pq.read_table(a.train).to_pylist()
    w, b = fit([r["text"] for r in rows], [int(r["label"]) for r in rows], dim=a.dim)
    np.savez_compressed(a.out, w=w.astype(np.float16), b=np.float32(b), dim=np.int64(a.dim))
    print(f"saved {a.out} (n={len(rows)})")


if __name__ == "__main__":
    main()
