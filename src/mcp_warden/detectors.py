"""Content detectors: sensitive data (PII / secrets) and prompt injection.

Everything here is deterministic and runs offline. The learned injection classifier is a
hashed character-n-gram logistic regression (numpy only) whose weights ship with the
package; see ``mcp_warden.train`` for how it was trained and ``evals/`` for its scores.
"""

from __future__ import annotations

import re
import unicodedata
import zlib
from dataclasses import dataclass
from importlib import resources
from typing import Any

import numpy as np


@dataclass(frozen=True)
class Finding:
    kind: str
    detail: str
    score: float = 1.0


# --- sensitive data ----------------------------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits][::-1]
    total = sum(nums[0::2]) + sum(sum(divmod(2 * d, 10)) for d in nums[1::2])
    return total % 10 == 0


SENSITIVE: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "phone": re.compile(r"(?<!\w)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "aws_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{30,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
}


def find_sensitive(text: str, kinds: list[str] | None = None) -> list[tuple[str, int, int]]:
    """Return (kind, start, end) spans of sensitive data."""
    out: list[tuple[str, int, int]] = []
    for kind, pat in SENSITIVE.items():
        if kinds is not None and kind not in kinds:
            continue
        for m in pat.finditer(text):
            if kind == "credit_card":
                digits = re.sub(r"\D", "", m.group(0))
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    continue
            out.append((kind, m.start(), m.end()))
    return out


def redact(text: str, kinds: list[str] | None = None,
           allow_values: frozenset[str] = frozenset()) -> tuple[str, list[Finding]]:
    """Mask sensitive spans; values in ``allow_values`` (e.g. echoed call args) are kept."""
    spans = sorted(find_sensitive(text, kinds), key=lambda s: (s[1], -s[2]))
    spans = [sp for sp in spans if text[sp[1]:sp[2]] not in allow_values]
    findings: list[Finding] = []
    out, pos = [], 0
    for kind, a, z in spans:
        if a < pos:
            continue  # overlapping span already redacted
        out.append(text[pos:a])
        out.append(f"[REDACTED:{kind}]")
        findings.append(Finding("sensitive", kind))
        pos = z
    out.append(text[pos:])
    return "".join(out), findings


def walk_strings(obj: Any, fn: Any) -> Any:
    """Apply ``fn`` to every string inside a JSON-like structure (returns a new object)."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [walk_strings(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: walk_strings(v, fn) for k, v in obj.items()}
    return obj


# --- prompt injection --------------------------------------------------------------------

_INJECTION_RULES: list[tuple[str, float, re.Pattern[str]]] = [
    (name, w, re.compile(p, re.I | re.S)) for name, w, p in [
        ("ignore_instructions", 0.9,
         r"\b(ignore|disregard|forget|override|bypass)\b\s+(all\s+|any\s+|the\s+|your\s+|of\s+)*"
         r"(previous|prior|above|earlier|preceding|system|safety|original|existing)?\s*"
         r"(instructions?|prompts?|rules?|directions?|guidelines|guardrails|context)\b"),
        ("ignore_everything", 0.8,
         r"\b(ignore|disregard|forget)\b\s+(all\s+|of\s+)*(the\s+)?(above|everything|"
         r"what (you were|i) told|all that)\b"),
        ("new_instructions", 0.6, r"\b(new|updated|real|actual)\s+(instructions?|task|rules?)\s*:"),
        ("role_hijack", 0.6,
         r"\b(you are now|from now on,? you|act as|pretend (to be|you are)|roleplay as)\b"),
        ("system_spoof", 0.7,
         r"(^|\n|<|\[)\s*(system|assistant|developer)\s*(:|>|\])|<\|im_start\|>|\[INST\]"),
        ("hidden_tag", 0.7, r"<\s*(important|system|secret|hidden|instructions?)\s*>"),
        ("conceal", 0.6,
         r"\b(do not|don't|never)\s+(tell|mention|reveal|inform|show)\b.{0,30}"
         r"\b(user|anyone|human)"),
        ("exfil_verbs", 0.5,
         r"\b(send|forward|email|post|upload|exfiltrate|leak)\b.{0,60}\b(password|secret|key|token|"
         r"credentials?|records?|ssh|id_rsa|env|api[_ ]?key|all (the )?data)"),
        ("tool_coercion", 0.5,
         r"\b(call|invoke|use|run|execute)\b.{0,20}\b(the\s+)?\w+_\w+\b.{0,20}\b(tool|function|with)"),
        ("prompt_leak", 0.6,
         r"\b(reveal|print|show|repeat|output)\b.{0,30}\b(system prompt|your (instructions|prompt)|"
         r"initial prompt|hidden prompt)"),
        ("jailbreak_persona", 0.6, r"\b(DAN|do anything now|developer mode|jailbreak)\b"),
        ("sensitive_paths", 0.5, r"(~/\.ssh|id_rsa|/etc/passwd|\.env\b|\.aws/credentials)"),
        ("german_ignore", 0.8,
         r"\b(ignoriere|vergiss|missachte)\b.{0,40}\b(anweisungen|vorherigen|alles|befehle)"),
    ]
]

_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]|[\U000e0000-\U000e007f]")


def heuristic_injection(text: str) -> tuple[float, list[str]]:
    """Weighted-rule score in [0, 1] plus the names of the rules that fired."""
    hits: list[str] = []
    score = 0.0
    if _INVISIBLE.search(text):
        hits.append("invisible_unicode")
        score = 1 - (1 - score) * (1 - 0.7)
    norm = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text))
    for name, w, pat in _INJECTION_RULES:
        if pat.search(norm):
            hits.append(name)
            score = 1 - (1 - score) * (1 - w)  # noisy-OR
    return score, hits


class HashedNgramClassifier:
    """Logistic regression on hashed char 3-5-grams + word unigrams (numpy only)."""

    def __init__(self, w: np.ndarray, b: float, dim: int) -> None:
        self.w, self.b, self.dim = w, b, dim

    @staticmethod
    def hashed_counts(text: str, dim: int) -> dict[int, float]:
        """L2-normalised hashed counts of char 3-5-grams and word unigrams."""
        t = " " + re.sub(r"\s+", " ", text.lower())[:4000] + " "
        grams = [t[j:j + n] for n in (3, 4, 5) for j in range(len(t) - n + 1)]
        grams += ["w:" + w for w in re.findall(r"[a-zäöüß]+", t)]
        counts: dict[int, float] = {}
        for g in grams:
            h = zlib.crc32(g.encode()) % dim
            counts[h] = counts.get(h, 0.0) + 1.0
        norm = float(np.sqrt(sum(v * v for v in counts.values()))) or 1.0
        return {k: v / norm for k, v in counts.items()}

    @classmethod
    def features(cls, texts: list[str], dim: int) -> np.ndarray:
        x = np.zeros((len(texts), dim), dtype=np.float32)
        for i, t in enumerate(texts):
            for k, v in cls.hashed_counts(t, dim).items():
                x[i, k] = v
        return x

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        z = self.features(texts, self.dim) @ self.w + self.b
        return np.asarray(1 / (1 + np.exp(-z)))

    @classmethod
    def load_default(cls) -> HashedNgramClassifier:
        with resources.files("mcp_warden").joinpath("injection_model.npz").open("rb") as f:
            d = np.load(f)
            return cls(d["w"].astype(np.float32), float(d["b"]), int(d["dim"]))


class InjectionDetector:
    """Combine rules and the learned model: score = max(rule score, model probability)."""

    def __init__(self, use_model: bool = True) -> None:
        self.model: HashedNgramClassifier | None = None
        if use_model:
            try:
                self.model = HashedNgramClassifier.load_default()
            except (FileNotFoundError, OSError, KeyError):
                self.model = None

    def score(self, text: str) -> tuple[float, list[str]]:
        s, hits = heuristic_injection(text)
        if self.model is not None and text.strip():
            p = float(self.model.predict_proba([text])[0])
            if p >= 0.5:
                hits.append(f"model:{p:.2f}")
            s = max(s, p)
        return s, hits
