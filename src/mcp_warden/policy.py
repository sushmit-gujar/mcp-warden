"""Policy-as-code: a small, explicit YAML schema validated at load time."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

Action = Literal["allow", "deny", "require_approval"]
_ACTIONS = {"allow", "deny", "require_approval"}


class PolicyError(ValueError):
    pass


@dataclass
class ArgRule:
    pattern: re.Pattern[str] | None = None
    deny_patterns: list[re.Pattern[str]] = field(default_factory=list)
    allowed_values: list[Any] | None = None
    allowed_prefixes: list[str] | None = None
    max_length: int | None = None
    required: bool = False

    @classmethod
    def parse(cls, name: str, d: dict[str, Any]) -> ArgRule:
        unknown = set(d) - {"pattern", "deny_patterns", "allowed_values", "allowed_prefixes",
                            "max_length", "required"}
        if unknown:
            raise PolicyError(f"arg {name!r}: unknown keys {sorted(unknown)}")
        try:
            return cls(
                pattern=re.compile(d["pattern"]) if "pattern" in d else None,
                deny_patterns=[re.compile(p) for p in d.get("deny_patterns", [])],
                allowed_values=d.get("allowed_values"),
                allowed_prefixes=d.get("allowed_prefixes"),
                max_length=d.get("max_length"),
                required=bool(d.get("required", False)),
            )
        except re.error as e:
            raise PolicyError(f"arg {name!r}: bad regex: {e}") from e


@dataclass
class RateLimit:
    calls: int
    per_seconds: float


@dataclass
class ToolRule:
    action: Action = "allow"
    args: dict[str, ArgRule] = field(default_factory=dict)
    allow_extra_args: bool = False
    egress: bool = False  # can send data outside the trust boundary
    private_data: bool = False  # returns private/regulated data
    untrusted_output: bool = False  # returns attacker-controllable content
    redact_output: bool | None = None
    scan_args_for: list[str] | None = None
    rate_limit: RateLimit | None = None


@dataclass
class Policy:
    default_action: Action = "deny"
    tools: dict[str, ToolRule] = field(default_factory=dict)
    redact_kinds: list[str] = field(default_factory=lambda: [
        "email", "ssn", "phone", "credit_card", "aws_key", "github_token", "private_key", "jwt",
        "openai_key"])
    redact_by_default: bool = True
    egress_arg_scan: list[str] = field(default_factory=lambda: [
        "ssn", "credit_card", "aws_key", "github_token", "private_key", "jwt", "openai_key"])
    injection_action: Literal["block", "flag", "off"] = "block"
    injection_threshold: float = 0.6
    injection_detector: Literal["rules", "model", "ensemble"] = "rules"
    trifecta_action: Literal["block", "require_approval", "off"] = "require_approval"
    pin_tools: bool = True
    on_tool_change: Literal["block", "warn"] = "block"
    scan_descriptions: bool = True
    lockfile: str | None = None
    audit_path: str | None = None
    audit_hmac_env: str | None = None
    approvals_path: str | None = None
    approval_ttl_s: float = 600.0
    max_output_chars: int = 100_000

    def rule_for(self, tool: str) -> ToolRule:
        return self.tools.get(tool, ToolRule(action=self.default_action))

    @classmethod
    def from_dict(cls, d: dict[str, Any], base_dir: Path | None = None) -> Policy:
        if not isinstance(d, dict):
            raise PolicyError("policy must be a mapping")
        p = cls()
        p.default_action = _action(d.get("default", "deny"), "default")
        for name, td in (d.get("tools") or {}).items():
            td = td or {}
            rl = td.get("rate_limit")
            p.tools[name] = ToolRule(
                action=_action(td.get("action", "allow"), name),
                args={a: ArgRule.parse(a, ad or {}) for a, ad in (td.get("args") or {}).items()},
                allow_extra_args=bool(td.get("allow_extra_args", False)),
                egress=bool(td.get("egress", False)),
                private_data=bool(td.get("private_data", False)),
                untrusted_output=bool(td.get("untrusted_output", False)),
                redact_output=td.get("redact_output"),
                scan_args_for=td.get("scan_args_for"),
                rate_limit=RateLimit(int(rl["calls"]), float(rl["per_seconds"])) if rl else None,
            )
        out = d.get("output") or {}
        p.redact_kinds = out.get("redact", p.redact_kinds)
        p.redact_by_default = bool(out.get("redact_by_default", True))
        p.max_output_chars = int(out.get("max_chars", p.max_output_chars))
        inj = out.get("injection") or {}
        p.injection_action = inj.get("action", p.injection_action)
        p.injection_threshold = float(inj.get("threshold", p.injection_threshold))
        p.injection_detector = inj.get("detector", p.injection_detector)
        flow = d.get("flow") or {}
        p.trifecta_action = flow.get("lethal_trifecta", p.trifecta_action)
        p.egress_arg_scan = flow.get("egress_arg_scan", p.egress_arg_scan)
        td_ = d.get("tool_definitions") or {}
        p.pin_tools = bool(td_.get("pin", True))
        p.on_tool_change = td_.get("on_change", "block")
        p.scan_descriptions = bool(td_.get("scan_descriptions", True))
        p.lockfile = _path(td_.get("lockfile"), base_dir)
        au = d.get("audit") or {}
        p.audit_path = _path(au.get("path"), base_dir)
        p.audit_hmac_env = au.get("hmac_key_env")
        ap = d.get("approvals") or {}
        p.approvals_path = _path(ap.get("path"), base_dir)
        p.approval_ttl_s = float(ap.get("ttl_seconds", p.approval_ttl_s))
        for key, val, ok in [
            ("output.injection.action", p.injection_action, {"block", "flag", "off"}),
            ("output.injection.detector", p.injection_detector, {"rules", "model", "ensemble"}),
            ("flow.lethal_trifecta", p.trifecta_action, {"block", "require_approval", "off"}),
            ("tool_definitions.on_change", p.on_tool_change, {"block", "warn"}),
        ]:
            if val not in ok:
                raise PolicyError(f"{key} must be one of {sorted(ok)}, got {val!r}")
        return p

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        path = Path(path)
        return cls.from_dict(yaml.safe_load(path.read_text()), base_dir=path.parent)


def _action(v: Any, where: str) -> Action:
    if v not in _ACTIONS:
        raise PolicyError(f"{where}: action must be one of {sorted(_ACTIONS)}, got {v!r}")
    return v  # type: ignore[no-any-return]


def _path(v: str | None, base: Path | None) -> str | None:
    if not v:
        return None
    pth = Path(v).expanduser()
    return str(pth if pth.is_absolute() or base is None else base / pth)
