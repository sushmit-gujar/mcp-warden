from pathlib import Path

import pytest

from mcp_warden.audit import AuditLog
from mcp_warden.engine import Warden
from mcp_warden.policy import Policy

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def policy(tmp_path):
    p = Policy.load(ROOT / "examples" / "policy.yaml")
    p.lockfile = str(tmp_path / "lock.json")
    p.approvals_path = str(tmp_path / "approvals.jsonl")
    p.audit_path = str(tmp_path / "audit.jsonl")
    return p


@pytest.fixture
def warden(policy):
    return Warden(policy, server="demo", audit=AuditLog(policy.audit_path))
