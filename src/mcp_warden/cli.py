"""mcp-warden CLI.

  mcp-warden run --policy policy.yaml -- python my_server.py     # wrap an MCP server
  mcp-warden verify audit.jsonl                                 # check the hash chain
  mcp-warden approve send_email <args_sha256> --policy policy.yaml
  mcp-warden check --policy policy.yaml                          # validate a policy
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid

from .approvals import ApprovalStore
from .audit import AuditLog, verify
from .engine import Warden
from .policy import Policy, PolicyError


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-warden", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="proxy an upstream stdio MCP server")
    r.add_argument("--policy", required=True)
    r.add_argument("--server-name", default=None)
    r.add_argument("upstream", nargs=argparse.REMAINDER)
    v = sub.add_parser("verify", help="verify an audit log hash chain")
    v.add_argument("path")
    v.add_argument("--key-env", default="WARDEN_AUDIT_KEY")
    a = sub.add_parser("approve", help="grant a single-use approval for an exact call")
    a.add_argument("tool")
    a.add_argument("args_sha256")
    a.add_argument("--policy", required=True)
    a.add_argument("--approver", default=os.environ.get("USER", "human"))
    c = sub.add_parser("check", help="validate a policy file")
    c.add_argument("--policy", required=True)
    ns = ap.parse_args(argv)

    if ns.cmd == "verify":
        key = os.environ.get(ns.key_env, "")
        res = verify(ns.path, key.encode() if key else None)
        if res.ok:
            print(f"OK: {res.entries} entries, chain intact")
            return 0
        print(f"TAMPERED at line {res.line}: {res.error} ({res.entries} valid entries before)")
        return 1
    try:
        policy = Policy.load(ns.policy)
    except (PolicyError, OSError) as e:
        print(f"invalid policy: {e}", file=sys.stderr)
        return 2
    if ns.cmd == "check":
        print(f"policy OK: default={policy.default_action}, {len(policy.tools)} tool rules")
        return 0
    if ns.cmd == "approve":
        ApprovalStore(policy.approvals_path, policy.approval_ttl_s).grant(
            ns.tool, ns.args_sha256, ns.approver)
        print(f"approved {ns.tool} {ns.args_sha256[:12]}… (single use)")
        return 0
    cmd = ns.upstream[1:] if ns.upstream[:1] == ["--"] else ns.upstream
    if not cmd:
        ap.error("missing upstream command after --")
    name = ns.server_name or os.path.basename(cmd[-1])
    warden = Warden(policy, server=name, session=uuid.uuid4().hex[:12],
                    audit=AuditLog.from_env(policy.audit_path, policy.audit_hmac_env))
    from .proxy import run_proxy

    return asyncio.run(run_proxy(warden, cmd))


if __name__ == "__main__":
    sys.exit(main())
