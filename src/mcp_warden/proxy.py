"""stdio MCP proxy: sits between an MCP client (host) and an upstream MCP server process.

Works at the JSON-RPC layer, so it is independent of SDK and protocol revision: it only
intercepts ``tools/list`` responses (scan + pin), ``tools/call`` requests (policy) and
``tools/call`` responses (redaction, injection scanning, taint tracking). All other
traffic is forwarded byte-for-byte.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from .engine import Warden

META_KEY = "io.github.sushmit-gujar/mcp-warden"


def blocked_result(tool: str, verdict: str, reasons: list[str], modern: bool = False
                   ) -> dict[str, Any]:
    """A model-readable tool error (not a JSON-RPC error), so the agent can recover."""
    head = "needs human approval" if verdict == "require_approval" else "was blocked by policy"
    text = f"[mcp-warden] Call to '{tool}' {head}: " + "; ".join(reasons)
    out: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": True,
                           "_meta": {META_KEY: {"verdict": verdict, "reasons": reasons}}}
    if modern:  # 2026-07-28+ results carry an explicit resultType
        out["resultType"] = "complete"
    return out


def _is_modern(msg: dict[str, Any]) -> bool:
    meta = (msg.get("params") or {}).get("_meta") or {}
    return "io.modelcontextprotocol/protocolVersion" in meta


class JsonRpcInterceptor:
    """Pure message transformer (no I/O), so it is easy to unit-test."""

    def __init__(self, warden: Warden) -> None:
        self.warden = warden
        self.pending: dict[Any, tuple[str, str | None, dict[str, Any]]] = {}

    def from_client(self, msg: dict[str, Any]) -> tuple[dict[str, Any] | None,
                                                         dict[str, Any] | None]:
        """Return (message_to_upstream, immediate_reply_to_client). Fails closed."""
        try:
            return self._from_client(msg)
        except Exception as e:  # noqa: BLE001 - a guard must never fail open
            if msg.get("method") == "tools/call" and msg.get("id") is not None:
                tool = str((msg.get("params") or {}).get("name"))
                return None, {"jsonrpc": "2.0", "id": msg["id"], "result": blocked_result(
                    tool, "deny", [f"warden internal error, failing closed: {e!r}"],
                    _is_modern(msg))}
            return msg, None

    def _from_client(self, msg: dict[str, Any]) -> tuple[dict[str, Any] | None,
                                                          dict[str, Any] | None]:
        method, mid = msg.get("method"), msg.get("id")
        if method == "tools/call" and mid is not None:
            params = msg.get("params") or {}
            tool = str(params.get("name"))
            d = self.warden.check_call(tool, params.get("arguments") or {})
            if not d.allowed:
                reply = {"jsonrpc": "2.0", "id": mid,
                         "result": blocked_result(tool, d.verdict, d.reasons, _is_modern(msg))}
                return None, reply
            self.pending[mid] = ("tools/call", tool, params.get("arguments") or {})
        elif method == "tools/list" and mid is not None:
            self.pending[mid] = ("tools/list", None, {})
        return msg, None

    def from_upstream(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Transform an upstream message. Fails closed on tool results."""
        try:
            return self._from_upstream(msg)
        except Exception as e:  # noqa: BLE001
            raw = msg.get("result")
            res: dict[str, Any] = raw if isinstance(raw, dict) else {}
            return {"jsonrpc": "2.0", "id": msg.get("id"), "result": blocked_result(
                "?", "deny", [f"warden internal error, output withheld: {e!r}"],
                "resultType" in res)}

    def _from_upstream(self, msg: dict[str, Any]) -> dict[str, Any]:
        mid = msg.get("id")
        if "method" in msg:
            return msg  # server-initiated request/notification
        if mid not in self.pending or "result" not in msg:
            self.pending.pop(mid, None)
            return msg
        kind, tool, call_args = self.pending.pop(mid)
        result = msg["result"]
        if kind == "tools/list" and isinstance(result.get("tools"), list):
            result = {**result, "tools": self.warden.on_tools_list(result["tools"])}
        elif kind == "tools/call" and tool is not None:
            chk = self.warden.check_result(tool, result, call_args)
            if chk.blocked:
                # keep protocol envelope keys (resultType, _meta...), replace the payload
                keep = {k: v for k, v in result.items() if k not in ("content",
                                                                     "structuredContent")}
                result = {**keep, **chk.result}
            else:
                result = chk.result
        return {**msg, "result": result}


def _parse(line: bytes) -> Any:
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


async def run_proxy(warden: Warden, command: list[str]) -> int:
    proc = await asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        limit=2**24)
    assert proc.stdin is not None and proc.stdout is not None
    up_in, up_out = proc.stdin, proc.stdout
    ix = JsonRpcInterceptor(warden)
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=2**24)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    out = sys.stdout.buffer
    lock = asyncio.Lock()

    async def to_client(obj: Any) -> None:
        async with lock:
            out.write(json.dumps(obj, ensure_ascii=False).encode() + b"\n")
            out.flush()

    async def client_to_upstream() -> None:
        while line := await reader.readline():
            obj = _parse(line)
            if obj is None:
                up_in.write(line)
                await up_in.drain()
                continue
            msgs = obj if isinstance(obj, list) else [obj]
            fwd, replies = [], []
            for m in msgs:
                f, r = ix.from_client(m) if isinstance(m, dict) else (m, None)
                if f is not None:
                    fwd.append(f)
                if r is not None:
                    replies.append(r)
            for r in replies:
                await to_client(r)
            if fwd:
                payload = fwd if isinstance(obj, list) else fwd[0]
                up_in.write(json.dumps(payload, ensure_ascii=False).encode() + b"\n")
                await up_in.drain()
        up_in.close()

    async def upstream_to_client() -> None:
        while line := await up_out.readline():
            obj = _parse(line)
            if obj is None:
                async with lock:
                    out.write(line)
                    out.flush()
                continue
            if isinstance(obj, list):
                await to_client([ix.from_upstream(m) if isinstance(m, dict) else m for m in obj])
            else:
                await to_client(ix.from_upstream(obj) if isinstance(obj, dict) else obj)

    t_up = asyncio.create_task(upstream_to_client())
    t_in = asyncio.create_task(client_to_upstream())
    done, _ = await asyncio.wait({t_up, t_in}, return_when=asyncio.FIRST_COMPLETED)
    if t_in in done:
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.terminate()
    else:
        t_in.cancel()
    await t_up if not t_up.done() else None
    return proc.returncode or 0
