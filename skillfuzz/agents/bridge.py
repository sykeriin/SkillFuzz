"""Host-side model bridge.

The sandbox has no network, so the in-sandbox agent cannot call an LLM API. It sends requests over a unix socket
(a filesystem path, which is not scoped to the network namespace) to this bridge, which runs on the host, holds the
API key, and enforces a call budget. The key never enters the sandbox.

Caveat: code inside the sandbox (including the skill under test) can also reach the socket and spend tokens. The
per-run call cap bounds that; it cannot leak the key.
"""
from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path
from typing import Callable

ModelFn = Callable[[dict], dict]


def anthropic_complete(model: str = "claude-haiku-5-5", max_tokens: int = 1500) -> ModelFn:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set (the offline agent needs no key: --agent offline)")
    try:
        import anthropic
    except ImportError as e:
        raise RuntimeError("pip install 'skillfuzz[llm]' to use the anthropic agent") from e
    client = anthropic.Anthropic()

    def complete(req: dict) -> dict:
        r = client.messages.create(model=model, max_tokens=max_tokens, system=req["system"], tools=req["tools"],
                                   messages=req["messages"])
        blocks = []
        for b in r.content:
            if b.type == "text":
                blocks.append({"type": "text", "text": b.text})
            elif b.type == "tool_use":
                blocks.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
        return {"content": blocks, "stop_reason": r.stop_reason,
                "usage": {"input": r.usage.input_tokens, "output": r.usage.output_tokens}}
    return complete


class ModelBridge:
    def __init__(self, complete: ModelFn, sock_path: str | Path, max_calls: int = 30):
        self.complete, self.path, self.max_calls = complete, str(sock_path), max_calls
        self.calls = 0
        self.usage = {"input": 0, "output": 0, "calls": 0}
        self._srv: socket.socket | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        if os.path.exists(self.path):
            os.unlink(self.path)
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.path)
        os.chmod(self.path, 0o666)
        self._srv.listen(8)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while self._srv is not None:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(1 << 20)
                if not chunk:
                    return
                buf += chunk
            with self._lock:
                self.calls += 1
                over = self.calls > self.max_calls
            if over:
                resp = {"error": "call budget exhausted"}
            else:
                try:
                    resp = self.complete(json.loads(buf))
                    with self._lock:
                        self.usage["calls"] += 1
                        self.usage["input"] += resp.get("usage", {}).get("input", 0)
                        self.usage["output"] += resp.get("usage", {}).get("output", 0)
                except Exception as e:
                    resp = {"error": repr(e)[:300]}
            conn.sendall(json.dumps(resp).encode() + b"\n")
        finally:
            conn.close()

    def stop(self) -> None:
        srv, self._srv = self._srv, None
        if srv:
            srv.close()
        if os.path.exists(self.path):
            os.unlink(self.path)
