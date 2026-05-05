#!/usr/bin/env python3
"""
Minimal Ollama-compatible POST /api/chat for e2e.
Reads strategist-shaped JSON lines (without \"target\"); injects target parsed from request body.
"""
from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("MOCK_OLLAMA_PORT", "11434"))
DEC_PATH = os.environ.get("MOCK_DECISIONS", "/app/mock_decisions.jsonl")


def _load_templates() -> list[dict]:
    with open(DEC_PATH, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


TEMPLATES = _load_templates()


def _extract_target(body: str) -> str:
    m = re.search(r'"target"\s*:\s*"((?:[^"\\]|\\.)*)"', body)
    if m:
        return m.group(1).replace("\\\"", '"')
    return os.environ.get("E2E_FALLBACK_TARGET", "172.30.0.0/24")


class Handler(BaseHTTPRequestHandler):
    _idx = 0

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/api/chat":
            self.send_error(404)
            return
        ln = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(ln).decode("utf-8", errors="replace")
        tgt = _extract_target(body)
        tpl = dict(TEMPLATES[Handler._idx % len(TEMPLATES)])
        Handler._idx += 1
        out = {**tpl, "target": tgt}
        payload = {
            "model": "mock",
            "message": {"role": "assistant", "content": json.dumps(out)},
        }
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args: object) -> None:
        print(fmt % args)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
