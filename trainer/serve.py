"""Serve your trained model as an OpenAI-compatible endpoint the dashboard can use.

    .venv-train\\Scripts\\python trainer\\serve.py            # latest adapter on http://127.0.0.1:8081/v1

then in logagent.toml:
    [llm]
    provider = "openai"
    base_url = "http://127.0.0.1:8081/v1"
    model = "logagent"
    mode = "triage"
"""
from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common import latest_adapter, load, generate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", help="default: latest in models/")
    ap.add_argument("--port", type=int, default=8081)
    args = ap.parse_args()
    adapter = args.adapter or latest_adapter()
    tok, model = load(adapter)
    lock = threading.Lock()  # one GPU, one generation at a time
    print(f"serving {adapter or 'base model'} on http://127.0.0.1:{args.port}/v1")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.rstrip("/").endswith("/models"):
                return self._send(200, {"data": [{"id": "logagent", "object": "model"}]})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self.path.rstrip("/").endswith("/chat/completions"):
                return self._send(404, {"error": "not found"})
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
            msgs = [{"role": m["role"], "content": m["content"]} for m in body.get("messages", [])]
            with lock:
                text = generate(tok, model, msgs, max_new_tokens=min(int(body.get("max_tokens") or 600), 2000),
                                temperature=float(body.get("temperature") or 0))
            self._send(200, {"object": "chat.completion", "model": "logagent",
                             "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                          "finish_reason": "stop"}], "usage": {}})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
