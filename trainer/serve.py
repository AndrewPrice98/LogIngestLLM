"""Serve your trained model as an OpenAI-compatible endpoint the dashboard can use.

    .venv-train\\Scripts\\python trainer\\serve.py            # latest adapter on http://127.0.0.1:8081/v1

then in logagent.toml:
    [llm]
    provider = "openai"
    base_url = "http://127.0.0.1:8081/v1"
    model = "logagent"
    mode = "triage"
    summary_model = "logagent-base"   # whole-log summaries use the base model with your adapter switched off

Model ids: "logagent" (base + your adapter) and "logagent-base" (same weights, adapter disabled for the request).
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import threading

os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")  # less fragmentation on 8 GB GPUs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import torch

from common import latest_adapter, load, generate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", help="default: latest in models/")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--max-input-tokens", type=int, default=12000, help="refuse longer prompts instead of running out of VRAM")
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
                return self._send(200, {"data": [{"id": "logagent", "object": "model"},
                                                 {"id": "logagent-base", "object": "model"}]})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self.path.rstrip("/").endswith("/chat/completions"):
                return self._send(404, {"error": "not found"})
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
            msgs = [{"role": m["role"], "content": m["content"]} for m in body.get("messages", [])]
            name = "logagent-base" if body.get("model") == "logagent-base" else "logagent"
            no_adapter = model.disable_adapter() if name == "logagent-base" and hasattr(model, "disable_adapter") \
                else contextlib.nullcontext()
            ids = tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=True)
            n_in = len(ids["input_ids"] if hasattr(ids, "keys") else ids)
            if n_in > args.max_input_tokens:
                return self._send(413, {"error": {"message": f"prompt is {n_in} tokens; this server accepts up to "
                                                              f"{args.max_input_tokens} (--max-input-tokens)"}})
            try:
                with lock, no_adapter:
                    text = generate(tok, model, msgs, max_new_tokens=min(int(body.get("max_tokens") or 600), 2000),
                                    temperature=float(body.get("temperature") or 0))
            except torch.OutOfMemoryError:
                torch.cuda.empty_cache()
                return self._send(507, {"error": {"message": f"GPU ran out of memory on a {n_in}-token prompt; "
                                                             "ask about a smaller scan or lower --max-input-tokens"}})
            self._send(200, {"object": "chat.completion", "model": name,
                             "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                          "finish_reason": "stop"}], "usage": {}})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
