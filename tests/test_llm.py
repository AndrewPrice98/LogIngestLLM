"""LLM plumbing against fake local Ollama / OpenAI-compatible servers."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from logagent import llm

REPLY = {"headline": "SD card failing on pi", "summary": "s", "findings": [
    {"keys": ["k1"], "title": "SD card", "importance": "critical", "host": "pi", "what": "w", "why": "y", "action": "a"}],
    "dismissed": []}


@pytest.fixture
def fake_server():
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            seen["path"], seen["body"] = self.path, body
            content = "<think>hmm</think>```json\n" + json.dumps(REPLY) + "\n```"
            if self.path == "/api/chat":
                out = {"message": {"content": content}, "prompt_eval_count": 10, "eval_count": 5}
            else:
                out = {"choices": [{"message": {"content": content}}], "usage": {}}
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", seen
    srv.shutdown()


FINDING = {"key": "k1", "host": "pi", "source": "syslog", "program": "kernel", "event_id": "", "severity": "err",
           "count": 3, "first": "x", "last": "y", "novel": True, "score": 90, "samples": ["I/O error"],
           "rule": {"title": "Storage I/O errors", "why": "w"}, "fields": {}}


@pytest.mark.parametrize("provider,path,base_suffix", [("ollama", "/api/chat", ""),
                                                        ("openai", "/v1/chat/completions", "/v1")])
def test_providers(fake_server, provider, path, base_suffix):
    url, seen = fake_server
    out = llm.analyze([FINDING], {"events": 3}, {"provider": provider, "base_url": url + base_suffix, "model": "m"})
    assert seen["path"] == path
    assert out["headline"] == "SD card failing on pi"
    assert "I/O error" in seen["body"]["messages"][1]["content"]


def test_ask_requires_provider():
    with pytest.raises(llm.LLMError):
        llm.ask({"findings": []}, "q", {"provider": "none"})
