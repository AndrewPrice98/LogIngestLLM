"""The built-in engine, with a stand-in llama-server (a tiny Python HTTP server) so no model is needed."""
import hashlib
import json
import os
import stat
import sys

import pytest

from logagent import bundled, llm

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the stand-in server is a shebang script")

FAKE = r'''#!{python}
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
args = sys.argv[1:]
if "{fail}" == "yes":
    sys.exit(3)
port = int(args[args.index("--port") + 1])
state = {{"scale": None, "lora": "--lora" in args, "model": args[args.index("-m") + 1]}}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj):
        b = json.dumps(obj).encode(); self.send_response(200)
        self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send({{"status": "ok"}})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if self.path == "/lora-adapters":
            state["scale"] = body[0]["scale"]; return self._send({{"ok": True}})
        reply = {{"scale": state["scale"], "model": state["model"].rsplit("/", 1)[-1], "json": "response_format" in body,
                 "build": "{build}"}}
        self._send({{"choices": [{{"message": {{"content": json.dumps(reply)}}}}]}})
HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


def _install(root, build, fail=False):
    d = root / "engine" / build
    d.mkdir(parents=True)
    p = d / "llama-server"
    p.write_text(FAKE.format(python=sys.executable, fail="yes" if fail else "no", build=build))
    p.chmod(p.stat().st_mode | stat.S_IXUSR)


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(bundled, "app_dir", lambda: tmp_path)
    monkeypatch.setattr(bundled, "user_dir", lambda: tmp_path)
    eng = bundled.Engine()
    monkeypatch.setattr(bundled, "ENGINE", eng)
    yield tmp_path
    eng.stop()


def _model(root, split=False, good_sum=True):
    m = root / "model"
    m.mkdir()
    data = os.urandom(3000)
    if split:
        (m / "logingestllm-base-Q4_K_M.gguf.part1").write_bytes(data[:1000])
        (m / "logingestllm-base-Q4_K_M.gguf.part2").write_bytes(data[1000:])
        h = hashlib.sha256(data if good_sum else b"x").hexdigest()
        (m / "SHA256SUMS").write_text(f"{h}  logingestllm-base-Q4_K_M.gguf\n")
    else:
        (m / "logingestllm-base-Q4_K_M.gguf").write_bytes(data)
    (m / "logingestllm-triage.lora.gguf").write_bytes(b"lora")
    return data


def test_adapter_switches_per_request(app):
    _install(app, "gpu")
    _model(app)
    assert bundled.available()
    cfg = dict(bundled.DEFAULT_LLM)
    triage = json.loads(llm.chat("s", "u", cfg, json_mode=True)[0])
    summary = json.loads(llm.chat("s", "u", {**cfg, "model": cfg["summary_model"]})[0])
    assert triage == {"scale": 1.0, "model": "logingestllm-base-Q4_K_M.gguf", "json": True, "build": "gpu"}
    assert summary["scale"] == 0.0 and summary["json"] is False
    assert bundled.ENGINE.status()["state"] == "online"


def test_split_model_is_joined_and_verified(app):
    _install(app, "gpu")
    data = _model(app, split=True)
    bundled.ENGINE.start(progress=lambda m: None)
    joined = app / "model" / "logingestllm-base-Q4_K_M.gguf"
    assert joined.read_bytes() == data and not list((app / "model").glob("*.part*"))


def test_corrupt_part_is_refused(app):
    _install(app, "gpu")
    _model(app, split=True, good_sum=False)
    with pytest.raises(RuntimeError, match="checksum"):
        bundled.ENGINE.start(progress=lambda m: None)
    assert list((app / "model").glob("*.part*"))  # parts kept so the user can re-download one


def test_falls_back_to_cpu_build(app):
    _install(app, "gpu", fail=True)
    _install(app, "cpu")
    _model(app)
    out = json.loads(llm.chat("s", "u", dict(bundled.DEFAULT_LLM))[0])
    assert out["build"] == "cpu"


def test_no_engine_means_rules_only(app):
    assert not bundled.available()
    with pytest.raises(llm.LLMError):
        llm.chat("s", "u", dict(bundled.DEFAULT_LLM))


@pytest.mark.parametrize("listing, want", [
    ("  Vulkan0: AMD Radeon 780M Graphics (RADV PHOENIX) (8142 MiB, 6646 MiB free)\n"
     "  Vulkan1: NVIDIA GeForce RTX 4060 Laptop GPU (8188 MiB, 4799 MiB free)", "Vulkan1"),
    ("  Vulkan0: Intel(R) Iris(R) Xe Graphics (4000 MiB, 3000 MiB free)\n  Vulkan1: AMD Radeon RX 7600 (8192 MiB, 8000 MiB free)", "Vulkan1"),
    ("  Metal: Apple M2 (16000 MiB, 12000 MiB free)", None),
    ("", None),
])
def test_prefers_discrete_gpu(listing, want):
    assert bundled.pick_device(listing) == want
