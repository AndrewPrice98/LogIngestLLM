"""The AI that ships inside the app: llama.cpp's server + your model, started and stopped by LogIngestLLM itself.

Layout next to the app (or in a source checkout):

    engine/gpu/llama-server[.exe]   Vulkan (Windows/Linux) or Metal (macOS) build, tried first
    engine/cpu/llama-server[.exe]   plain CPU build, used if the GPU build can't start
    model/logingestllm-base-<Q>.gguf          the base model (shipped split as .part1, .part2 ...; joined on first run)
    model/logingestllm-triage.lora.gguf      your trained triage adapter

The server listens on 127.0.0.1 only, on a free port, and nothing is downloaded: the tool works with the network
unplugged. One base model serves both jobs: the triage adapter is loaded but switched on per request only for
triage ("logagent"), and off for summaries, explanations and questions ("logagent-base"), like trainer/serve.py.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from .paths import app_dir, user_dir

DEFAULT_LLM = {"provider": "bundled", "model": "logagent", "summary_model": "logagent-base", "mode": "triage",
               "timeout": 900, "triage_limit": 20}
CTX = int(os.environ.get("LOGINGESTLLM_CTX", "8192"))  # 8k tokens keeps the KV cache ~1.2 GB on small machines
EXE = ".exe" if sys.platform == "win32" else ""


def _engine_dir() -> Path:
    return app_dir() / "engine"


def _model_dir() -> Path:
    return app_dir() / "model"


def binaries() -> list[Path]:
    d = _engine_dir()
    order = [d / "gpu", d, d / "cpu"]
    out = []
    for base in order:
        if base.is_dir():
            out += sorted(base.rglob(f"llama-server{EXE}"), key=lambda p: len(p.parts))[:1]
    return out


def _base_candidates() -> list[Path]:
    d = _model_dir()
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("*.gguf") if "lora" not in p.name.lower())


def _parts() -> dict[str, list[Path]]:
    groups: dict[str, list[Path]] = {}
    for p in _model_dir().glob("*.gguf.part*") if _model_dir().is_dir() else []:
        groups.setdefault(p.name.split(".gguf.part")[0] + ".gguf", []).append(p)
    return {k: sorted(v, key=lambda p: int(p.name.rsplit("part", 1)[1] or 0)) for k, v in groups.items()}


def available() -> bool:
    return bool(binaries()) and bool(_base_candidates() or _parts())


def _join_parts(progress=print) -> None:
    """model.gguf.part1 + .part2 ... -> model.gguf (GitHub limits release files to 2 GB). Verified when a
    model/SHA256SUMS file is present."""
    sums = {}
    f = _model_dir() / "SHA256SUMS"
    if f.exists():
        for line in f.read_text().splitlines():
            if line.strip():
                h, name = line.split(None, 1)
                sums[name.strip().lstrip("*")] = h
    for name, parts in _parts().items():
        target = _model_dir() / name
        if target.exists():
            continue
        progress(f"[model] assembling {name} from {len(parts)} parts (first run only) ...")
        tmp = target.with_suffix(".gguf.tmp")
        h = hashlib.sha256()
        with open(tmp, "wb") as out:
            for p in parts:
                with open(p, "rb") as src:
                    while chunk := src.read(8 << 20):
                        out.write(chunk)
                        h.update(chunk)
        if name in sums and sums[name] != h.hexdigest():
            tmp.unlink()
            raise RuntimeError(f"{name}: checksum mismatch, a part is incomplete or corrupt; download it again")
        tmp.replace(target)
        for p in parts:
            p.unlink()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post(url: str, body, timeout: float) -> dict:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


class Engine:
    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.port = 0
        self.lock = threading.Lock()
        self.state, self.detail = "stopped", ""
        self.has_lora = False
        self.scale: float | None = None
        self.binary: Path | None = None

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def status(self) -> dict:
        if not available():
            return {"state": "offline", "detail": "bundled model or engine not found next to the app"}
        if self.proc and self.proc.poll() is not None:
            self.state, self.detail = "offline", f"engine exited (code {self.proc.returncode}); see {user_dir() / 'engine.log'}"
        return {"state": {"running": "online"}.get(self.state, self.state), "detail": self.detail}

    def start(self, progress=print) -> None:
        with self.lock:
            if self.proc and self.proc.poll() is None and self.state == "running":
                return
            self.state, self.detail = "starting", "loading the model"
            try:
                _join_parts(progress)
            except (OSError, RuntimeError) as exc:
                self.state, self.detail = "offline", str(exc)
                raise RuntimeError(str(exc)) from exc
            base = _base_candidates()
            lora = sorted(p for p in _model_dir().glob("*.gguf") if "lora" in p.name.lower())
            if not base:
                self.state, self.detail = "offline", "no model file in model/"
                raise RuntimeError(self.detail)
            log = open(user_dir() / "engine.log", "ab")
            last = ""
            for binary in binaries():
                self.port = _free_port()
                args = [str(binary), "-m", str(base[0]), "--host", "127.0.0.1", "--port", str(self.port), "-c", str(CTX),
                        "-np", "1", "-ngl", "999", "--jinja"]
                if lora:
                    args += ["--lora", str(lora[0]), "--lora-init-without-apply"]
                flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                log.write(f"\n=== {time.ctime()} {' '.join(args)}\n".encode())
                log.flush()
                self.proc = subprocess.Popen(args, stdout=log, stderr=log, stdin=subprocess.DEVNULL, creationflags=flags,
                                             cwd=str(binary.parent))
                deadline = time.time() + 600
                while time.time() < deadline and self.proc.poll() is None:
                    try:
                        with urllib.request.urlopen(self.url("/health"), timeout=2) as r:
                            if r.status == 200:
                                break
                    except (urllib.error.URLError, OSError):
                        pass
                    time.sleep(0.5)
                if self.proc.poll() is None:
                    self.binary, self.has_lora, self.scale = binary, bool(lora), None
                    self.state = "running"
                    self.detail = f"{binary.parent.name} engine · {base[0].name}" + (" + triage adapter" if lora else "")
                    progress(f"[model] ready ({self.detail})")
                    return
                last = f"{binary} exited with code {self.proc.returncode}"
                progress(f"[model] {last}; trying the next engine build")
            self.state, self.detail = "offline", f"{last or 'no engine could start'}; see {user_dir() / 'engine.log'}"
            raise RuntimeError(self.detail)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.state = "stopped"

    def chat(self, system: str, user: str, adapter: bool, max_tokens: int, temperature: float, json_mode: bool,
             timeout: float) -> str:
        if self.state != "running" or not self.proc or self.proc.poll() is not None:
            self.start()
        with self.lock:  # one generation at a time, with the right adapter setting
            want = 1.0 if adapter and self.has_lora else 0.0
            if self.has_lora and self.scale != want:
                _post(self.url("/lora-adapters"), [{"id": 0, "scale": want}], 30)
                self.scale = want
            body = {"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    "max_tokens": max_tokens, "temperature": temperature}
            if json_mode:
                body["response_format"] = {"type": "json_object"}
            resp = _post(self.url("/v1/chat/completions"), body, timeout)
        return resp["choices"][0]["message"]["content"]


ENGINE = Engine()
atexit.register(ENGINE.stop)
