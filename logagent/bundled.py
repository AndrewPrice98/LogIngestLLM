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
import re
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
CTX = int(os.environ.get("LOGINGESTLLM_CTX", "12288"))  # 12k tokens: KV cache ~1.7 GB next to the 2.5 GB model
# prompts must leave room for the answer inside the context window (JSON scan data is ~3 characters per token)
DEFAULT_LLM["prompt_chars"] = max(8000, min(24000, (CTX - 1200 - 800) * 3))
EXE = ".exe" if sys.platform == "win32" else ""


def _engine_dir() -> Path:
    return app_dir() / "engine"


def _model_dir() -> Path:
    return app_dir() / "model"


def binaries() -> list[Path]:
    d = _engine_dir()
    order = [d / "gpu", d, d / "cpu"]
    out: list[Path] = []
    for base in order:
        if base.is_dir():
            hit = sorted(base.rglob(f"llama-server{EXE}"), key=lambda p: len(p.parts))[:1]
            out += [h for h in hit if h not in out]
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


def pick_device(listing: str) -> str | None:
    """From `llama-server --list-devices`: prefer a discrete GPU over integrated graphics (which is often listed
    first and much slower). None = let llama.cpp decide."""
    devs = []
    for line in listing.splitlines():
        m = re.match(r"\s*(\w+\d+):\s*(.+?)\s*\((\d+) MiB,\s*(\d+) MiB free\)", line)
        if m:
            devs.append((m.group(1), m.group(2), int(m.group(3))))
    if len(devs) < 2:
        return None

    def rank(d):
        name = d[1].lower()
        discrete = ("nvidia" in name or " rx " in f" {name} " or "radeon pro" in name or "arc" in name.split()
                    or "geforce" in name or "quadro" in name)
        integrated = "graphics" in name or "uhd" in name or "iris" in name
        return (discrete, not integrated, d[2])
    return max(devs, key=rank)[0]


def _die_with_parent() -> None:
    """Linux: the kernel stops the engine if LogIngestLLM itself dies, even from kill -9 (no orphaned GPU use)."""
    try:
        import ctypes
        import signal
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
    except (OSError, AttributeError):
        pass


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
                try:
                    lst = subprocess.run([str(binary), "--list-devices"], capture_output=True, timeout=60,
                                         creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
                    dev = pick_device(lst.stdout.decode(errors="replace") + lst.stderr.decode(errors="replace"))
                    if dev:
                        args += ["--device", dev]
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if lora:
                    args += ["--lora", str(lora[0]), "--lora-init-without-apply"]
                flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                log.write(f"\n=== {time.ctime()} {' '.join(args)}\n".encode())
                log.flush()
                self.proc = subprocess.Popen(args, stdout=log, stderr=log, stdin=subprocess.DEVNULL, creationflags=flags,
                                             cwd=str(binary.parent),
                                             preexec_fn=_die_with_parent if sys.platform.startswith("linux") else None)
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


def _exit_on_signal(*_):
    raise SystemExit(0)  # runs atexit, which stops the engine (closing the window sends SIGHUP; kill sends SIGTERM)


try:
    import signal as _signal
    if threading.current_thread() is threading.main_thread():
        for _sig in ("SIGTERM", "SIGHUP"):
            if hasattr(_signal, _sig):
                _signal.signal(getattr(_signal, _sig), _exit_on_signal)
except (ValueError, OSError):
    pass
