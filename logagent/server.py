"""Local web dashboard. Stdlib only. Binds to 127.0.0.1 by default."""
from __future__ import annotations

import ctypes
import json
import os
import threading
import time
import traceback
import urllib.request
import webbrowser
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from . import __version__, engine, feedback, llm, locations
from .collectors.sources import parse_window

STATIC = Path(__file__).parent / "static"


class Job:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.log: list[str] = []
        self.scan_id: str | None = None
        self.error: str | None = None

    def snapshot(self) -> dict:
        with self.lock:
            return {"running": self.running, "log": self.log[-200:], "scan_id": self.scan_id, "error": self.error}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return hasattr(os, "geteuid") and os.geteuid() == 0


_model_cache: dict = {"t": 0.0, "v": None}


def model_status(llm_cfg: dict) -> dict:
    """Is the configured model reachable? Cached for 10 s."""
    prov = (llm_cfg.get("provider") or "none").lower()
    if prov in ("none", "anthropic"):
        return {"state": "off" if prov == "none" else "remote", "detail": prov}
    if time.time() - _model_cache["t"] < 10 and _model_cache["v"]:
        return _model_cache["v"]
    base = (llm_cfg.get("base_url") or ("http://localhost:11434" if prov == "ollama" else "")).rstrip("/")
    url = base + ("/api/tags" if prov == "ollama" else "/models")
    t0 = time.time()
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            r.read(2000)
        v = {"state": "online", "detail": base, "latency_ms": round((time.time() - t0) * 1000)}
    except Exception as exc:  # noqa: BLE001 - any failure means offline
        v = {"state": "offline", "detail": f"{base}: {getattr(exc, 'reason', exc)}"}
    _model_cache.update(t=time.time(), v=v)
    return v


def src_name(s: dict) -> str:
    return s.get("name") or s.get("type")


def make_handler(cfg: dict, job: Job, sched: dict):
    def public_sources():
        return [{"name": src_name(s), "type": s.get("type"), "enabled": s.get("enabled", True),
                 "detail": s.get("host") or s.get("path") or ",".join(s.get("channels", []) or s.get("units", []) or [])}
                for s in cfg.get("sources", [])]

    def start_scan(body: dict):
        """body: sources=[names] of configured sources, or specs=[ad-hoc source specs] (picked files/units)."""
        names = body.get("sources")
        if body.get("specs") is not None:
            srcs = [locations.validate_source(sp) for sp in body["specs"]][:200]
            if not srcs:
                raise ValueError("pick at least one log")
        else:
            srcs = [s for s in cfg.get("sources", [])
                    if (src_name(s) in names if names is not None else s.get("enabled", True))]
        with job.lock:
            if job.running:
                return False
            job.running, job.log, job.scan_id, job.error = True, [], None, None

        def progress(msg):
            with job.lock:
                job.log.append(f"{datetime.now(timezone.utc):%H:%M:%SZ} {msg}")

        def work():
            try:
                scan = engine.run_scan(cfg, srcs, body.get("window"), bool(body.get("use_llm", True)), progress,
                                       summarize=bool(body.get("summarize")), label=str(body.get("label") or "")[:120] or None)
                with job.lock:
                    job.scan_id = scan["id"]
            except Exception as exc:  # surface any failure in the UI instead of dying silently
                traceback.print_exc()
                with job.lock:
                    job.error = f"{type(exc).__name__}: {exc}"
            finally:
                with job.lock:
                    job.running = False

        threading.Thread(target=work, daemon=True).start()
        return True

    class Handler(BaseHTTPRequestHandler):
        server_version = "logagent"

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

        def _send(self, code: int, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(data)))
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            # Block DNS-rebinding: only answer to localhost names.
            host = (self.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
            return host in ("127.0.0.1", "localhost", "::1") or cfg.get("_allow_any_host")

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "bad host"})
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            if path == "/api/config":
                return self._send(200, {"sources": public_sources(), "window": cfg.get("window"),
                                        "llm": {"provider": cfg["llm"].get("provider"),
                                                "model": cfg["llm"].get("model")},
                                        "config_path": cfg.get("_path")})
            if path == "/api/status":
                return self._send(200, {
                    "version": __version__, "model": model_status(cfg["llm"]),
                    "llm": {k: cfg["llm"].get(k) for k in ("provider", "model", "mode", "base_url")},
                    "admin": is_admin(), "schedule": sched, "job_running": job.snapshot()["running"],
                    "config_path": cfg.get("_path"), "data_dir": str(Path(cfg["data_dir"]).resolve())})
            if path == "/api/scans":
                return self._send(200, engine.list_scans(cfg))
            if path.startswith("/api/scans/"):
                scan = engine.load_scan(cfg, path.rsplit("/", 1)[-1])
                return self._send(200, scan) if scan else self._send(404, {"error": "not found"})
            if path.startswith("/api/feedback/"):
                return self._send(200, feedback.for_scan(cfg, path.rsplit("/", 1)[-1]))
            if path == "/api/job":
                return self._send(200, job.snapshot())
            if path == "/api/system":
                return self._send(200, locations.system_info())
            if path == "/api/sources":
                return self._send(200, {"sources": cfg.get("sources", []), "config_path": cfg.get("_path")})
            if path == "/api/discover":
                if cfg.get("_allow_any_host"):
                    return self._send(403, {"error": "file browsing is disabled when the dashboard is network-reachable"})
                return self._send(200, locations.discover(cfg))
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok() or "application/json" not in (self.headers.get("content-type") or ""):
                return self._send(403, {"error": "forbidden"})
            try:
                n = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(min(n, 1_000_000)) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "bad json"})
            path = urlparse(self.path).path
            if path in ("/api/sources", "/api/sources/test", "/api/browse") or (path == "/api/scan" and "specs" in body):
                if cfg.get("_allow_any_host"):
                    return self._send(403, {"error": "editing sources and picking files is disabled when the "
                                                     "dashboard is network-reachable"})
            try:
                if path == "/api/sources":
                    return self._send(200, {"sources": locations.save_sources(cfg, body.get("sources")),
                                            "config_path": cfg.get("_path")})
                if path == "/api/sources/test":
                    return self._send(200, locations.test_source(cfg, locations.validate_source(body.get("source"))))
                if path == "/api/browse":
                    return self._send(200, locations.browse(locations.validate_source(body.get("source"))))
                if path == "/api/scan":
                    ok = start_scan(body)
                    return self._send(202 if ok else 409, {"started": ok})
            except ValueError as exc:
                return self._send(400, {"error": str(exc)})
            except OSError as exc:
                return self._send(500, {"error": f"{type(exc).__name__}: {exc}"})
            if path == "/api/feedback":
                sid, key = str(body.get("scan_id", "")), str(body.get("key", ""))
                if not engine.load_scan(cfg, sid) or not key.isalnum():
                    return self._send(400, {"error": "unknown scan or key"})
                try:
                    return self._send(200, feedback.save(cfg, sid, key, body.get("verdict"),
                                                         body.get("importance"), body.get("note")))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if path == "/api/ask":
                scan = engine.load_scan(cfg, str(body.get("scan_id", "")))
                q = str(body.get("question", "")).strip()[:2000]
                if not scan or not q:
                    return self._send(400, {"error": "scan_id and question required"})
                try:
                    return self._send(200, {"answer": llm.ask(scan, q, cfg["llm"])})
                except llm.LLMError as exc:
                    return self._send(502, {"error": str(exc)})
            return self._send(404, {"error": "not found"})

    Handler.start_scan = staticmethod(start_scan)
    return Handler


def _scheduler(cfg: dict, sched: dict, start_scan) -> None:
    """Run a scan of all enabled sources every `schedule` (e.g. "6h"), covering the gap since the last one."""
    every = parse_window(cfg["schedule"]).total_seconds()
    sched["next"] = datetime.fromtimestamp(time.time() + every, timezone.utc).isoformat()
    while True:
        time.sleep(max(5, datetime.fromisoformat(sched["next"]).timestamp() - time.time()))
        started = start_scan({"window": cfg["schedule"], "use_llm": True})
        sched["last_auto"] = datetime.now(timezone.utc).isoformat()
        sched["last_auto_started"] = started
        sched["next"] = datetime.fromtimestamp(time.time() + every, timezone.utc).isoformat()


def serve(cfg: dict, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        cfg["_allow_any_host"] = True
        print("WARNING: dashboard is reachable from your network and has no login.")
    sched: dict = {"every": cfg.get("schedule") or None, "next": None}
    handler = make_handler(cfg, Job(), sched)
    httpd = ThreadingHTTPServer((host, port), handler)
    if cfg.get("schedule"):
        threading.Thread(target=_scheduler, args=(cfg, sched, handler.start_scan), daemon=True).start()
        print(f"automatic scans every {cfg['schedule']}")
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/"
    print(f"logagent dashboard on {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
