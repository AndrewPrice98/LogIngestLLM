"""Local web dashboard. Stdlib only. Binds to 127.0.0.1 by default."""
from __future__ import annotations

import json
import threading
import traceback
import webbrowser
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from . import engine, feedback, llm

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


def make_handler(cfg: dict, job: Job):
    def public_sources():
        return [{"name": s.get("name") or s.get("type"), "type": s.get("type"),
                 "detail": s.get("host") or s.get("path") or ",".join(s.get("channels", []) or [])}
                for s in cfg.get("sources", [])]

    def start_scan(body: dict):
        names = body.get("sources")
        srcs = [s for s in cfg.get("sources", []) if not names or (s.get("name") or s.get("type")) in names]
        with job.lock:
            if job.running:
                return False
            job.running, job.log, job.scan_id, job.error = True, [], None, None

        def progress(msg):
            with job.lock:
                job.log.append(f"{datetime.now():%H:%M:%S} {msg}")

        def work():
            try:
                scan = engine.run_scan(cfg, srcs, body.get("window"), bool(body.get("use_llm", True)), progress)
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
            if path == "/api/scans":
                return self._send(200, engine.list_scans(cfg))
            if path.startswith("/api/scans/"):
                scan = engine.load_scan(cfg, path.rsplit("/", 1)[-1])
                return self._send(200, scan) if scan else self._send(404, {"error": "not found"})
            if path.startswith("/api/feedback/"):
                return self._send(200, feedback.for_scan(cfg, path.rsplit("/", 1)[-1]))
            if path == "/api/job":
                return self._send(200, job.snapshot())
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
            if path == "/api/scan":
                ok = start_scan(body)
                return self._send(202 if ok else 409, {"started": ok})
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

    return Handler


def serve(cfg: dict, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        cfg["_allow_any_host"] = True
        print("WARNING: dashboard is reachable from your network and has no login.")
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg, Job()))
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/"
    print(f"logagent dashboard on {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
