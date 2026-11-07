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
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__, engine, explain, feedback, knowledge, labelqueue, llm, locations, logview, report
from .collectors.sources import parse_window

STATIC = Path(__file__).parent / "static"
MAX_UPLOAD = 4 * 2**30  # bigger logs: open them by path (Log locations → + Add / open file)


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
    if prov == "bundled":
        from . import bundled
        return bundled.ENGINE.status()
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


def _models_overview() -> dict:
    """Trained versions, which one is active, held-out scores, co-pilot eval results and promotion decisions."""
    from . import evals
    from .paths import models_dir
    models = models_dir()
    read = lambda p: json.loads(p.read_text(encoding="utf-8"))
    active = evals.active_adapter()
    copilot = {}
    for p in sorted(models.glob("copilot-eval-model-*.json")):
        r = read(p)
        copilot[r.get("adapter") or "?"] = {"passed": r["passed"], "total": r["total"], "created": r["created"],
                                           "failed": [f"{s['name']}: {c['check']}" for s in r["scenarios"]
                                                      for c in s.get("checks", []) if not c["ok"]]}
    versions = []
    for d in sorted(models.glob("logagent-*"), reverse=True):
        if not (d / "adapter").is_dir():
            continue
        ev = models / f"eval-{d.name}.json"
        versions.append({"name": d.name, "active": d.name == active,
                         "train": read(d / "train_info.json") if (d / "train_info.json").exists() else {},
                         "heldout": read(ev)["report"].get("all") if ev.exists() else None,
                         "copilot": copilot.get(d.name)})
    base = models / "eval-base.json"
    return {"active": active, "versions": versions, "base": read(base)["report"].get("all") if base.exists() else None,
            "promotions": [{k: v for k, v in read(p).items() if not k.endswith("_report")}
                           for p in sorted(models.glob("promote-*.json"), reverse=True)][:20]}


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
            if path == "/api/logview":
                qs = parse_qs(urlparse(self.path).query)
                g = lambda k, d=None: (qs.get(k) or [d])[0]
                scan = engine.load_scan(cfg, str(g("scan", "")))
                if not scan:
                    return self._send(404, {"error": "unknown scan"})
                try:
                    return self._send(200, logview.view(scan, str(g("ref", "")), int(g("before", 25)), int(g("after", 25)), g("at")))
                except (logview.ViewError, ValueError) as exc:
                    return self._send(400, {"error": str(exc)})
            if path == "/api/report":
                qs = parse_qs(urlparse(self.path).query)
                scan = engine.load_scan(cfg, (qs.get("scan") or [""])[0])
                if not scan:
                    return self._send(404, {"error": "unknown scan"})
                md = report.markdown(scan)
                fmt = (qs.get("format") or ["md"])[0]
                body = report.to_html(md, f"LogIngestLLM report {scan['id']}") if fmt == "html" else md
                data = body.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8" if fmt == "html" else "text/markdown; charset=utf-8")
                if fmt != "html":
                    self.send_header("content-disposition", f'attachment; filename="logagent-report-{scan["id"]}.md"')
                self.send_header("content-length", str(len(data)))
                self.send_header("x-content-type-options", "nosniff")
                self.end_headers()
                self.wfile.write(data)
                return
            if path == "/api/samples":
                from .cli import DEMO
                from .paths import resource
                root = resource("samples")
                return self._send(200, [{"file": f, "label": l, "path": str(root / f), "host": h} for f, l, h in DEMO if (root / f).exists()])
            if path == "/api/models":
                return self._send(200, _models_overview())
            if path == "/api/queue":
                return self._send(200, labelqueue.build(cfg))
            if path == "/api/reference":
                return self._send(200, knowledge.reference_catalog())
            if path == "/api/pivot":
                qs = parse_qs(urlparse(self.path).query)
                kind, value = (qs.get("type") or [""])[0], (qs.get("value") or [""])[0]
                if not kind or not value:
                    return self._send(400, {"error": "type and value required"})
                return self._send(200, engine.pivot(cfg, kind, value[:500]))
            if path == "/api/system":
                return self._send(200, locations.system_info())
            if path == "/api/sources":
                return self._send(200, {"sources": cfg.get("sources", []), "config_path": cfg.get("_path")})
            if path == "/api/discover":
                if cfg.get("_allow_any_host"):
                    return self._send(403, {"error": "file browsing is disabled when the dashboard is network-reachable"})
                return self._send(200, locations.discover(cfg))
            return self._send(404, {"error": "not found"})

        def _upload(self):
            """Save one log sent from the browser's file picker / drag-and-drop into data_dir/uploads, then the
            page scans it like a picked file. octet-stream + a custom header forces a CORS preflight (which we never
            answer), so other web pages can't push files here."""
            if cfg.get("_allow_any_host"):
                return self._send(403, {"error": "uploads are disabled when the dashboard is network-reachable"})
            name = os.path.basename(unquote(self.headers.get("x-filename") or "").replace("\\", "/")).strip()
            name = "".join(ch if ch.isalnum() or ch in "._- ()" else "_" for ch in name).strip(". ") or "upload.log"
            try:
                n = int(self.headers.get("content-length") or -1)
            except ValueError:
                n = -1
            if n < 0:
                return self._send(411, {"error": "content-length required"})
            if n > MAX_UPLOAD:
                return self._send(413, {"error": f"file is over {MAX_UPLOAD // 2**30} GB; open it by path instead"})
            d = Path(cfg["data_dir"]) / "uploads" / f"{datetime.now():%Y%m%d-%H%M%S}-{os.urandom(2).hex()}"
            d.mkdir(parents=True, exist_ok=True)
            dest = d / name
            with open(dest, "wb") as fh:
                left = n
                while left > 0:
                    chunk = self.rfile.read(min(left, 1 << 20))
                    if not chunk:
                        break
                    fh.write(chunk)
                    left -= len(chunk)
            if left:
                dest.unlink(missing_ok=True)
                return self._send(400, {"error": "upload was cut short"})
            return self._send(200, {"path": str(dest.resolve()), "name": name, "bytes": n})

        def do_POST(self):
            if (self._host_ok() and urlparse(self.path).path == "/api/upload" and self.headers.get("x-filename")
                    and (self.headers.get("content-type") or "").startswith("application/octet-stream")):
                return self._upload()
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
            if path == "/api/quit":  # stop the dashboard (and the built-in model) from the browser
                self._send(200, {"stopping": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            if path == "/api/feedback":
                sid, key = str(body.get("scan_id", "")), str(body.get("key", ""))
                if not engine.load_scan(cfg, sid) or not key.isalnum():
                    return self._send(400, {"error": "unknown scan or key"})
                try:
                    return self._send(200, feedback.save(cfg, sid, key, body.get("verdict"),
                                                         body.get("importance"), body.get("note")))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if path == "/api/explain":
                scan = engine.load_scan(cfg, str(body.get("scan_id", "")))
                c = next((c for c in (scan or {}).get("findings", []) + (scan or {}).get("others", [])
                          if c["key"] == str(body.get("key", ""))), None)
                if not c:
                    return self._send(400, {"error": "unknown scan or pattern"})
                exp = explain.explain(c, scan)
                if body.get("ask"):
                    os_info = (scan.get("stats") or {}).get("os") or {}
                    origin = os_info.get("origin") or ("Windows" if c["source"].startswith("windows") else "unknown")
                    try:
                        exp["model_text"] = llm.explain_event(exp, c, origin, os_info.get("viewer") or
                                                              locations.system_info()["pretty"],
                                                              str(body.get("level") or "learning"), cfg["llm"],
                                                              [i for i in scan.get("iocs", []) if c["key"] in i["keys"]])
                    except (llm.LLMError, KeyError, ValueError, TimeoutError, OSError) as exc:
                        exp["model_error"] = str(exc)
                return self._send(200, exp)
            if path == "/api/ask":
                scan = engine.load_scan(cfg, str(body.get("scan_id", "")))
                q = str(body.get("question", "")).strip()[:2000]
                if not scan or not q:
                    return self._send(400, {"error": "scan_id and question required"})
                try:
                    answer, refs = llm.ask(scan, q, cfg["llm"])
                    return self._send(200, {"answer": answer, "refs": refs})
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
    if (cfg["llm"].get("provider") or "").lower() == "bundled":  # warm the built-in model while the page loads
        from . import bundled

        def warm():
            try:
                bundled.ENGINE.start()
            except RuntimeError as exc:
                print(f"[model] {exc}  (continuing with rules only)")
        threading.Thread(target=warm, daemon=True).start()
    if cfg.get("schedule"):
        threading.Thread(target=_scheduler, args=(cfg, sched, handler.start_scan), daemon=True).start()
        print(f"automatic scans every {cfg['schedule']}")
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/"
    print(f"LogIngestLLM dashboard on {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
