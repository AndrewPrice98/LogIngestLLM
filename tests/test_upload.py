"""OPEN LOG FILE: the browser sends a file to /api/upload, it lands in data_dir/uploads and can then be scanned."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from logagent import engine, server


@pytest.fixture
def base(tmp_path):
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path / "data")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(cfg, server.Job(), {}))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", tmp_path
    httpd.shutdown()


def _post(url, data, headers):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method="POST")) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_upload_saves_into_data_dir(base):
    url, tmp = base
    body = b"Nov  6 10:02:00 pi sshd[1]: Failed password for root from 10.0.0.2 port 22 ssh2\n"
    code, r = _post(url + "/api/upload", body, {"content-type": "application/octet-stream",
                                                "x-filename": "..%2F..%2Fauth%20log.txt"})
    assert code == 200 and r["name"] == "auth log.txt" and r["bytes"] == len(body)
    p = Path(r["path"])
    assert p.read_bytes() == body and (tmp / "data" / "uploads") in p.parents  # the name can't climb out


def test_upload_needs_the_custom_header(base):
    url, tmp = base
    # what a plain cross-site form could send: no x-filename, so it's refused and nothing is written
    code, _ = _post(url + "/api/upload", b"x", {"content-type": "application/octet-stream"})
    assert code == 403 and not (tmp / "data" / "uploads").exists()


def test_folder_upload_lands_in_one_batch_folder(base):
    url, tmp = base
    h = {"content-type": "application/octet-stream", "x-batch": "0a1b2c3d4e5f6071"}
    a = _post(url + "/api/upload", b"one", dict(h, **{"x-filename": "NOTEPAD.EXE-0A1B2C3D.pf"}))[1]
    b = _post(url + "/api/upload", b"two", dict(h, **{"x-filename": "NOTEPAD.EXE-0A1B2C3D.pf"}))[1]  # same name, other subfolder
    assert a["dir"] == b["dir"] and Path(a["dir"]).name == "batch-0a1b2c3d4e5f6071"
    assert b["name"] == "NOTEPAD.EXE-0A1B2C3D-2.pf" and Path(b["path"]).read_bytes() == b"two"
    code, _ = _post(url + "/api/upload", b"x", dict(h, **{"x-filename": "a.log", "x-batch": "../../etc"}))
    assert code == 400
