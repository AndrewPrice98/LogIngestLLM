"""The packaged Linux app must launch the browser without its bundled libraries on LD_LIBRARY_PATH."""
from logagent import paths


def test_host_env_restores_library_path(monkeypatch):
    monkeypatch.setattr(paths, "FROZEN", True)
    monkeypatch.setattr(paths.sys, "platform", "linux")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/app/_internal")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/local/lib")
    env = paths.host_env()
    assert env["LD_LIBRARY_PATH"] == "/usr/local/lib" and "LD_LIBRARY_PATH_ORIG" not in env
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG")
    assert "LD_LIBRARY_PATH" not in paths.host_env()  # it wasn't set before the app started


def test_host_env_untouched_from_source(monkeypatch):
    monkeypatch.setattr(paths, "FROZEN", False)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/x")
    assert paths.host_env()["LD_LIBRARY_PATH"] == "/x"
