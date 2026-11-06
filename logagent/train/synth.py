"""Synthetic log scenarios so the model sees Pi/Jetson/Linux/Windows cases before you have real ones.

Every line is built from templates with randomized hosts, IPs, PIDs, units and numbers, then goes through
the real parsers and clustering, so the training input looks exactly like a real scan.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from ..collectors.textlogs import parse_app_log, parse_syslog

HOSTS = ["raspberrypi", "pi-cam", "pi-hole", "jetson-nano", "orin", "nas", "homeserver", "octopi", "k3s-node1"]
UNITS = ["camera-stream", "mqtt-bridge", "inference", "grafana-server", "node-red", "docker", "homeassistant",
         "octoprint", "nginx", "postgresql", "wireguard"]
APPS = ["worker", "api", "detector", "scheduler", "ingest"]

# (program, message template, repeat range). {ip} {n} {pid} {unit} {user} {dev} {port} {temp} {addr} are filled.
INTERESTING = [
    ("kernel", "[{n}.{n}] hwmon hwmon1: Undervoltage detected!", (1, 6)),
    ("kernel", "[{n}.{n}] mmc0: timeout waiting for hardware interrupt.", (1, 4)),
    ("kernel", "[{n}.{n}] blk_update_request: I/O error, dev {dev}, sector {n} op 0x1:(WRITE) flags 0x800", (1, 8)),
    ("kernel", "[{n}.{n}] EXT4-fs error (device {dev}p2): ext4_lookup:1785: inode #{n}: comm {unit}: deleted inode referenced", (1, 3)),
    ("kernel", "[{n}.{n}] EXT4-fs ({dev}p2): Remounting filesystem read-only", (1, 1)),
    ("kernel", "[{n}.{n}] Out of memory: Killed process {pid} ({unit}) total-vm:{n}kB, anon-rss:{n}kB", (1, 3)),
    ("kernel", "[{n}.{n}] {unit}[{pid}]: segfault at {addr} ip {addr} sp {addr} error 4 in libc.so.6", (1, 5)),
    ("kernel", "[{n}.{n}] cpu cpu0: thermal throttling: temperature above threshold {temp}C", (1, 10)),
    ("kernel", "[{n}.{n}] nvgpu: 17000000.gv11b gk20a_fifo_handle_pbdma_intr:2645 [ERR] pbdma_intr_0(0):0x{n}", (1, 6)),
    ("kernel", "[{n}.{n}] NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus.", (1, 1)),
    ("kernel", "[{n}.{n}] usb 1-1.{n}: device descriptor read/64, error -71", (2, 8)),
    ("kernel", "[{n}.{n}] INFO: task {unit}:{pid} blocked for more than 120 seconds.", (1, 3)),
    ("kernel", "[{n}.{n}] [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=192.168.1.10 PROTO=TCP SPT={port} DPT=23", (20, 60)),
    ("sshd", "Failed password for invalid user {user} from {ip} port {port} ssh2", (5, 80)),
    ("sshd", "Accepted publickey for pi from {ip} port {port} ssh2: ED25519 SHA256:abc", (1, 2)),
    ("sudo", "pam_unix(sudo:auth): authentication failure; logname={user} uid=1000 euid=0 tty=/dev/pts/0 ruser={user} rhost=  user={user}", (1, 4)),
    ("useradd", "new user: name={user}, UID=1001, GID=1001, home=/home/{user}, shell=/bin/bash", (1, 1)),
    ("systemd", "{unit}.service: Main process exited, code=exited, status=1/FAILURE", (1, 3)),
    ("systemd", "{unit}.service: Scheduled restart job, restart counter is at {n}.", (3, 20)),
    ("systemd", "{unit}.service: Start request repeated too quickly.", (1, 1)),
    ("systemd-resolved", "Using degraded feature set UDP instead of UDP+EDNS0 for DNS server 1.1.1.1.", (1, 3)),
    ("dhcpcd", "eth0: carrier lost", (1, 6)),
    ("kernel", "[{n}.{n}] audit: type=1400 audit({n}.{n}:{n}): apparmor=\"DENIED\" operation=\"open\" profile=\"{unit}\" name=\"/etc/shadow\"", (1, 3)),
]
ROUTINE = [
    ("CRON", "(root) CMD (/usr/local/bin/backup.sh)", (10, 60)),
    ("systemd", "Started {unit}.service - {unit} daemon.", (1, 3)),
    ("systemd", "Starting Daily apt download activities...", (1, 2)),
    ("systemd", "Finished Clean php session files.", (1, 2)),
    ("rsyslogd", "[origin software=\"rsyslogd\"] rsyslogd was HUPed", (1, 2)),
    ("dhcpcd", "eth0: leased 192.168.1.{n} for 86400 seconds", (1, 4)),
    ("systemd-timesyncd", "Initial clock synchronization to Thu 2026-11-06 10:00:00.123 UTC.", (1, 1)),
    ("kernel", "[{n}.{n}] IPv6: ADDRCONF(NETDEV_CHANGE): wlan0: link becomes ready", (1, 2)),
    ("sshd", "pam_unix(sshd:session): session opened for user pi(uid=1000) by (uid=0)", (1, 5)),
    ("systemd-logind", "New session {n} of user pi.", (1, 5)),
    ("NetworkManager", "<info>  [{n}.{n}] dhcp4 (wlan0): state changed new lease, address=192.168.1.{n}", (1, 4)),
    ("anacron", "Job `cron.daily' terminated", (1, 1)),
    ("kernel", "[{n}.{n}] Bluetooth: hci0: BCM: firmware Patch file not found, tried: 'brcm/BCM4345C0.hcd'", (1, 2)),
]
APP_INTERESTING = [
    ["ERROR {app}: failed to process job {n}", "Traceback (most recent call last):",
     '  File "/srv/{app}/main.py", line {n}, in run', "    result = handler(msg)",
     "KeyError: 'payload'"],
    ["ERROR {app}: inference failed", "Traceback (most recent call last):",
     '  File "/srv/{app}/model.py", line {n}, in infer', "RuntimeError: CUDA out of memory. Tried to allocate {n}.00 MiB"],
    ["CRITICAL {app}: database is locked, giving up after {n} retries"],
    ["WARNING {app}: connection refused to {ip}:5432, retrying in {n}s"],
    ["ERROR {app}: 401 Unauthorized from api.example.com: invalid token"],
    ["ERROR {app}: [Errno 24] Too many open files"],
]
APP_ROUTINE = ["INFO {app}: processed batch {n} in {n}ms", "DEBUG {app}: heartbeat ok",
               "INFO {app}: config reloaded", "INFO {app}: served GET /health 200 in {n}ms"]


def _fill(t: str, rnd: random.Random, ctx: dict) -> str:
    rep = {
        "{n}": lambda: str(rnd.randint(1, 99999)), "{pid}": lambda: str(rnd.randint(300, 32000)),
        "{ip}": lambda: ctx["ip"], "{port}": lambda: str(rnd.randint(1024, 65000)),
        "{unit}": lambda: ctx["unit"], "{user}": lambda: ctx["user"], "{dev}": lambda: ctx["dev"],
        "{temp}": lambda: str(rnd.randint(80, 95)), "{addr}": lambda: hex(rnd.getrandbits(40)), "{app}": lambda: ctx["app"],
    }
    for k, f in rep.items():
        while k in t:
            t = t.replace(k, f(), 1)
    return t


def scenario(rnd: random.Random, now: datetime) -> tuple[list[str], list[str]]:
    """One fake host-day: a few interesting events buried in routine noise. Returns (syslog lines, app lines)."""
    host = rnd.choice(HOSTS)
    lines: list[tuple[datetime, str]] = []
    picks = [(p, 1) for p in rnd.sample(INTERESTING, rnd.randint(0, 4))] + [(p, 0) for p in rnd.sample(ROUTINE, rnd.randint(3, 8))]
    for (prog, tmpl, (lo, hi)), _ in picks:
        ctx = {"ip": f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
               "unit": rnd.choice(UNITS), "user": rnd.choice(["admin", "test", "oracle", "ubuntu", "git", "pi"]),
               "dev": rnd.choice(["mmcblk0", "sda", "nvme0n1"]), "app": rnd.choice(APPS)}
        start = now - timedelta(minutes=rnd.randint(30, 1400))
        for i in range(rnd.randint(lo, hi)):
            ts = start + timedelta(seconds=i * rnd.randint(1, 120))
            pid = f"[{rnd.randint(300, 32000)}]" if prog not in ("kernel",) else ""
            lines.append((ts, f"{ts:%b %e %H:%M:%S} {host} {prog}{pid}: {_fill(tmpl, rnd, ctx)}"))
    lines.sort()

    app: list[str] = []
    ctx = {"ip": "192.168.1.5", "unit": "", "user": "", "dev": "", "app": rnd.choice(APPS)}
    t = now - timedelta(hours=6)
    errs = rnd.sample(APP_INTERESTING, rnd.randint(0, 2))
    for i in range(rnd.randint(20, 60)):
        t += timedelta(seconds=rnd.randint(5, 600))
        if errs and rnd.random() < 0.08:
            block = rnd.choice(errs)
            app.append(f"{t:%Y-%m-%d %H:%M:%S},{rnd.randint(100, 999)} " + _fill(block[0], rnd, ctx))
            app.extend(_fill(x, rnd, ctx) for x in block[1:])
        else:
            app.append(f"{t:%Y-%m-%d %H:%M:%S},{rnd.randint(100, 999)} " + _fill(rnd.choice(APP_ROUTINE), rnd, ctx))
    return [l for _, l in lines], app


def synthetic_events(n_scenarios: int, seed: int = 7):
    """Yield lists of Events, one list per fake host-day."""
    rnd = random.Random(seed)
    now = datetime.now().astimezone()
    for _ in range(n_scenarios):
        sys_lines, app_lines = scenario(rnd, now)
        evs = list(parse_syslog(sys_lines, year=now.year))
        host = evs[0].host if evs else "host"
        evs += list(parse_app_log(app_lines, rnd.choice(APPS), host))
        yield evs
