"""Known-valuable event signatures.

Each rule says *why* the event matters and *what to do*, so the report is useful
even without an LLM, and the LLM gets expert hints instead of raw noise.
Add your own in config (see config.example.toml -> [[rules]]).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Event, WARNING


@dataclass
class Rule:
    id: str
    title: str
    category: str           # security | hardware | storage | power | thermal | stability | app | update | network
    score: int              # 0-100 base importance
    why: str
    action: str
    event_ids: tuple[str, ...] = ()     # Windows EventIDs (optional)
    providers: tuple[str, ...] = ()     # provider/program substrings, case-insensitive (optional)
    pattern: str | None = None          # regex on message (optional)
    min_count: int = 1                  # only flag when the cluster has at least this many hits
    exclude: str | None = None          # regex: never match when the message contains this
    max_severity: int = 7               # only match events at least this severe (0=emerg .. 7=debug)
    _rx: re.Pattern | None = field(default=None, repr=False)
    _ex: re.Pattern | None = field(default=None, repr=False)

    def matches(self, e: Event) -> bool:
        if e.severity > self.max_severity:
            return False
        if self.event_ids and e.event_id not in self.event_ids:
            return False
        if self.providers and not any(p.lower() in (e.program or "").lower() or p.lower() in e.source.lower()
                                      for p in self.providers):
            return False
        if self.pattern:
            if self._rx is None:
                self._rx = re.compile(self.pattern, re.I)
            if not self._rx.search(e.message):
                return False
        if self.exclude:
            if self._ex is None:
                self._ex = re.compile(self.exclude, re.I)
            if self._ex.search(e.message):
                return False
        return bool(self.event_ids or self.providers or self.pattern)


R = Rule
BUILTIN_RULES: list[Rule] = [
    # ------------------------------------------------ Windows: security
    R("win_audit_cleared", "Security audit log was cleared", "security", 95,
      "Clearing the Security log is a classic step to hide an intrusion.",
      "Confirm you (or an update/tool you trust) cleared it; if not, treat the machine as compromised.",
      event_ids=("1102", "104"), pattern=r"clear|cleared"),
    R("win_failed_logon_burst", "Repeated failed logons", "security", 70,
      "Many failed logons in a short time usually means password guessing or a stale saved credential.",
      "Check the account and source address in the event; if it's not a stale credential, block the source.",
      event_ids=("4625",), min_count=5),
    R("win_failed_logon", "Failed logon", "security", 35,
      "A single failed logon is normally a typo, but worth knowing about on remote/network logons.",
      "Glance at the logon type and source; ignore if it was you.", event_ids=("4625",)),
    R("win_lockout", "Account locked out", "security", 75,
      "Lockouts follow repeated bad passwords: attack or a broken saved credential.",
      "Find the caller computer in the event and fix the credential or block it.", event_ids=("4740",)),
    R("win_user_created", "New user account created", "security", 80,
      "New local accounts are a persistence technique if you didn't make them.",
      "Verify the account in Settings > Accounts or `net user`.", event_ids=("4720",)),
    R("win_admin_group_add", "Account added to a privileged group", "security", 85,
      "Someone got admin rights.", "Verify the member and who added it.", event_ids=("4732", "4728", "4756")),
    R("win_service_installed", "New service installed", "security", 55,
      "New services are how drivers, updaters and also malware get persistence.",
      "Check the service name and binary path; unknown paths in Temp/AppData are red flags.",
      event_ids=("7045", "4697")),
    R("win_defender_threat", "Microsoft Defender detected a threat", "security", 90,
      "Defender found malware or a PUA.", "Open Windows Security > Protection history and confirm it was quarantined.",
      event_ids=("1116", "1117", "1006", "1015")),
    R("win_defender_off", "Defender protection disabled", "security", 80,
      "Real-time protection or tamper protection was turned off.",
      "Turn it back on unless you did this deliberately.", event_ids=("5001", "5010", "5012")),
    R("win_rdp_logon", "Remote Desktop logon", "security", 45,
      "Interactive remote logons should be ones you expect.", "Confirm the source IP is yours.",
      event_ids=("4624",), pattern=r"Logon Type:\s*10\b"),
    R("win_kerberoast", "Kerberoasting: RC4 service ticket requested", "security", 85,
      "A service ticket was requested with weak RC4 encryption for a user-run service. Attackers do this to crack "
      "the service account's password offline (Kerberoasting).",
      "Check which account requested it (Account Name, Client Address) and whether that's expected; give service "
      "accounts long random passwords or gMSAs, and disable RC4 for them.",
      event_ids=("4769",), pattern=r"Ticket\s?Encryption\s?Type:\s*0x17\b", exclude=r"Service\s?Name:\s*(krbtgt|\S+\$)"),
    R("win_kerberos_preauth_burst", "Many Kerberos pre-authentication failures", "security", 65,
      "Lots of failed Kerberos logons usually means password guessing or spraying against the domain "
      "(or one device with a stale password).",
      "Look at the account names and client addresses: many accounts from one address = spraying.",
      event_ids=("4771",), min_count=10),
    # ------------------------------------------------ Windows: stability / hardware
    R("win_unexpected_shutdown", "Unexpected shutdown / power loss", "stability", 75,
      "The system rebooted without shutting down cleanly: crash, freeze, or power loss.",
      "Correlate with a BugCheck or WHEA event right before; check PSU/power if none.",
      event_ids=("41", "6008"), providers=("Kernel-Power", "EventLog")),
    R("win_bugcheck", "Blue screen (BugCheck)", "stability", 90,
      "Windows crashed. The bugcheck code identifies the failing driver class.",
      "Look up the stop code; check C:\\Windows\\Minidump with WinDbg or BlueScreenView.",
      event_ids=("1001",), providers=("BugCheck", "WER-SystemErrorReporting")),
    R("win_whea", "Hardware error (WHEA)", "hardware", 85,
      "CPU, memory or PCIe reported a hardware error. Corrected errors that repeat precede failures.",
      "Check the component in the event (often PCIe/GPU or memory); review overclocks/XMP; reseat hardware.",
      providers=("WHEA-Logger",)),
    R("win_disk_bad", "Disk errors / bad blocks", "storage", 90,
      "The disk reported bad blocks, controller errors or retries. Data loss risk.",
      "Back up now, then check SMART (CrystalDiskInfo / `smartctl`).",
      event_ids=("7", "11", "51", "153", "129"), providers=("disk", "stornvme", "storahci", "iaStor", "Disk")),
    R("win_ntfs_corrupt", "File system corruption", "storage", 85,
      "NTFS found corruption.", "Run `chkdsk /scan` and back up important data.",
      event_ids=("55", "98", "137"), providers=("Ntfs",), exclude=r"is healthy|No action is needed",
      max_severity=WARNING),
    R("win_volsnap", "Shadow copies / restore points deleted", "storage", 60,
      "Shadow copies were removed (low space, or ransomware behaviour).",
      "Check free space; if unexplained, investigate.", event_ids=("25", "36"), providers=("volsnap",)),
    R("win_app_crash", "Application crash", "app", 40,
      "An application crashed. Repeated crashes of the same app point to a bad update or plugin.",
      "Check the faulting module named in the event.", event_ids=("1000", "1002"),
      providers=("Application Error", "Application Hang")),
    R("win_service_crash", "Service terminated unexpectedly", "stability", 50,
      "A Windows service died; some auto-restart, some don't.", "Check whether the service is running now.",
      event_ids=("7031", "7034", "7023", "7024")),
    R("win_service_start_fail", "Service failed to start", "stability", 45,
      "A service or driver failed to start at boot.", "Check the service named; disable it if obsolete.",
      event_ids=("7000", "7001", "7009", "7026")),
    R("win_display_reset", "GPU driver reset (TDR)", "hardware", 65,
      "The display driver stopped responding and recovered: unstable GPU driver, overclock or overheating.",
      "Update/roll back the GPU driver; check GPU temps and overclocks.", event_ids=("4101",),
      providers=("Display", "nvlddmkm")),
    R("win_update_fail", "Windows Update failed", "update", 45,
      "Security updates are not installing.", "Run Windows Update manually and note the error code.",
      event_ids=("20", "31", "25"), providers=("WindowsUpdateClient",)),
    R("win_time_sync", "Time sync problems", "network", 25,
      "Clock drift breaks TLS and Kerberos.", "Run `w32tm /resync`.", providers=("Time-Service",),
      pattern=r"not synchroniz|no valid response|unable to"),
    # ------------------------------------------------ Linux / Pi / Jetson
    R("lx_oom", "Out-of-memory killer fired", "stability", 85,
      "The kernel killed a process to free memory. Services silently die.",
      "Find the killed process in the message; add swap/zram or cap that service's memory.",
      pattern=r"Out of memory: Kill|oom-kill|oom_reaper|invoked oom-killer|Killed process \d+"),
    R("lx_segfault", "Process segfault", "app", 55,
      "A program crashed on a memory fault (bug, bad library, or failing RAM if it's random).",
      "If different programs segfault randomly, test RAM; otherwise update/rebuild that program.",
      pattern=r"segfault at|general protection fault|core dumped|traps:.*trap"),
    R("lx_kernel_panic", "Kernel panic / BUG / Oops", "stability", 95,
      "The kernel hit a fatal or serious internal error.", "Capture the full trace; check recent kernel/driver changes.",
      pattern=r"Kernel panic|BUG: |Oops:|kernel BUG|watchdog: BUG: soft lockup|hung_task|blocked for more than \d+ seconds"),
    R("lx_ssh_bruteforce", "SSH password guessing", "security", 70,
      "Repeated failed SSH logins: an internet-facing box being brute-forced.",
      "Disable password auth (PasswordAuthentication no), use keys, consider fail2ban.",
      pattern=r"Failed password for|Invalid user .* from|authentication failure.*rhost=|Connection closed by authenticating user",
      min_count=5),
    R("lx_ssh_accepted", "SSH login accepted", "security", 30,
      "Successful remote login. Unremarkable if it was you.",
      "Confirm the source IP is yours.", pattern=r"Accepted (password|publickey|keyboard-interactive) for"),
    R("lx_sudo_fail", "sudo authentication failures", "security", 55,
      "Someone typed a wrong sudo password or a user not in sudoers tried sudo.",
      "Check the user named.", pattern=r"sudo:.*(authentication failure|incorrect password|NOT in sudoers)"),
    R("lx_new_user", "New user/group created", "security", 70,
      "Account creation on a server is a persistence technique if unexpected.", "Verify with `getent passwd`.",
      pattern=r"useradd\[|new user: name=|new group: name="),
    R("lx_io_error", "Storage I/O errors", "storage", 90,
      "The block device returned errors. On a Pi/Jetson this is usually a dying SD card or a flaky USB drive.",
      "Back up now; replace the SD card/drive; check `dmesg` and SMART.",
      pattern=r"I/O error|Buffer I/O error|blk_update_request|critical medium error|mmc\d+: (timeout|error)|"
              r"mmcblk\d+: .*error|ata\d+.*(failed command|exception)|nvme.*(timeout|reset)|UNC\b"),
    R("lx_fs_error", "Filesystem errors / read-only remount", "storage", 90,
      "The filesystem found corruption or remounted read-only: writes are now failing.",
      "Reboot to fsck, then check the underlying disk/SD card.",
      pattern=r"EXT4-fs error|EXT4-fs warning.*(error|corrupt)|Remounting filesystem read-only|XFS.*(corrupt|error)|"
              r"btrfs.*(error|corrupt)|FAT-fs.*error"),
    R("lx_disk_full", "Disk full", "storage", 75,
      "Something could not write because the disk is full.", "Free space (logs, docker images, journal vacuum).",
      pattern=r"No space left on device|disk_full|is \d{2,3}% full"),
    R("pi_undervoltage", "Under-voltage (power supply too weak)", "power", 90,
      "The Pi isn't getting enough power. This causes random crashes and SD card corruption.",
      "Use the official PSU / a thicker USB-C cable; avoid powering USB drives off the Pi.",
      pattern=r"[Uu]nder-?voltage|hwmon.*in0.*(alarm|undervoltage)|pi_throttle_(0|16)"),
    R("thermal_throttle", "Thermal throttling / overheating", "thermal", 75,
      "The CPU/GPU is slowing down (or will) because it's too hot.",
      "Add a heatsink/fan, improve airflow, check the fan is spinning.",
      pattern=r"thermal.*(throttl|critical|trip)|cpu clock throttled|temperature above threshold|"
              r"Thermal zone .* at|soc_therm|OC alarm|over-?current|[Tt]hrottl(ed|ing)|frequency capp|"
              r"temperature limit"),
    R("jetson_gpu", "Jetson GPU / NVIDIA driver errors", "hardware", 70,
      "The Tegra GPU driver reported faults: crashes in CUDA/TensorRT workloads usually show up here.",
      "Check JetPack/L4T version compatibility of your CUDA libs; watch power mode (nvpmodel) and temps.",
      pattern=r"nvgpu.*(error|fault|timeout)|NVRM|gk20a.*(error|fault)|nvmap.*(error|fail)|tegra.*(error|fault)|"
              r"Xid \d+|nvidia.*(error|fault)"),
    R("lx_usb_disconnect_err", "USB device errors / resets", "hardware", 45,
      "A USB device errored or keeps resetting (camera, SSD, adapter): cable, power, or hub problem.",
      "Try a powered hub or different cable/port.",
      pattern=r"usb \S+: (device descriptor read.*error|device not accepting address|reset high-speed|"
              r"USB disconnect.*device number)|over-current change"),
    R("lx_unit_failed", "systemd service failed", "stability", 60,
      "A service crashed or failed to start and stayed down.", "Run `systemctl status <unit>` and `journalctl -u <unit>`.",
      pattern=r"Failed with result|Main process exited, code=(exited|killed|dumped), status=(?!0/)|"
              r"Failed to start |unit .* is in failed state|entered failed state"),
    R("lx_restart_loop", "Service restart loop", "stability", 70,
      "A service keeps restarting: it's broken but systemd hides it by restarting.",
      "Check the unit's logs right before each restart.",
      pattern=r"Scheduled restart job, restart counter is at|Start request repeated too quickly"),
    R("lx_net_down", "Network link flapping / DNS failures", "network", 40,
      "Interface dropped or name resolution failed: can explain app timeouts.",
      "Check cabling/Wi-Fi signal; check DNS server.",
      pattern=r"Link is Down|link becomes not ready|carrier lost|brcmf.*(error|fail)|"
              r"Temporary failure in name resolution|DNSSEC validation failed"),
    R("lx_time_jump", "Clock not synchronized", "network", 25,
      "No RTC on a Pi: without NTP, timestamps and TLS break.", "Check systemd-timesyncd/chrony.",
      pattern=r"Time has been changed|clock (unsynchroni|jumped)|NTP.*(unreachable|failed)"),
    R("lx_firewall_block", "Firewall blocks", "security", 20,
      "Firewall dropped inbound traffic. High volume from one IP = scanning.",
      "Usually fine; look for unexpected ports.", pattern=r"\[UFW BLOCK\]|IPTABLES.*DROP|nft.*drop", min_count=20),
    R("lx_apparmor_deny", "AppArmor/SELinux denials", "security", 40,
      "A confined program tried something it's not allowed to do.", "Check the profile and the denied operation.",
      pattern=r'apparmor="DENIED"|avc:\s+denied'),
    # ------------------------------------------------ generic app logs
    R("app_traceback", "Unhandled exception / stack trace", "app", 60,
      "Your app threw an exception. Repeats of the same trace are a real bug.",
      "Open the trace; the last frame in your own code is the place to fix.",
      pattern=r"Traceback \(most recent call last\)|Exception in thread|Unhandled exception|panic: |"
              r"\bat [\w.$]+\([\w]+\.java:\d+\)|stack backtrace:|UnhandledPromiseRejection"),
    R("app_fatal", "Fatal error in app", "app", 75,
      "The app logged a fatal/critical error, often right before exiting.", "Check what happened just before.",
      pattern=r"\b(FATAL|CRITICAL|PANIC)\b"),
    R("app_db", "Database / connection errors", "app", 55,
      "Lost or refused connections to a DB/broker/API.", "Check that dependency is up and reachable.",
      pattern=r"(connection (refused|reset|timed out)|could not connect|deadlock|too many connections|"
              r"ECONNREFUSED|ETIMEDOUT|database is locked)"),
    R("app_auth", "Auth / permission failures", "security", 45,
      "Requests were rejected for auth reasons: expired tokens or probing.",
      "Check if a key/certificate expired.",
      pattern=r"\b(401|403)\b.*(unauthori|forbidden)|invalid (token|api key|credentials)|permission denied|"
              r"certificate (has )?expired|x509"),
    R("app_resource", "Resource exhaustion in app", "stability", 60,
      "Memory/file-handle/thread exhaustion.", "Look for leaks; check limits (ulimit, container memory).",
      pattern=r"MemoryError|OutOfMemoryError|Too many open files|EMFILE|cannot allocate memory|CUDA out of memory"),
]


# Known-benign chatter. A negative score suppresses the cluster entirely.
NOISE_RULES: list[Rule] = [
    R("noise_dcom_10016", "DCOM permission warning (benign)", "noise", -100,
      "Microsoft documents 10016 as safe to ignore.", "", event_ids=("10016",)),
    R("noise_device_assoc", "Device association chatter", "noise", -100, "", "",
      providers=("DeviceAssociationService",)),
    R("noise_cron", "cron job ran", "noise", -100, "", "", providers=("CRON",), pattern=r"CMD \("),
]


def load_rules(extra: list[dict] | None = None) -> list[Rule]:
    rules = list(BUILTIN_RULES) + list(NOISE_RULES)
    for d in extra or []:
        rules.append(Rule(
            id=d["id"], title=d.get("title", d["id"]), category=d.get("category", "app"),
            score=int(d.get("score", 50)), why=d.get("why", ""), action=d.get("action", ""),
            event_ids=tuple(str(x) for x in d.get("event_ids", ())), providers=tuple(d.get("providers", ())),
            pattern=d.get("pattern"), min_count=int(d.get("min_count", 1)), exclude=d.get("exclude"),
            max_severity=int(d.get("max_severity", 7)),
        ))
    return rules


# Built-in rules written for Linux / app log text. On Windows events they would match words inside rendered
# messages and PowerShell script blocks (source code), so they don't apply there.
_NOT_FOR_WINDOWS = ("lx_", "pi_", "jetson_", "thermal_", "app_")


def match_rules(e: Event, rules: list[Rule]) -> list[Rule]:
    win = e.source.startswith("windows")
    return [r for r in rules if not (win and r.id.startswith(_NOT_FOR_WINDOWS)) and r.matches(e)]
