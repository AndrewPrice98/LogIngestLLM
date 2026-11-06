"""Reference knowledge for learning to read logs and for analysts: MITRE ATT&CK techniques, Windows event IDs,
logon types and failure codes, common Linux log messages, programs and fields.

Static and local (nothing is fetched). Only security-relevant entries carry ATT&CK techniques: a disk error
or an OOM kill is an operations problem, not adversary behaviour, and is left unmapped on purpose.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------- MITRE ATT&CK (Enterprise)
TACTICS = [  # matrix order; Resource Development left out (it happens on the attacker's side)
    ("TA0043", "Reconnaissance"), ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"), ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"), ("TA0008", "Lateral Movement"), ("TA0009", "Collection"),
    ("TA0011", "Command and Control"), ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]

TECHNIQUES = {  # id: (name, [tactic ids])
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["TA0006"]),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ["TA0008"]),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", ["TA0008"]),
    "T1021.004": ("Remote Services: SSH", ["TA0008"]),
    "T1046": ("Network Service Discovery", ["TA0007"]),
    "T1053.003": ("Scheduled Task/Job: Cron", ["TA0002", "TA0003", "TA0004"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ["TA0002", "TA0003", "TA0004"]),
    "T1055": ("Process Injection", ["TA0005", "TA0004"]),
    "T1059": ("Command and Scripting Interpreter", ["TA0002"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["TA0002"]),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ["TA0002"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["TA0005"]),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", ["TA0005"]),
    "T1071.004": ("Application Layer Protocol: DNS", ["TA0011"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1087": ("Account Discovery", ["TA0007"]),
    "T1098": ("Account Manipulation", ["TA0003", "TA0004"]),
    "T1110": ("Brute Force", ["TA0006"]),
    "T1110.001": ("Brute Force: Password Guessing", ["TA0006"]),
    "T1112": ("Modify Registry", ["TA0005"]),
    "T1136.001": ("Create Account: Local Account", ["TA0003"]),
    "T1490": ("Inhibit System Recovery", ["TA0040"]),
    "T1529": ("System Shutdown/Reboot", ["TA0040"]),
    "T1531": ("Account Access Removal", ["TA0040"]),
    "T1543.002": ("Create or Modify System Process: Systemd Service", ["TA0003", "TA0004"]),
    "T1543.003": ("Create or Modify System Process: Windows Service", ["TA0003", "TA0004"]),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ["TA0004", "TA0005"]),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ["TA0006"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["TA0005"]),
    "T1562.002": ("Impair Defenses: Disable Windows Event Logging", ["TA0005"]),
    "T1569.002": ("System Services: Service Execution", ["TA0002"]),
    "T1047": ("Windows Management Instrumentation", ["TA0002"]),
    "T1021.006": ("Remote Services: Windows Remote Management", ["TA0008"]),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", ["TA0003", "TA0004"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ["TA0005"]),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ["TA0005"]),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ["TA0005"]),
    "T1219": ("Remote Access Software", ["TA0011"]),
    "T1496": ("Resource Hijacking", ["TA0040"]),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", ["TA0005"]),
    "T1572": ("Protocol Tunneling", ["TA0011"]),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", ["TA0043"]),
    "T1595.003": ("Active Scanning: Wordlist Scanning", ["TA0043"]),
}


def attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


# Built-in rules -> techniques. Only rules that describe adversary behaviour are mapped.
RULE_ATTACK = {
    "win_audit_cleared": ["T1070.001"],
    "win_failed_logon_burst": ["T1110"],
    "win_failed_logon": ["T1110"],
    "win_lockout": ["T1110"],
    "win_user_created": ["T1136.001"],
    "win_admin_group_add": ["T1098"],
    "win_service_installed": ["T1543.003", "T1569.002"],
    "win_defender_off": ["T1562.001"],
    "win_rdp_logon": ["T1021.001", "T1078"],
    "win_volsnap": ["T1490"],
    "win_kerberoast": ["T1558.003"],
    "win_rdp_failed": ["T1110", "T1021.001"],
    "win_explicit_creds": ["T1078"],
    "win_admin_share": ["T1021.002"],
    "win_task_created": ["T1053.005"],
    "win_audit_policy": ["T1562.002"],
    "win_account_enum": ["T1087"],
    "win_ps_suspicious": ["T1059.001"],
    "win_ps_remote": ["T1021.006"],
    "win_sysmon_lsass": ["T1003.001"],
    "win_sysmon_remote_thread": ["T1055"],
    "win_sysmon_run_key": ["T1547.001"],
    "win_kerberos_preauth_burst": ["T1110"],
    "lx_ssh_bruteforce": ["T1110.001", "T1021.004"],
    "lx_ssh_accepted": ["T1021.004", "T1078"],
    "lx_sudo_fail": ["T1548.003"],
    "lx_new_user": ["T1136.001"],
    "lx_firewall_block": ["T1046"],
}

# ---------------------------------------------------------------- Windows
LOGON_TYPES = {
    "2": ("Interactive", "someone typed a password at the keyboard (or a console session)"),
    "3": ("Network", "access over the network: file shares, net use, many remote admin tools"),
    "4": ("Batch", "a scheduled task ran as this account"),
    "5": ("Service", "a service started under this account"),
    "7": ("Unlock", "the screen was unlocked"),
    "8": ("NetworkCleartext", "network logon where the password was sent in clear text (e.g. IIS basic auth)"),
    "9": ("NewCredentials", "runas /netonly: local identity kept, other credentials used for the network"),
    "10": ("RemoteInteractive", "Remote Desktop (RDP) or Terminal Services"),
    "11": ("CachedInteractive", "logon with cached domain credentials (no domain controller reachable)"),
    "12": ("CachedRemoteInteractive", "RDP with cached domain credentials"),
    "13": ("CachedUnlock", "unlock with cached credentials"),
}

STATUS_CODES = {  # NTSTATUS values seen in 4625/4771/4776 Status / SubStatus
    "0xc000006a": "wrong password for a valid user name",
    "0xc0000064": "user name does not exist (guessing user names?)",
    "0xc000006d": "bad user name or password (see SubStatus for which)",
    "0xc000006e": "account restriction (see SubStatus)",
    "0xc0000234": "account is locked out",
    "0xc0000072": "account is disabled",
    "0xc000006f": "logon outside the allowed hours",
    "0xc0000070": "logon from a workstation that isn't allowed",
    "0xc0000071": "password has expired",
    "0xc0000193": "account has expired",
    "0xc0000133": "clocks out of sync between this machine and the domain controller",
    "0xc0000224": "user must change password at next logon",
    "0xc000015b": "user isn't granted this logon type here (e.g. RDP not allowed)",
    "0xc000005e": "no logon servers available",
    "0xc0000413": "authentication firewall: machine not allowed to authenticate",
    "0x0": "success",
}

KERBEROS_ENC = {"0x17": "RC4-HMAC (weak; requested on purpose in Kerberoasting)", "0x12": "AES256", "0x11": "AES128",
                "0x3": "DES (very old)", "0x1": "DES (very old)"}

WINDOWS_EVENTS = {  # id: (title, what it means, normal, worth a look when, [techniques])
    "4624": ("An account successfully logged on", "A logon session was created. LogonType says how (keyboard, network, RDP...).",
             "constant: services, scheduled tasks and the machine itself log on all the time",
             "LogonType 10 (RDP) or 3 from an unexpected IP, logons at odd hours, admin accounts from new places",
             ["T1078"]),
    "4625": ("An account failed to log on", "A logon attempt was refused. Status/SubStatus says why.",
             "an occasional typo", "many in a short time, many user names from one IP (guessing), or 0xc0000064 (unknown user)",
             ["T1110"]),
    "4634": ("An account was logged off", "A logon session ended.", "constant", "rarely interesting on its own", []),
    "4647": ("User initiated logoff", "Someone clicked sign out.", "normal", "rarely interesting", []),
    "4648": ("A logon was attempted using explicit credentials", "A process used a different account's credentials (runas, mapped drives).",
             "admins using runas, some backup tools", "unusual process or target server: possible lateral movement", ["T1078"]),
    "4672": ("Special privileges assigned to new logon", "An admin-equivalent logon happened (privileges like SeDebugPrivilege).",
             "every admin and SYSTEM logon", "admin rights for an account that shouldn't have them", []),
    "4688": ("A new process has been created", "A program started. CommandLine shows its arguments if auditing includes them.",
             "constant", "encoded PowerShell, Office spawning cmd/powershell, tools from Temp/Downloads", ["T1059"]),
    "4697": ("A service was installed in the system", "A new Windows service was registered (Security log view).",
             "software installs and driver updates", "random names, services running from Temp or user folders", ["T1543.003"]),
    "4698": ("A scheduled task was created", "A new scheduled task was registered.", "installers and updaters",
             "tasks that run scripts or binaries from user-writable folders", ["T1053.005"]),
    "4702": ("A scheduled task was updated", "An existing scheduled task changed.", "updaters",
             "a task's action changed to something unfamiliar", ["T1053.005"]),
    "4719": ("System audit policy was changed", "What Windows audits was changed.", "group policy updates",
             "auditing turned off right before other activity", ["T1562.002"]),
    "4720": ("A user account was created", "A new local or domain account exists.", "you made an account",
             "accounts you didn't create", ["T1136.001"]),
    "4722": ("A user account was enabled", "A disabled account was turned on.", "admin work", "old or built-in accounts re-enabled", ["T1098"]),
    "4724": ("An attempt was made to reset an account's password", "Someone reset (not changed) a password.", "helpdesk resets",
             "resets of admin accounts by unexpected users", ["T1098"]),
    "4725": ("A user account was disabled", "An account was turned off.", "admin work", "many accounts disabled at once", ["T1531"]),
    "4726": ("A user account was deleted", "An account was removed.", "admin work", "accounts deleted to cover tracks or lock you out", ["T1531"]),
    "4728": ("A member was added to a security-enabled global group", "Group membership changed (domain).", "admin work",
             "additions to Domain Admins or other privileged groups", ["T1098"]),
    "4732": ("A member was added to a security-enabled local group", "Local group membership changed, e.g. Administrators.",
             "admin work", "an account added to Administrators that you didn't add", ["T1098"]),
    "4738": ("A user account was changed", "Account properties changed (flags, password never expires...).", "admin work",
             "'password not required' or 'don't expire' set on an account", ["T1098"]),
    "4740": ("A user account was locked out", "Too many bad passwords; the account is locked.", "someone forgot a password",
             "repeated lockouts, or a caller computer you don't recognise", ["T1110"]),
    "4756": ("A member was added to a security-enabled universal group", "Group membership changed (domain).", "admin work",
             "additions to Enterprise Admins or other privileged groups", ["T1098"]),
    "4768": ("A Kerberos authentication ticket (TGT) was requested", "A domain logon started.", "constant on domain controllers",
             "failures, or requests without pre-authentication (AS-REP roasting)", []),
    "4769": ("A Kerberos service ticket was requested", "An account asked for access to a service.", "constant on domain controllers",
             "TicketEncryptionType 0x17 (RC4) for many services from one account: Kerberoasting", ["T1558.003"]),
    "4771": ("Kerberos pre-authentication failed", "Wrong password in a Kerberos logon.", "typos",
             "many in a short time (password guessing against the domain)", ["T1110"]),
    "4776": ("The computer attempted to validate the credentials for an account", "NTLM authentication.", "constant",
             "many failures (Status not 0x0) from one workstation", ["T1110"]),
    "4798": ("A user's local group membership was enumerated", "Something listed a user's groups.", "some management tools",
             "unknown processes enumerating many users", ["T1087"]),
    "4799": ("A security-enabled local group membership was enumerated", "Something listed a local group's members.",
             "some management tools", "net localgroup administrators run by an unknown process", ["T1087"]),
    "5140": ("A network share object was accessed", "Someone connected to a file share.", "file sharing",
             "ADMIN$ / C$ access from another machine (remote admin or lateral movement)", ["T1021.002"]),
    "5145": ("A network share object was checked for access", "Detailed file share access check.", "file sharing",
             "access to ADMIN$/C$ or many files from one source", ["T1021.002"]),
    "1102": ("The audit log was cleared", "The Security event log was emptied.", "rare: someone deliberately cleared it",
             "always worth confirming who did it and why", ["T1070.001"]),
    "104": ("An event log was cleared", "A log such as System was emptied.", "rare", "always worth confirming", ["T1070.001"]),
    "7045": ("A service was installed in the system", "A new Windows service was registered (System log view).",
             "software and driver installs", "unfamiliar names, image paths in Temp/AppData, cmd or powershell in the path",
             ["T1543.003", "T1569.002"]),
    "7034": ("A service terminated unexpectedly", "A service crashed.", "occasional", "repeated crashes, security software crashing", []),
    "7036": ("A service entered the running/stopped state", "Service start/stop.", "constant", "security services stopping", []),
    "7040": ("A service's start type was changed", "E.g. from automatic to disabled.", "updates",
             "Defender, firewall or logging services set to disabled", ["T1562.001"]),
    "6005": ("The Event Log service was started", "Marks a boot.", "every boot", "unexpected reboots", []),
    "6006": ("The Event Log service was stopped", "Marks a clean shutdown.", "every shutdown", "rarely", []),
    "6008": ("The previous system shutdown was unexpected", "The machine lost power or crashed.", "power cuts",
             "repeated: failing PSU, overheating, driver crashes", []),
    "41": ("Kernel-Power: rebooted without cleanly shutting down", "Power loss, hard reset or crash.", "power cuts",
           "repeated: check PSU, temperatures, BugCheck events", []),
    "1074": ("A process initiated a restart/shutdown", "Who or what shut the machine down, and why.", "updates, users",
             "shutdowns by unexpected processes", ["T1529"]),
    "1001": ("Windows Error Reporting / BugCheck", "A crash report; with BugCheck it's a blue screen and its stop code.",
             "rare", "repeated stop codes point at a driver or hardware", []),
    "1000": ("Application Error", "A program crashed; shows the faulting module.", "occasional",
             "the same program crashing repeatedly, or security tools crashing", []),
    "1002": ("Application Hang", "A program stopped responding and was closed.", "occasional", "repeated hangs", []),
    "1116": ("Microsoft Defender detected malware", "Defender found something.", "should be rare",
             "always: check the threat name, path and whether 1117 (action taken) followed", []),
    "1117": ("Microsoft Defender took action", "Defender quarantined/removed a threat.", "follows 1116",
             "action failed, or the same threat keeps coming back", []),
    "5001": ("Defender real-time protection was disabled", "Real-time scanning is off.", "rare",
             "always worth confirming", ["T1562.001"]),
    "5007": ("Defender configuration changed", "A Defender setting changed (incl. exclusions).", "updates",
             "new exclusions for folders or processes", ["T1562.001"]),
    "4103": ("PowerShell module logging", "PowerShell pipeline execution details.", "admin scripts",
             "download cradles, encoded commands", ["T1059.001"]),
    "4104": ("PowerShell script block logging", "The actual script text PowerShell ran.", "admin scripts",
             "obfuscation, IEX/DownloadString, AMSI bypass strings", ["T1059.001"]),
    "25": ("Volume Shadow Copy: shadow copies deleted (volsnap)", "Restore points / shadow copies were removed.",
           "low disk space can do this", "deletion right before mass file changes (ransomware pattern)", ["T1490"]),
    "10016": ("DCOM permission warning", "An app asked for a DCOM permission it doesn't have.", "very common, benign",
              "practically never", []),
}

SYSMON_EVENTS = {
    "1": ("Process creation", ["T1059"]), "3": ("Network connection", []), "7": ("Image (DLL) loaded", []),
    "8": ("CreateRemoteThread (code injected into another process)", ["T1055"]),
    "10": ("Process accessed another process (lsass access = credential dumping)", ["T1003.001"]),
    "11": ("File created", []), "13": ("Registry value set", ["T1112"]), "22": ("DNS query", ["T1071.004"]),
}

WINDOWS_FIELDS = {
    "TargetUserName": "the account that logged on / was acted on",
    "TargetDomainName": "domain (or computer name) of that account",
    "SubjectUserName": "the account that performed the action",
    "SubjectDomainName": "domain of the acting account",
    "LogonType": "how the logon happened (see logon types)",
    "IpAddress": "where the logon came from ('-' or ::1 = this machine)",
    "IpPort": "source port of the network connection",
    "WorkstationName": "name the client machine reported",
    "ProcessName": "program that requested the logon or action",
    "NewProcessName": "program that was started",
    "ParentProcessName": "program that started it",
    "CommandLine": "full command line (needs command-line auditing enabled)",
    "Status": "result code (see failure codes)", "SubStatus": "more specific result code",
    "FailureReason": "Windows' text for why it failed",
    "AuthenticationPackageName": "Negotiate/Kerberos/NTLM: NTLM from remote hosts deserves a second look",
    "LmPackageName": "NTLM version (NTLM V1 is weak)",
    "LogonProcessName": "component that handled the logon (User32 = interactive, NtLmSsp = NTLM)",
    "ServiceName": "service name", "ImagePath": "program the service runs: check where it lives",
    "ServiceType": "kernel driver / user-mode service", "StartType": "auto/demand/disabled",
    "AccountName": "account the service runs as",
    "TaskName": "scheduled task path", "MemberName": "account added/removed", "MemberSid": "SID of that account",
    "TargetSid": "SID of the account or group acted on", "CallerComputerName": "machine the bad passwords came from",
    "TicketEncryptionType": "Kerberos encryption (0x17 RC4 = weak, used in Kerberoasting)",
    "ServiceSid": "SID of the service", "PrivilegeList": "privileges granted to the session",
}

# ---------------------------------------------------------------- Linux / Unix
LINUX_PATTERNS = [  # (regex on "program: message", title, meaning, normal, worth a look when, [techniques])
    (r"sshd.*Failed (password|publickey) for (invalid user )?", "SSH login failed",
     "Someone tried to log in over SSH and was refused.", "a typo now and then",
     "many attempts, many user names, or 'invalid user' (the name doesn't exist): password guessing", ["T1110.001"]),
    (r"sshd.*Invalid user ", "SSH login for a user that doesn't exist",
     "A client tried a user name this machine doesn't have.", "rare from your own clients",
     "almost always internet scanners guessing names like admin, test, oracle", ["T1110.001"]),
    (r"sshd.*Accepted (password|publickey|keyboard-interactive)", "SSH login succeeded",
     "A user logged in over SSH. 'publickey' = key, 'password' = password.", "your own logins",
     "logins from unfamiliar IPs, password logins on internet-facing hosts, logins right after many failures",
     ["T1021.004", "T1078"]),
    (r"sshd.*(maximum authentication attempts exceeded|Too many authentication failures)", "SSH too many attempts",
     "A client hit MaxAuthTries in one connection.", "rare", "password guessing", ["T1110.001"]),
    (r"sshd.*(Disconnected from|Connection closed by|Received disconnect from).*\[preauth\]", "SSH connection closed before login",
     "A client connected and left without authenticating.", "internet background noise: scanners probing port 22",
     "huge volumes may justify fail2ban or moving SSH off the internet", []),
    (r"POSSIBLE BREAK-IN ATTEMPT", "SSH reverse DNS mismatch",
     "The client's IP doesn't reverse-resolve to the name it claims.", "misconfigured DNS",
     "worded alarmingly but usually not an attack on its own", []),
    (r"pam_unix\(.*\):? authentication failure", "PAM authentication failure",
     "A password check failed (login, sudo, su, ssh...). 'user=' names the account.", "typos",
     "repeated failures for one account", ["T1110"]),
    (r"pam_unix\(.*\):? session opened for user", "Session opened",
     "A login session (or cron/sudo session) started.", "constant", "sessions for unexpected users", []),
    (r"sudo.*COMMAND=", "sudo command run",
     "A user ran a command as root. Shows who (before ':'), where (TTY), and the command.", "admin work",
     "unexpected users, shells (COMMAND=/bin/bash), or commands that download/run scripts", ["T1548.003"]),
    (r"sudo.*(incorrect password attempts?|NOT in sudoers|authentication failure)", "sudo failure",
     "A user failed to get root via sudo.", "a typo",
     "users who aren't in sudoers trying anyway, repeated failures", ["T1548.003"]),
    (r"\bsu(\[\d+\])?:.*(FAILED SU|authentication failure)", "su failure", "Failed switch-user attempt.", "typos",
     "repeated attempts at root", ["T1548.003"]),
    (r"(useradd|adduser).*new user|groupadd.*new group", "User or group created",
     "A local account/group was added.", "you added one", "accounts you didn't create", ["T1136.001"]),
    (r"usermod.*(add .* to group|changed)|gpasswd", "User modified / added to group", "Account or group membership changed.",
     "admin work", "users added to sudo/wheel/adm/docker (all are root-equivalent or close)", ["T1098"]),
    (r"(passwd|chpasswd).*password changed", "Password changed", "A local password changed.", "you changed it",
     "changes you didn't make, especially for root", ["T1098"]),
    (r"(userdel|deluser).*delete user", "User deleted", "A local account was removed.", "admin work", "unexpected deletions",
     ["T1531"]),
    (r"crontab.*(REPLACE|BEGIN EDIT|END EDIT)", "crontab edited", "A user's scheduled jobs changed.", "you edited cron",
     "new jobs that download or run scripts from /tmp", ["T1053.003"]),
    (r"(CRON|crond).*CMD", "cron job ran", "A scheduled job ran.", "constant", "jobs you don't recognise", ["T1053.003"]),
    (r"systemd.*(Created symlink|Reloading)", "systemd units changed",
     "A unit was enabled or systemd reloaded its configuration.", "package installs, enabling services",
     "new units you didn't install (persistence)", ["T1543.002"]),
    (r"systemd.*(Failed with result|failed with result|Main process exited, code=)", "systemd unit failed",
     "A service exited with an error.", "occasional", "security services failing, or repeated failures", []),
    (r"systemd.*Scheduled restart job", "systemd restarting a service",
     "A service crashed and systemd is restarting it (Restart= in the unit).", "rare", "a high restart counter: a crash loop", []),
    (r"Out of memory: Killed process|oom-kill", "OOM killer", "The kernel ran out of memory and killed a process to survive.",
     "rare on healthy machines", "repeats: a memory leak or too little RAM/swap", []),
    (r"segfault at", "Segmentation fault", "A program crashed reading or writing memory it doesn't own.", "buggy software",
     "repeated crashes of network-facing services (possible exploitation attempts)", []),
    (r"I/O error|blk_update_request|Buffer I/O error", "Block device I/O error",
     "Reading or writing the disk/SD card failed.", "never on healthy hardware", "always: back up, check the drive", []),
    (r"EXT4-fs error|XFS.*(corrupt|error)|BTRFS.*error|remounting filesystem read-only", "Filesystem error",
     "The filesystem found inconsistencies.", "never on healthy systems", "always: run fsck, check the drive", []),
    (r"[Uu]nder-?voltage", "Under-voltage (Raspberry Pi)", "The Pi's supply voltage dipped below ~4.63 V.",
     "never with a good PSU", "always: weak PSU or cable; causes SD card corruption", []),
    (r"apparmor=\"DENIED\"|avc: +denied", "AppArmor / SELinux denial",
     "The security policy blocked an action.", "misconfigured software after updates",
     "denials for web servers or network services trying unusual files or exec", []),
    (r"UFW BLOCK|firewalld.*REJECT|IN=.*OUT=.*SRC=", "Firewall dropped a packet",
     "The firewall blocked a connection. SRC= is the sender, DPT= the port they tried.", "internet background noise",
     "many ports from one source (a port scan), or blocks of your own services", ["T1046"]),
    (r"usb .*: new .*USB device", "USB device connected", "A USB device was plugged in.", "you plugged something in",
     "devices nobody plugged in, keyboards appearing unexpectedly (HID attacks)", []),
    (r"(journal|rsyslogd).*(Vacuum|cleared|deleted|rotat)|logrotate", "Logs rotated or cleaned",
     "Old logs were compressed or deleted.", "daily logrotate / journald size limits",
     "logs deleted outside the normal schedule (covering tracks)", ["T1070.002"]),
    (r"Accepted .* for root|session opened for user root by \(uid=0\)", "Root session",
     "A root session started.", "sudo -i, cron jobs running as root", "direct root SSH logins (should be disabled)", ["T1078"]),
]
_LINUX_RX = [(re.compile(p, re.I), t, m, n, s, a) for p, t, m, n, s, a in LINUX_PATTERNS]

PROGRAMS = {
    "sshd": "OpenSSH server: remote logins over SSH",
    "sudo": "runs commands as root; logs who ran what",
    "su": "switch user", "login": "console login",
    "systemd": "init system: starts/stops services (units)", "systemd-logind": "tracks user logins and sessions",
    "systemd-journald": "the journal itself", "kernel": "the Linux kernel: hardware, drivers, memory, filesystems",
    "debian-sa1": "sysstat: records CPU/memory/disk statistics every 10 minutes (Debian/Ubuntu)",
    "sa1": "sysstat: records system activity statistics", "sadc": "sysstat data collector",
    "CRON": "scheduled jobs (cron)", "crond": "scheduled jobs (cron)", "cron": "scheduled jobs (cron)",
    "NetworkManager": "network connections (Wi-Fi, Ethernet, VPN)", "dbus-daemon": "desktop/system message bus",
    "polkitd": "authorises privileged actions for desktop apps", "audit": "Linux audit subsystem",
    "auditd": "Linux audit daemon", "rsyslogd": "classic syslog daemon", "chronyd": "time synchronisation",
    "firewalld": "firewall (Fedora/RHEL)", "ufw": "firewall (Ubuntu)", "dnf": "package manager (Fedora)",
    "apt": "package manager (Debian/Ubuntu)", "nginx": "web server", "httpd": "Apache web server",
    "apache2": "Apache web server", "dockerd": "Docker engine", "containerd": "container runtime",
    "Service Control Manager": "Windows component that starts/stops services",
    "Microsoft-Windows-Security-Auditing": "Windows security auditing (logons, accounts, policy)",
    "Microsoft-Windows-Kernel-Power": "Windows power state (sleep, shutdown, power loss)",
    "Microsoft-Windows-WHEA-Logger": "Windows hardware error architecture: CPU/memory/PCIe errors",
    "Application Error": "Windows crash reporter for programs", "Microsoft-Windows-Windows Defender": "Microsoft Defender antivirus",
    "EventLog": "the Windows Event Log service", "volsnap": "Volume Shadow Copy (restore points)",
    "Ntfs": "NTFS filesystem driver", "disk": "disk driver", "Microsoft-Windows-Sysmon": "Sysmon: detailed process/network telemetry",
    "Microsoft-Windows-PowerShell": "PowerShell engine logging",
}

JOURNAL_FIELDS = {
    "_PID": "process id", "_UID": "user id the process ran as (0 = root)", "_COMM": "process name",
    "_EXE": "program path", "_CMDLINE": "full command line", "_SYSTEMD_UNIT": "service (unit) that wrote it",
    "SYSLOG_IDENTIFIER": "program tag", "_TRANSPORT": "how it reached the journal (kernel, syslog, stdout, journal)",
    "PRIORITY": "severity 0-7 (0 = emergency, 7 = debug)", "_HOSTNAME": "machine name", "pid": "process id",
}

SEVERITIES = {
    "emerg": "0 emergency: system unusable", "alert": "1 alert: act immediately", "crit": "2 critical",
    "err": "3 error", "warning": "4 warning", "notice": "5 notice: normal but significant", "info": "6 informational",
    "debug": "7 debug",
}


# Entries whose occurrence is itself notable get their techniques *mapped* (finding tags, coverage matrix).
# All others (a 4624 logon, a cron run, a sudo command) only show techniques as context on the reference card:
# the event is how the technique would appear, not evidence that it happened.
STRONG_WINDOWS = {"4625", "4720", "4722", "4724", "4725", "4726", "4728", "4732", "4738", "4740", "4756", "4771",
                  "4697", "7045", "4698", "4702", "4719", "1102", "104", "5001", "5007", "25"}
STRONG_LINUX = {"SSH login failed", "SSH login for a user that doesn't exist", "SSH too many attempts",
                "PAM authentication failure", "sudo failure", "su failure", "User or group created",
                "User modified / added to group", "Password changed", "User deleted", "crontab edited"}

# ---------------------------------------------------------------- lookups
def windows_entry(event_id: str, program: str = "", source: str = "") -> dict | None:
    if not event_id:
        return None
    if "sysmon" in (program or "").lower() and event_id in SYSMON_EVENTS:
        t, a = SYSMON_EVENTS[event_id]
        return {"kind": "windows", "id": event_id, "title": "Sysmon " + event_id + ": " + t, "attack": a,
                "strong": event_id in ("8", "10")}
    if event_id in WINDOWS_EVENTS:
        t, m, n, s, a = WINDOWS_EVENTS[event_id]
        if event_id == "25" and "volsnap" not in (program or "").lower():
            return None  # 25 is only the shadow-copy event for volsnap
        return {"kind": "windows", "id": event_id, "title": t, "meaning": m, "normal": n, "suspicious": s, "attack": a,
                "strong": event_id in STRONG_WINDOWS}
    return None


def linux_entries(program: str, message: str) -> list[dict]:
    text = f"{program}: {message}"[:2000]
    return [{"kind": "linux", "title": t, "meaning": m, "normal": n, "suspicious": s, "attack": a, "strong": t in STRONG_LINUX}
            for rx, t, m, n, s, a in _LINUX_RX if rx.search(text)]


def references(cluster: dict) -> list[dict]:
    """Reference entries for a cluster: Windows event ID (Windows sources only) and Linux message patterns."""
    out = []
    if str(cluster.get("source", "")).startswith("windows"):
        w = windows_entry(str(cluster.get("event_id") or ""), cluster.get("program", ""), cluster.get("source", ""))
        if w:
            out.append(w)
    else:
        sample = (cluster.get("samples") or [cluster.get("template", "")])[0]
        out += linux_entries(cluster.get("program", ""), sample)
    return out


# A successful remote login is only ATT&CK evidence when it comes from outside the local network;
# your own SSH/RDP from the LAN is routine.
EXTERNAL_ONLY = {"lx_ssh_accepted", "win_rdp_logon"}
_IP_IN_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _from_outside(cluster: dict) -> bool:
    from .iocs import _ip_scope
    text = " ".join(cluster.get("samples") or []) + " " + " ".join(str(v) for v in (cluster.get("fields") or {}).values())
    return any(_ip_scope(ip) in ("public", "reserved") for ip in _IP_IN_TEXT.findall(text))


def attack_for(cluster: dict) -> list[str]:
    """Mapped techniques for a cluster: from its rule, then from reference entries that are notable in themselves."""
    ids: list[str] = []
    rule = cluster.get("rule") or {}
    if rule.get("id") not in EXTERNAL_ONLY or _from_outside(cluster):
        ids += RULE_ATTACK.get(rule.get("id", ""), []) + list(rule.get("attack") or [])
    for ref in references(cluster):
        if ref.get("strong"):
            ids += ref.get("attack", [])
    return [t for t in dict.fromkeys(ids) if t in TECHNIQUES or re.fullmatch(r"T\d{4}(\.\d{3})?", t)]


def reference_catalog() -> dict:
    """Everything, for the dashboard's Reference view and hover cards."""
    return {
        "tactics": [{"id": i, "name": n} for i, n in TACTICS],
        "techniques": {k: {"name": n, "tactics": t, "url": attack_url(k)} for k, (n, t) in TECHNIQUES.items()},
        "windows": [{"id": k, "title": t, "meaning": m, "normal": n, "suspicious": s, "attack": a}
                    for k, (t, m, n, s, a) in WINDOWS_EVENTS.items()],
        "sysmon": [{"id": k, "title": t, "attack": a} for k, (t, a) in SYSMON_EVENTS.items()],
        "linux": [{"pattern": p, "title": t, "meaning": m, "normal": n, "suspicious": s, "attack": a}
                  for p, t, m, n, s, a in LINUX_PATTERNS],
        "logon_types": [{"id": k, "name": n, "meaning": m} for k, (n, m) in LOGON_TYPES.items()],
        "status_codes": [{"code": k, "meaning": v} for k, v in STATUS_CODES.items()],
        "programs": PROGRAMS, "windows_fields": WINDOWS_FIELDS, "journal_fields": JOURNAL_FIELDS,
        "severities": SEVERITIES,
    }
