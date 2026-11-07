# LinkedIn post

Attach `LogIngestLLM-carousel.pdf` as a document (title it "SOC co-pilot that runs on my laptop"). Post the link in
the first comment, not in the post (LinkedIn shows posts with external links to fewer people). Publish after the
v0.2.0 release is live so the downloads exist.

---

I built a SOC co-pilot that runs entirely on my laptop. No cloud, no API keys, and every claim links to the exact log line behind it.

The logs you most need help with are the ones you can't paste into a chatbot: usernames, hostnames, internal IPs, command lines. So I built LogIngestLLM, a local log analyzer running on an AI model I fine-tuned myself.

What it does:
→ Reads Windows Event Logs (including exported .evtx, natively on Linux and macOS), journald/syslog, web and app logs
→ Groups thousands of lines into patterns and scores them with ~65 detection rules, Sigma rules and attacker-tool signatures
→ My model triages each pattern: how much it matters, why, and what to do
→ Maps findings to MITRE ATT&CK, pulls out indicators, shows where attacker tools ran from, and builds a timeline and a cited incident report

Example: the bundled Windows sample. It flags the LSASS memory dump (rundll32 + comsvcs.dll MiniDump at 09:11:40 UTC) and ties it to what came before and after: five failed logons from one IP, a certutil download, a new admin account and a cleared Security log. One click opens the exact record behind each claim.

The part I'm proudest of is the guardrails. A 4B model is fluent, not infallible, so:
1. Every claim cites a numbered log line you can open.
2. If the model names a tool that doesn't appear in the log, it's dropped.
3. Known-answer test cases, including a healthy machine that must stay quiet, gate every change. They caught real problems: a routine LAN login mapped to an ATT&CK technique, the model suggesting "stop sshd" on a machine you reach over SSH, and citations to events that didn't exist.

The model is Qwen3-4B with a QLoRA adapter, trained in 44 minutes on a laptop RTX 4060. Exact triage accuracy on held-out logs went from 34% (base) to 67% (v1) to 92% (v2), and v2 passes 95 of 96 end-to-end checks. A new version only ships if it beats the current one.

It's a single download for Windows, macOS and Linux. Unzip, double-click, and the AI runs inside the app, even with the network unplugged.

Code and downloads are in the first comment. What should it detect next?

#cybersecurity #SOC #blueteam #DFIR #threathunting #infosec #LLM

---

## First comment

Code, docs and downloads (Windows, macOS, Linux): https://github.com/<owner>/LogIngestLLM
Built with Python's standard library, llama.cpp and Qwen3-4B (Apache 2.0). Try the five bundled example investigations first, then point it at your own logs.
