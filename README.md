# 🛡️ Antigravity Malware Sandbox & Automated Triage Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red.svg)](https://attack.mitre.org/)
[![AI-Agent Ready](https://img.shields.io/badge/AI--Agent-Ready-purple.svg)](#-agent-skill-integration)

A lightweight, zero-configuration automated malware triage and behavioral analysis engine designed for security analysts, incident responders, and AI coding agents. 

Inspired by classical malware analysis methodologies (*Practical Malware Analysis* by Sikorski & Honig) and modern automated sandboxing (*Cuckoo Sandbox*), this engine provides instant static triage, PE section entropy analysis, MITRE ATT&CK capability mapping, isolated dynamic behavioral monitoring, and auto-generates actionable **YARA detection rules** alongside a visual **interactive HTML dashboard**.

---

## ✨ Key Features

- ⚡ **Instant Static Triage:** Computes cryptographic hashes (MD5, SHA-1, SHA-256), Import Hash (`imphash`), and inspects PE headers, ASLR, DEP/NX, and SafeSEH flags.
- 📐 **Shannon Entropy Section Analysis:** Calculates mathematical entropy ($0.0 - 8.0$) across PE sections to reliably identify packed or encrypted binaries (UPX, Themida, ASPack, MPRESS).
- 🎯 **MITRE ATT&CK Behavioral Mapping:** Automatically categorizes Import Address Table (IAT) calls into attack techniques:
  - *Process Injection (`T1055`)*
  - *Anti-Debugging & Sandbox Evasion (`T1497 / T1622`)*
  - *Persistence Mechanisms (`T1547 / T1543`)*
  - *Input Capture & Keylogging (`T1056.001`)*
  - *C2 / Downloader Operations (`T1071 / T1105`)*
  - *Ransomware Cryptography (`T1486`)*
- 🔬 **Dynamic Behavioral Sandbox:** Bounded, controlled execution monitoring child process trees (`psutil`), temporary file drops in `%TEMP%`, and registry `Run`/`RunOnce` persistence diffing (Regshot methodology).
- 📝 **Automated YARA Rule Generation:** Automatically synthesizes custom, syntax-valid YARA detection rules tailored to the analyzed sample.
- 📊 **Multi-Format Reporting:** Produces both an **Interactive Dark-Theme HTML Dashboard** and a structured **JSON report** ready for SIEM / EDR ingestion.
- 🤖 **AI-Agent Ready:** Bundled with an official `SKILL.md` for seamless integration into agentic workflows (Antigravity, Cursor, Claude Code).

---

## 🚀 Quick Start

### 1. Installation
Clone the repository and install the lightweight dependencies:
```bash
git clone https://github.com/nafik-cs/antigravity-malware-sandbox.git
cd antigravity-malware-sandbox
pip install -r requirements.txt
```

### 2. Run Static Triage
Perform a deep static triage and generate reports in seconds:
```bash
python sandbox_cli.py "C:\path\to\sample.exe"
```

### 3. Run Dynamic Behavioral Analysis
Execute the sample in a controlled, monitored sandbox window (e.g. 15 seconds):
```bash
python sandbox_cli.py "C:\path\to\sample.exe" --dynamic --timeout 15 --outdir reports
```

All analysis artifacts are saved in the `reports/` directory:
- `reports/<sample>_report.html` (Interactive visual dashboard)
- `reports/<sample>_report.json` (Machine-readable SIEM log)
- `reports/<sample>_rule.yar` (Auto-generated YARA detection signature)

---

## 🔬 Real-World Showcase: In-Memory Triage Case Study

Included in the [`examples/`](examples/) directory is a real-world case study triaging an unverified activation binary (`KMSAuto++ x64.exe`, 40.9 MB) extracted safely via in-memory streaming:

| Metric | Result |
| :--- | :--- |
| **Threat Score** | 🔥 **`100 / 100`** (`MALICIOUS`) |
| **Architecture** | AMD64 (64-bit x64 PE) |
| **SHA-256** | `4eb7d3d117382ee6935ee6d3e5902e44523e7529455e9a3d3c9daf035fa507ac` |
| **Imphash** | `3b4bcc6db16a1a25e1c9cd8e1cf93242` |
| **MITRE Techniques** | • *T1056.001 (Input Capture / Keylogging)*: `SetWindowsHookEx`, `GetAsyncKeyState`<br>• *T1547 / T1543 (Persistence)*: `CreateService`, `RegSetValueEx`<br>• *T1497 (Anti-Debugging Evasion)*: `CheckRemoteDebuggerPresent`<br>• *T1071 / T1105 (C2 Downloader)*: `InternetOpen`, `URLDownloadToFile` |

- 📊 **[View Sample HTML Dashboard](examples/sample_triage_report.html)**
- 📝 **[View Generated YARA Rule](examples/sample_detection.yar)**
- 📋 **[View Structured JSON Report](examples/sample_triage_report.json)**

---

## 🤖 Agent Skill Integration

This repository includes a native agent skill located in `skills/malware-triage/SKILL.md`.

You can mount this skill into your AI coding assistant (Antigravity, Cursor, or Claude Code) by copying it to your agent's skills directory:
```bash
cp -r skills/malware-triage ~/.gemini/config/skills/
```

Once loaded, you can ask your AI agent naturally:
> *"Triage this suspicious binary using the malware-triage skill and generate a YARA rule for our SOC."*

---

## 📊 Sample Threat Scoring

| Score Range | Verdict | Interpretation |
| :--- | :--- | :--- |
| **0 – 29** | `CLEAN / BENIGN` | Standard software without suspicious behavioral capabilities. |
| **30 – 59** | `SUSPICIOUS` | Packed sections, potentially unwanted behaviors, or evasion techniques. |
| **60 – 100** | `MALICIOUS` | High-risk capabilities (Process injection, keylogging hooks, persistence). |

---

## 🧪 Testing

Run unit tests with pytest:
```bash
pip install pytest
pytest tests/
```

---

## ⚖️ Disclaimer

This project is developed strictly for **educational, defensive security research, and authorized malware triage purposes only**. The authors assume no liability for misuse or damage caused by analyzing malicious samples. Always execute untrusted software in an isolated virtualized environment.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
