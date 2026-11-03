# 🛡️ Antigravity Malware Sandbox & Automated Triage Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red.svg)](https://attack.mitre.org/)
[![AI-Agent Ready](https://img.shields.io/badge/AI--Agent-Ready-purple.svg)](#-agent-skill-integration)

A lightweight, zero-configuration automated malware triage and behavioral analysis engine designed for security analysts, incident responders, and AI coding agents. 

Inspired by classical malware analysis methodologies (*Practical Malware Analysis* by Sikorski & Honig), modern automated sandboxing (*Cuckoo Sandbox*), and Indonesian cybersecurity training curricula (*Syai Labs*), this engine provides instant static triage, PE section entropy analysis, MITRE ATT&CK capability mapping, isolated dynamic behavioral monitoring, local C2 network sinkholing, registry differential tracking, and auto-generates actionable **YARA detection rules** alongside a visual **interactive HTML dashboard**.

---

## ✨ Key Features & Architecture

- ⚡ **Instant Static Triage:** Computes cryptographic hashes (MD5, SHA-1, SHA-256), Import Hash (`imphash`), and inspects PE headers, ASLR, DEP/NX, and SafeSEH flags.
- 📐 **Shannon Entropy Section Analysis:** Calculates mathematical entropy ($0.0 - 8.0$) across PE sections to reliably identify packed or encrypted binaries (UPX, Themida, ASPack, MPRESS).
- 📦 **Packer & Compiler Detection (`core/packer_detector.py`):** Identifies runtime environments (.NET CLR, Go, Rust, GCC/MinGW, MSVC) and common packers (UPX, Themida, ASPack, MPRESS, VMProtect) inspired by Detect It Easy (DIE).
- 🎯 **MITRE ATT&CK Behavioral Mapping:** Automatically categorizes Import Address Table (IAT) calls into attack techniques:
  - *Process Injection (`T1055`)*
  - *Anti-Debugging & Sandbox Evasion (`T1497 / T1622`)*
  - *Persistence Mechanisms (`T1547 / T1543`)*
  - *Input Capture & Keylogging (`T1056.001`)*
  - *C2 / Downloader Operations (`T1071 / T1105`)*
  - *Ransomware Cryptography (`T1486`)*
- 🔬 **Dynamic Behavioral Sandbox:** Bounded, controlled execution monitoring child process trees (`psutil`), temporary file drops in `%TEMP%`, and registry `Run`/`RunOnce` persistence diffing.
- 🗄️ **Registry Differential Engine (`core/registry_diff.py`):** Pre- and post-execution snapshot comparison (Regshot technique) to catch sneaky autoruns across `HKCU` and `HKLM`.
- 🌐 **Network Sinkhole & C2 Simulator (`core/network_sinkhole.py`):** Emulates local C2 HTTP listeners (ApateDNS & INetSim technique) to capture beacons and exfiltration attempts safely.
- 📝 **Automated YARA Rule Generation:** Automatically synthesizes custom, syntax-valid YARA detection rules tailored to the analyzed sample.
- 📊 **Multi-Format Reporting:** Produces both an **Interactive Dark-Theme HTML Dashboard** and a structured **JSON report** ready for SIEM / EDR ingestion.
- 🤖 **AI-Agent Ready:** Bundled with an official `SKILL.md` for seamless integration into agentic workflows (Antigravity, Cursor, Claude Code).

---

## 📚 Community & Educational Resources

We have packaged open learning materials inspired by top-tier Indonesian cybersecurity workshops:

* 🎓 **[Kurikulum Terbuka Analisis Malware Indonesia (Full Curriculum)](docs/MALWARE_ANALYSIS_CURRICULUM_ID.md)**  
  Silabus komprehensif 5 modul mulai dari struktur PE, triage statis, analisis dinamis, reverse engineering assembly, hingga rekayasa YARA.
* 🔍 **[Writeup Reverse Engineering: CrackMe 1.0](docs/CRACKME_REVERSE_ENGINEERING_WRITEUP.md)**  
  Panduan praktis langkah-demi-langkah membongkar biner .NET CLR, deobfuscation user strings `#US`, dan binary patching bypass.
* 🏗️ **[Blueprint Setup Lab Terisolasi (Air-Gapped Sandbox)](docs/ISOLATED_SANDBOX_BLUEPRINT.md)**  
  Arsitektur lab aman menggunakan FLARE VM, REMnux/Kali Linux dengan simulasi gateway INetSim dan snapshot lifecycle.

---

## 🚀 Quick Start

### 1. Installation
Clone the repository and install the lightweight dependencies:
```bash
git clone https://github.com/nafik-cs/antigravity-malware-sandbox.git
cd antigravity-malware-sandbox
pip install -r requirements.txt
```

### 2. Run Static Deep Triage
Perform a deep static triage and generate reports in seconds:
```bash
python sandbox_cli.py "C:\path\to\sample.exe"
```

### 3. Run Full Dynamic Behavioral Sandbox with Registry Diff & Sinkhole
Execute the sample in a controlled, monitored sandbox with C2 simulation and registry diffing:
```bash
python sandbox_cli.py "C:\path\to\sample.exe" --dynamic --timeout 15 --reg-diff --sinkhole --outdir reports
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

Run unit tests:
```bash
python -m unittest discover tests
```

---

## 🙏 Credits & Special Dedication

Special dedication and credits to **Yohanes Syailendra Kotualubun, M.Kom, CEH, ECSA, CCNA (Pak Syai)**:
* Senior Cybersecurity Consultant & Threat Hunter.
* Researcher at **Indonesia Honeynet Project (IHP)** — Malware Stream.
* 3-time Winner of **Cyber Defence Competition Kementerian Pertahanan RI (Kemhan)** (2013, 2014, 2015).
* Faculty Member at Swiss German University (SGU).

His foundational workshop materials and hands-on lab methodology (**Syai Labs**) served as a direct inspiration for the architecture, educational documentation, and triage techniques implemented in this project.

---

## ⚖️ Disclaimer

This project is developed strictly for **educational, defensive security research, and authorized malware triage purposes only**. The authors assume no liability for misuse or damage caused by analyzing malicious samples. Always execute untrusted software in an isolated virtualized environment.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
