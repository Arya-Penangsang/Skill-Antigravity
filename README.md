# 🛡️ Skill-Antigravity: Complete Cybersecurity & Threat Operations Suite

<p align="center">
  <b>English</b> • <a href="README.id.md">Bahasa Indonesia</a>
</p>

[![Author: Arya Penangsang](https://img.shields.io/badge/Author-Arya%20Penangsang-blue.svg)](https://github.com/Arya-Penangsang)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![PHP 8.0+](https://img.shields.io/badge/PHP-8.0+-777BB4.svg?logo=php&logoColor=white)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20%26%20Web-red.svg)](https://attack.mitre.org/)
[![NIST Compliance](https://img.shields.io/badge/NIST-SP%20800--86%20%7C%20800--115-green.svg)](https://csrc.nist.gov/)
[![OWASP Aligned](https://img.shields.io/badge/OWASP-Top%2010%20%7C%20ASVS%20v4.0-orange.svg)](https://owasp.org/)
[![AI-Agent Ready](https://img.shields.io/badge/AI--Agent-Antigravity%20Ready-purple.svg)](#-integration-with-google-antigravity)

**Skill-Antigravity** is the official comprehensive cybersecurity and threat operations skillset repository built for **Google Antigravity AI Agents** and professional security analysts.

Authored by **Arya Penangsang** ([@Arya-Penangsang](https://github.com/Arya-Penangsang)), this repository bridges the full spectrum of modern cyber defense and offensive security: **Offensive Operations (Red Team)**, **Defensive Hardening (Blue Team)**, **Continuous Validation (Purple Team)**, **Digital Forensics & Incident Response (DFIR)**, **Automated Malware Sandboxing & Quarantine Vault**, and **Multi-Target Binary Reverse Engineering (REA)**.

📄 **Full Documentation (Executive Summary PDF):**  
[Download Ringkasan_Skill_Cybersecurity_Antigravity.pdf](Ringkasan_Skill_Cybersecurity_Antigravity.pdf)

---

## 🏛️ Architecture & Taxonomy

```text
Skill-Antigravity/
├── Ringkasan_Skill_Cybersecurity_Antigravity.pdf # Official Executive Summary Report (7 Pages)
├── sandbox_cli.py                              # Main Automated Malware Sandbox CLI
├── core/                                       # Core Malware Sandbox & Quarantine Vault Engine
├── docs/                                       # Technical Documentation & Curriculum
├── skills/
│   ├── malware-triage/                         # 🦠 Malware Analysis, Shannon Entropy, Vault & NIST DFIR
│   ├── digital-forensics/                      # 🕵️ DFIR Disk Carving, RAM Volatility, USB & Sigma Rules
│   ├── infra-red-teaming/                      # ⚔️ Network Scanning, PrivEsc, SMB/SNMP & CEH v11
│   ├── web-purple-teaming/                     # 🟣 Continuous Detection Validation & Triad Orchestrator
│   ├── web-red-teaming/                        # 🔴 Web Penetration Testing (OWASP Top 10 / ASVS)
│   ├── web-blue-teaming/                       # 🔵 Server Hardening, CIS Benchmarks & WAF
│   └── reverse-engineer-anything/              # 🔬 Multi-Architecture Binary Decompilation & Frida Instrumentation
```

---

## 📦 Skillset Catalog & Core Capabilities

### 1. 🦠 Malware Triage & DFIR Sandbox (`skills/malware-triage`)
* **Reference Standards:** NIST SP 800-86, MITRE ATT&CK for Enterprise.
* **Core Capabilities:**
  * **Static PE Triage:** MD5, SHA1, SHA256, Imphash, and PE memory mitigations (ASLR, DEP, SafeSEH).
  * **Shannon Entropy Analysis ($0.0 - 8.0$):** High-precision payload compression and encryption detection (UPX, Themida, VMProtect).
  * **Quarantine Vault Engine:** Safely neutralizes malicious binaries into `.quarantined` stream masked files via XOR encryption (`0x5A`).
  * **Dynamic Behavior & Registry Diff:** Detects Run/RunOnce persistence mechanisms and tracks dropped files in `%TEMP%` / `%APPDATA%`.
  * **C2 Network Sinkhole:** Captures HTTP/DNS beacons and formats structured audit logs mapped to the 4 NIST incident phases.
  * **Automated YARA Rule Generator:** Automatically synthesizes production-ready detection rules.
* **CLI Usage:**
  ```bash
  python sandbox_cli.py "sample.exe" --dynamic --timeout 15 --reg-diff --sinkhole --quarantine --outdir reports
  ```

---

### 2. 🕵️ Digital Forensics & Incident Response (`skills/digital-forensics`)
* **Reference Standards:** NIST SP 800-86, ISO/IEC 27037, RFC 3227 (*Order of Volatility*).
* **Core Capabilities:**
  * **Automated File Carving:** Extracts deleted and hidden files from raw disk images (`.raw`, `.dd`, `.001`, `.E01`) using file header/footer magic bytes (JPEG, PDF, ZIP, Office, PE MZ).
  * **RAM Memory Forensics:** Process reconstruction via Volatility 3 (`windows.pslist`, `pstree`), hidden injected code detection (`malfind`), and socket inspection (`netscan`).
  * **USB Artifact Auditing (USBSTOR Forensics):** Parses Windows registry `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` to investigate unauthorized data exfiltration (*insider threat*).
  * **Windows Event Log Forensics:** Analyzes critical Event IDs: 4624 (Logon), 4625 (Brute Force), 4688 (Process Creation), 7045 (Service Install), and 1102 (Log Cleared).
  * **Sigma YAML Generator:** Generates vendor-agnostic detection rules for SIEM and EDR deployments.
* **CLI Usage:**
  ```bash
  python skills/digital-forensics/scripts/forensic_triage.py --audit-usb
  python skills/digital-forensics/scripts/forensic_triage.py --carve evidence.raw --outdir carved_files
  python skills/digital-forensics/scripts/forensic_triage.py --gen-sigma --title "Ransomware Detection" --process "vssadmin.exe delete shadows"
  ```

---

### 3. ⚔️ Infrastructure Red Teaming & CEH (`skills/infra-red-teaming`)
* **Reference Standards:** CEH (Certified Ethical Hacker v10/v11), NIST SP 800-115, MITRE ATT&CK for Enterprise.
* **Core Capabilities:**
  * **High-Speed Multi-Threaded Port Scanner:** Fast TCP socket scanning with service banner grabbing.
  * **Firewall Evasion Scanning:** Implements stealth TCP SYN (`-sS`), TCP ACK (`-sA`), and Inverse TCP (Xmas, Null, FIN) packet scans following RFC 793.
  * **Local Privilege Escalation (LPE) Auditor:** Audits Linux SUID / POSIX capabilities and Windows Token Manipulation misconfigurations (`SeImpersonatePrivilege` / Potato family).
  * **SMB & Service Enumeration:** Checks for Null Session access on `IPC$` (Port 445/139) and SNMP MIB walking (Port 161).
  * **MITM Simulation:** ARP Spoofing and LLMNR/NBT-NS credential poisoning via Responder.
* **CLI Usage:**
  ```bash
  python skills/infra-red-teaming/scripts/infra_audit.py --scan 192.168.1.1 --ports 21,22,80,443,445,3389
  python skills/infra-red-teaming/scripts/infra_audit.py --audit-privesc
  python skills/infra-red-teaming/scripts/infra_audit.py --smb-check 192.168.1.50
  ```

---

### 4. 🟣 Web Purple Teaming & Continuous Validation (`skills/web-purple-teaming`)
* **Reference Standards:** MITRE ATT&CK for Web Applications, NIST CSF 2.0.
* **Core Capabilities:**
  * **4-Phase Orchestration Cycle:** *Threat Emulation* ➔ *Detection Validation* ➔ *Remediation Tuning* ➔ *Regression Testing*.
  * **Triad Orchestrator Script:** Simultaneously runs Red Team attack simulations alongside Blue Team SIEM/WAF detection checks.
  * **Threat Resistance Score:** Quantitatively scores defensive posture resilience.
* **CLI Usage:**
  ```bash
  php skills/web-purple-teaming/scripts/purple_orchestrator.php --path="/path/to/project" --target-url="http://target:port"
  ```

---

### 5. 🔴 Web Red Teaming (`skills/web-red-teaming`)
* **Reference Standards:** OWASP Top 10:2021, OWASP ASVS v4.0.
* **Core Capabilities:**
  * Automated injection vulnerability scanning: SQL Injection (SQLi), Cross-Site Scripting (XSS), IDOR, SSRF, and CSRF.
  * Sensitive file exposure detection: `.env`, `.git`, `.htaccess`, and `.sql` database dumps.
  * Backdoor, PHP trojan, and CVE detection via `scan_webshell_cve.php`.
* **CLI Usage:**
  ```bash
  php skills/web-red-teaming/scripts/audit_target.php --url="http://localhost:8080"
  php skills/web-red-teaming/scripts/scan_webshell_cve.php --dir="/var/www/html"
  ```

---

### 6. 🔵 Web Blue Teaming (`skills/web-blue-teaming`)
* **Reference Standards:** CIS Benchmarks, OWASP Defense in Depth, BSSN.
* **Core Capabilities:**
  * Web application server security hardening audits (PHP, Apache, Nginx).
  * HTTP Security Headers enforcement: Content Security Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options.
  * Media upload directory sandboxing (prevention of malicious binary/PHP execution).
* **CLI Usage:**
  ```bash
  php skills/web-blue-teaming/scripts/hardening_checker.php --path="/path/to/project"
  ```

---

### 7. 🔬 Reverse Engineer Anything (`skills/reverse-engineer-anything`)
* **Reference Standards:** Binary Static & Dynamic Reverse Engineering Standards.
* **Core Capabilities:**
  * Multi-architecture binary analysis: x86/x64, ARM, PE (Windows), ELF (Linux), and Mach-O (macOS).
  * Managed & Web Applications: .NET CLR assemblies, Go, Rust, Java/DEX, Electron ASAR, and Webpack JS bundles.
  * Dynamic Instrumentation Engine: Runtime function memory hooking powered by the Frida toolkit.

---

## 🚀 Integration with Google Antigravity

To enable this entire cybersecurity skillset directly in your Antigravity AI assistant:

1. **Copy Skills to Antigravity Configuration Directory:**
   ```bash
   cp -r skills/* ~/.gemini/config/skills/
   ```
2. **Start a New Antigravity Session:**
   Antigravity will automatically discover all 7 skills and invoke them on demand during penetration testing, security auditing, malware analysis, or incident forensics tasks.

---

## 👨‍💻 Contributors & License

* **Lead Security Researcher & Creator:** **Arya Penangsang** ([@Arya-Penangsang](https://github.com/Arya-Penangsang))
* **AI Security Pair:** Google Antigravity
* **License:** This project is licensed under the [MIT License](LICENSE).
