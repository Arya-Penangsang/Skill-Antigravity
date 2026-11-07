# 🛡️ Skill-Antigravity: Complete Cybersecurity & Threat Operations Suite

<p align="center">
  <img src="docs/skill-antigravity-banner.svg" alt="Skill-Antigravity Banner" width="100%">
</p>

<p align="center">
  <a href="README.md">English</a> • <b>Bahasa Indonesia</b>
</p>

[![Author: Arya Penangsang](https://img.shields.io/badge/Author-Arya%20Penangsang-blue.svg)](https://github.com/Arya-Penangsang)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![PHP 8.0+](https://img.shields.io/badge/PHP-8.0+-777BB4.svg?logo=php&logoColor=white)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20%26%20Web-red.svg)](https://attack.mitre.org/)
[![NIST Compliance](https://img.shields.io/badge/NIST-SP%20800--86%20%7C%20800--115-green.svg)](https://csrc.nist.gov/)
[![OWASP Aligned](https://img.shields.io/badge/OWASP-Top%2010%20%7C%20ASVS%20v4.0-orange.svg)](https://owasp.org/)
[![AI-Agent Ready](https://img.shields.io/badge/AI--Agent-Antigravity%20Ready-purple.svg)](#-integrasi-ke-google-antigravity)

**Skill-Antigravity** adalah repositori resmi kumpulan modul dan keahlian (*skillset*) keamanan siber komprehensif untuk **Google Antigravity AI Agent** dan analis keamanan profesional. 

Dikembangkan oleh **Arya Penangsang** ([@Arya-Penangsang](https://github.com/Arya-Penangsang)), repositori ini menggabungkan seluruh spektrum pertahanan dan pengujian keamanan siber modern: **Offensive Operations (Red Team)**, **Defensive Hardening (Blue Team)**, **Continuous Validation (Purple Team)**, **Digital Forensics & Incident Response (DFIR)**, **Automated Malware Sandboxing & Quarantine Vault**, serta **Multi-Target Binary Reverse Engineering (REA)**.

📄 **Dokumentasi Lengkap (PDF Ringkasan Eksekutif):**  
[Unduh Ringkasan_Skill_Cybersecurity_Antigravity.pdf](Ringkasan_Skill_Cybersecurity_Antigravity.pdf)

---

## 🏛️ Arsitektur & Taksonomi Modul Keamanan

```text
Skill-Antigravity/
├── Ringkasan_Skill_Cybersecurity_Antigravity.pdf # Laporan Eksekutif Resmi (7 Halaman)
├── sandbox_cli.py                              # CLI Utama Automated Malware Sandbox
├── core/                                       # Core Engine Malware Sandbox & Quarantine Vault
├── docs/                                       # Kurikulum & Dokumentasi Teknis
├── skills/
│   ├── malware-triage/                         # 🦠 Analisis Malware, Entropi, Vault & NIST DFIR
│   ├── digital-forensics/                      # 🕵️ DFIR Disk Carving, RAM Volatility, USB & Sigma
│   ├── infra-red-teaming/                      # ⚔️ Network Scanning, PrivEsc, SMB/SNMP & CEH v11
│   ├── web-purple-teaming/                     # 🟣 Validasi Deteksi Kontinu & Orkestrator Triad
│   ├── web-red-teaming/                        # 🔴 Web Penetration Testing (OWASP Top 10 / ASVS)
│   ├── web-blue-teaming/                       # 🔵 Hardening Server, CIS Benchmarks & WAF
│   └── reverse-engineer-anything/              # 🔬 Decompilasi Biner & Instrumentasi Dinamis Frida
```

---

## 📦 Katalog Skillset & Kemampuan Utama

### 1. 🦠 Malware Triage & DFIR Sandbox (`skills/malware-triage`)
* **Standar Acuan:** NIST SP 800-86, MITRE ATT&CK for Enterprise.
* **Fitur Utama:**
  * **Static PE Triage:** MD5, SHA1, SHA256, Imphash, mitigasi memori PE (ASLR, DEP, SafeSEH).
  * **Analisis Entropi Shannon ($0.0 - 8.0$):** Deteksi kompresi dan enkripsi payload (UPX, Themida, VMProtect).
  * **Quarantine Vault Engine:** Menetralkan biner otomatis dengan XOR stream mask (Key: `0x5A`) ke format `.quarantined`.
  * **Dynamic Behavior & Registry Diff:** Deteksi persistensi Run/RunOnce dan pelacakan dropper di `%TEMP%` / `%APPDATA%`.
  * **C2 Network Sinkhole:** Menangkap koneksi beacon HTTP/DNS dan menstrukturkan log ke 4 fase NIST.
  * **Automated YARA Rule Generator:** Sintesis aturan deteksi biner secara instan.
* **Perintah CLI:**
  ```bash
  python sandbox_cli.py "sample.exe" --dynamic --timeout 15 --reg-diff --sinkhole --quarantine --outdir reports
  ```

---

### 2. 🕵️ Digital Forensics & Incident Response (`skills/digital-forensics`)
* **Standar Acuan:** NIST SP 800-86, ISO/IEC 27037, RFC 3227 (*Order of Volatility*).
* **Fitur Utama:**
  * **File Carving Otomatis:** Ekstraksi berkas terhapus dari citra raw disk (`.raw`, `.dd`, `.001`, `.E01`) via *Magic Bytes* (JPEG, PDF, ZIP, Office, PE MZ).
  * **Forensik Memori RAM:** Rekonstruksi proses via Volatility 3 (`windows.pslist`, `pstree`), deteksi injeksi kode tersembunyi (`malfind`), dan soket aktif (`netscan`).
  * **Pelacakan Flashdisk (USBSTOR Forensics):** Audit registri Windows `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` untuk membuktikan kebocoran data internal (*insider threat*).
  * **Windows Event Log Forensics:** Analisis Event ID 4624 (Logon), 4625 (Brute force), 4688 (Process Creation), 7045 (New Service), 1102 (Log Cleared).
  * **Sigma YAML Generator:** Menghasilkan template aturan deteksi insiden untuk SIEM/EDR.
* **Perintah CLI:**
  ```bash
  python skills/digital-forensics/scripts/forensic_triage.py --audit-usb
  python skills/digital-forensics/scripts/forensic_triage.py --carve evidence.raw --outdir carved_files
  python skills/digital-forensics/scripts/forensic_triage.py --gen-sigma --title "Deteksi Ransomware" --process "vssadmin.exe delete shadows"
  ```

---

### 3. ⚔️ Infrastructure Red Teaming & CEH (`skills/infra-red-teaming`)
* **Standar Acuan:** CEH (Certified Ethical Hacker v10/v11), NIST SP 800-115, MITRE ATT&CK for Enterprise.
* **Fitur Utama:**
  * **Multi-threaded Port Scanner & Banner Grabbing:** Pemindaian TCP cepat berkecepatan tinggi.
  * **Firewall Evasion Scanning:** Teknik TCP SYN Stealth (`-sS`), TCP ACK (`-sA`), dan Inverse TCP (Xmas, Null, FIN) berbasis RFC 793.
  * **Local Privilege Escalation (LPE) Auditor:** Pengecekan otomatis miskonfigurasi Linux SUID / Capabilities serta Windows Token Manipulation (`SeImpersonatePrivilege` / Potato family).
  * **SMB & Service Enumeration:** Pengecekan *Null Session* pada `IPC$` (Port 445/139) dan SNMP MIB walking (Port 161).
  * **Simulasi MITM:** ARP Spoofing dan sniffing LLMNR/NBT-NS via Responder.
* **Perintah CLI:**
  ```bash
  python skills/infra-red-teaming/scripts/infra_audit.py --scan 192.168.1.1 --ports 21,22,80,443,445,3389
  python skills/infra-red-teaming/scripts/infra_audit.py --audit-privesc
  python skills/infra-red-teaming/scripts/infra_audit.py --smb-check 192.168.1.50
  ```

---

### 4. 🟣 Web Purple Teaming & Continuous Validation (`skills/web-purple-teaming`)
* **Standar Acuan:** MITRE ATT&CK for Web Applications, NIST CSF 2.0.
* **Fitur Utama:**
  * **Siklus Orkestrasi 4 Tahap:** *Threat Emulation* ➔ *Detection Validation* ➔ *Remediation Tuning* ➔ *Regression Testing*.
  * **Triad Orchestrator Script:** Mengintegrasikan serangan Red Team dan verifikasi Blue Team secara simultan.
  * **Perhitungan Skor Ketahanan (Threat Resistance Score):** Mengukur efektivitas pertahanan secara kuantitatif.
* **Perintah CLI:**
  ```bash
  php skills/web-purple-teaming/scripts/purple_orchestrator.php --path="/path/to/project" --target-url="http://target:port"
  ```

---

### 5. 🔴 Web Red Teaming (`skills/web-red-teaming`)
* **Standar Acuan:** OWASP Top 10:2021, OWASP ASVS v4.0.
* **Fitur Utama:**
  * Pemindaian otomatis kerentanan injeksi: SQL Injection (SQLi), Cross-Site Scripting (XSS), IDOR, SSRF, dan CSRF.
  * Deteksi kebocoran berkas sensitif: `.env`, `.git`, `.htaccess`, database dump `.sql`.
  * Deteksi webshell, trojan PHP, dan CVE backdoor bawaan via `scan_webshell_cve.php`.
* **Perintah CLI:**
  ```bash
  php skills/web-red-teaming/scripts/audit_target.php --url="http://localhost:8080"
  php skills/web-red-teaming/scripts/scan_webshell_cve.php --dir="/var/www/html"
  ```

---

### 6. 🔵 Web Blue Teaming (`skills/web-blue-teaming`)
* **Standar Acuan:** CIS Benchmarks, OWASP Defense in Depth, BSSN.
* **Fitur Utama:**
  * Audit konfigurasi keamanan aplikasi web (PHP, Apache, Nginx).
  * Penguatan HTTP Security Headers: Content Security Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options.
  * Sandboxing direktori upload media (pencegahan eksekusi biner/PHP berbahaya).
* **Perintah CLI:**
  ```bash
  php skills/web-blue-teaming/scripts/hardening_checker.php --path="/path/to/project"
  ```

---

### 7. 🔬 Reverse Engineer Anything (`skills/reverse-engineer-anything`)
* **Standar Acuan:** Binary Static & Dynamic Reverse Engineering Standards.
* **Fitur Utama:**
  * Analisis biner lintas arsitektur: x86/x64, ARM, PE (Windows), ELF (Linux), Mach-O (macOS).
  * Managed & Web Applications: .NET CLR assemblies, Go, Rust, Java/DEX, Electron ASAR, dan Webpack JS.
  * Dynamic Instrumentation Engine: Hooking fungsi memori secara langsung menggunakan Frida toolkit.

---

## 🚀 Integrasi ke Google Antigravity

Untuk mengaktifkan seluruh modul ini langsung pada asisten AI Antigravity Anda:

1. **Kloning atau Salin Modul ke Direktori Konfigurasi Antigravity:**
   ```bash
   # Salin seluruh folder skills ke folder skill global Antigravity:
   cp -r skills/* ~/.gemini/config/skills/
   ```
2. **Restart Antigravity / Buka Sesi Baru:**
   Asisten secara otomatis akan mendeteksi ke-7 skill ini dan langsung menggunakannya saat diperintahkan untuk melakukan analisis keamanan, audit penetrasi, atau forensik digital.

---

## 👨‍💻 Kontributor & Lisensi

* **Lead Security Researcher & Creator:** **Arya Penangsang** ([@Arya-Penangsang](https://github.com/Arya-Penangsang))
* **AI Security Pair:** Google Antigravity
* **Lisensi:** Proyek ini dirilis di bawah lisensi [MIT License](LICENSE).
