---
name: web-purple-teaming
description: >-
  Metodologi Purple Teaming, Kolaborasi Red-Blue, Validasi Deteksi Ancaman (Threat Detection Verification),
  Pemetaan MITRE ATT&CK for Enterprise/Web, dan Pengujian Otomatis DevSecOps.
  Gunakan skill ini saat pengguna meminta pengujian keamanan menyeluruh (triad audit),
  orkestrasi Red + Blue Team, validasi apakah serangan terdeteksi oleh sistem pertahanan,
  pemetaan taktik MITRE ATT&CK, atau pembuatan laporan keamanan terpadu (Unified Security Report).
---

# 🟣 Web Purple Teaming & Continuous Security Validation Runbook

Panduan metodologi operasional kolaborasi keamanan siber terpadu (*Purple Teaming*) yang mengintegrasikan serangan etis (**Red Team**) dengan penguatan pertahanan (**Blue Team**) berbasis taktik **MITRE ATT&CK for Enterprise (Web Applications)** dan **NIST Cybersecurity Framework**.

---

## 🔁 Siklus Operasional Purple Teaming

```
   ┌──────────────────────────────────────────────────────────────┐
   │                   1. THREAT EMULATION                        │
   │  Simulasi teknik serangan spesifik dari taktik MITRE ATT&CK  │
   └──────────────────────────────┬───────────────────────────────┘
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                  2. DETECTION VALIDATION                     │
   │  Verifikasi: "Apakah kontrol defensif memblokir/mencatat?"   │
   └──────────────────────────────┬───────────────────────────────┘
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                  3. REMEDIATION & TUNING                     │
   │  Penyesuaian konfigurasi WAF, headers, dan patch kode sumber │
   └──────────────────────────────┬───────────────────────────────┘
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                  4. REGRESSION VALIDATION                    │
   │  Jalankan ulang orkestrator untuk memastikan skor sempurna   │
   └──────────────────────────────────────────────────────────────┘
```

---

## 🎯 Pemetaan Taktik & Teknik MITRE ATT&CK for Web

| Taktik MITRE | ID Teknik | Nama Teknik | Simulasi Red Team | Verifikasi Blue Team | Status Target Ideal |
|:---|:---:|:---|:---|:---|:---:|
| **Reconnaissance** | `T1595` | Active Scanning | Fingerprinting & Dotfiles probe | Akses `/.env`, `/.git` diblokir (403/404) | **BLOCKED** |
| **Initial Access** | `T1190` | Exploit Public-Facing App | Injeksi parameter (SQLi / XSS) | Parameter tersanitasi & lolos CSP | **MITIGATED** |
| **Credential Access** | `T1110` | Brute Force | Pengiriman login beruntun | Rate limiter (429) & CAPTCHA aktif | **DETECTED & BLOCKED** |
| **Persistence** | `T1505.003` | Web Shell Drop | Percobaan unggah skrip berbahaya | Sandboxing `.htaccess` mematikan engine | **BLOCKED** |
| **Defense Evasion** | `T1036` | Masquerading Extension | Ekstensi ganda `file.php.jpg` | Validasi MIME riil & hash rename | **MITIGATED** |
| **Discovery** | `T1083` | File & Directory Discovery | Scanning `web.config`, dump `.sql` | Directory listing mati (`-Indexes`) | **BLOCKED** |

---

## 🚀 Orkestrasi Audit Triad (Red + Blue + Purple)
Skill ini menyediakan skrip orkestrasi terpusat yang menjalankan seluruh rangkaian pengujian dari ke-3 pilar dan merangkumnya ke dalam satu laporan terpadu:
```bash
php <skill-path>/scripts/purple_orchestrator.php --path="/path/to/project" --target-url="http://target:port"
```
