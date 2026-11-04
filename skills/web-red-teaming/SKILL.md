---
name: web-red-teaming
description: >-
  Metodologi Red Teaming, Web Penetration Testing (VAPT), dan audit keamanan aplikasi web mendalam
  berdasarkan standar OWASP Top 10:2021, OWASP ASVS v4.0, NIST SP 800-115, NIST CSF 2.0, dan panduan keamanan BSSN.
  Mendukung multi-framework (PHP/Laravel, Node.js/Next.js/Express, Python/Django/FastAPI, Go).
  Gunakan skill ini setiap kali pengguna meminta audit keamanan, vulnerability assessment, simulasi serangan etis,
  penetration testing, pembuatan proof-of-concept (PoC) celah keamanan, review kode keamanan (secure code review),
  atau penyusunan laporan perbaikan keamanan (remediation).
---

# 🛡️ Web Red Teaming & VAPT Framework: OWASP Top 10 & NIST SP 800-115

Kerangka kerja operasional pengujian penetrasi (*penetration testing*), asesmen kerentanan (*vulnerability assessment*), dan *secure code review* berbasis standar global:
- **OWASP Top 10:2021** & **OWASP WSTG (Web Security Testing Guide) v4.2**
- **OWASP ASVS (Application Security Verification Standard) v4.0**
- **NIST SP 800-115** (*Technical Guide to Information Security Testing and Assessment*)
- **NIST Cybersecurity Framework (CSF 2.0)** & Pedoman Audit Keamanan Siber **BSSN**

---

## 🚀 Skrip Audit Otomatis (Baseline Tooling)
Skill ini menyertakan skrip CLI cepat untuk mengaudit baseline kepatuhan OWASP & NIST:
```bash
# Audit live endpoint web:
php <skill-path>/scripts/audit_target.php --url=http://127.0.0.1:8000
```

---

## 🏛️ Metodologi NIST SP 800-115 (4 Fase Pengujian)

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   1. PLANNING    │ ──> │   2. DISCOVERY   │ ──> │    3. ATTACK     │ ──> │   4. REPORTING   │
│ Scope, RoE & SLA │     │ Recon & Scanning │     │ Validation (PoC) │     │ Matrix & Fixes   │
└──────────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────┘
```

1. **Fase 1: Planning (Perencanaan & Rules of Engagement)**
   - Penetapan *Scope* target resmi (domain/IP, port, API spec).
   - Penegasan *Non-Destructive Testing*: Dilarang melakukan DoS/DDoS, manipulasi permanen integritas basis data, atau eksfiltrasi data privat (PII).

2. **Fase 2: Discovery (Pengintaian & Pemindaian Celah)**
   - Pemetaan *Attack Surface*: endpoint publik, port aktif, skema otentikasi.
   - Analisis *Security Misconfiguration*, *Fingerprinting*, dan *Information Disclosure*.

3. **Fase 3: Attack / Validation (Verifikasi Celah Non-Destruktif)**
   - Memvalidasi ada/tidaknya kerentanan melalui *Proof of Concept* (PoC) jinak tanpa merusak sistem (contoh: kalkulasi matematis SQLi `AND 1=1`, bypass login simulasi, payload XSS `alert/confirm`).

4. **Fase 4: Reporting & Remediation (Pelaporan & Mitigasi NIST CSF)**
   - Klasifikasi dampak dan kemungkinan (*Impact vs Likelihood*).
   - Rekomendasi solusi teknis (*Actionable Remediation Code*) untuk menutup celah ke level risiko yang dapat diterima (*Residual Risk*).

---

## ⚔️ Audit Komprehensif: OWASP Top 10 (2021) & WSTG Checklist

### A01:2021 – Broken Access Control (WSTG-ATHZ)
- **IDOR (Insecure Direct Object Reference):** Ganti parameter ID objek (`/users/5` -> `/users/6`, `/arsip/edit/100`) untuk memastikan otorisasi berbasis sesi/role pemanggil.
- **Horizontal & Vertical Privilege Escalation:** Pengguna reguler mengakses fitur administrasi (`/admin`, `/api/pengaturan`, `/api/v1/users/delete`).
- **Missing Function Level Access Control:** Pengecekan HTTP method sensitif (operasi POST/DELETE langsung dari user tamu tanpa token otorisasi).

### A02:2021 – Cryptographic Failures (WSTG-CRYP)
- **Data in Transit:** Ketiadaan HTTPS/TLS atau penggunaan cipher usang (SSLv3, TLS 1.0/1.1). Pastikan header `Strict-Transport-Security` (HSTS) aktif.
- **Data at Rest:** Kredensial, kunci API, atau password disimpan dalam bentuk plain-text atau hash lemah (MD5/SHA1). Wajib menggunakan `bcrypt`, `argon2id`, atau `pbkdf2`.
- **Sensitive Data Exposure:** Kredensial API / private key yang di-hardcode di kode sumber repositori.

### A03:2021 – Injection (WSTG-INPV)
- **SQL / NoSQL Injection:**
  - Karakter uji: `' OR '1'='1`, `{"$ne": null}`
  - *Code Review:* Wajib menggunakan *Prepared Statements* / *Parameterized Queries* / ORM bawaan. Dilarang konkatenasi string SQL mentah (`DB::raw`, `queryRawUnsafe`, `db.query("... " + input)`).
- **Command / Code Injection:** Input pengguna dialirkan ke `system()`, `exec()`, `eval()`, atau shell OS tanpa sanitasi *escapeshellarg*.

### A04:2021 – Insecure Design (WSTG-DSGN)
- Ketiadaan *Business Logic Protection*:
  - Manipulasi harga atau kuantitas bernilai negatif.
  - Alur *Reset Password* tanpa verifikasi token kedaluwarsa atau token dapat ditebak.
  - Ketiadaan batas frekuensi (*Rate Limiting*) pada formulir reset sandi dan checkout.

### A05:2021 – Security Misconfiguration (WSTG-CONF)
- **Debug Mode Aktif:** `APP_DEBUG=true` di Laravel, `DEBUG=True` di Django, atau stack trace bawaan Express mengekspos variabel lingkungan, path absolut server, dan password database.
- **Dotfiles & Sensitif:** Akses langsung ke `/.env`, `/.git/`, `/.env.local`, `web.config`, `backup.sql`, `dump.sqlite`.
- **Missing HTTP Security Headers:**
  - `X-Frame-Options: SAMEORIGIN / DENY` (Clickjacking)
  - `X-Content-Type-Options: nosniff` (MIME Sniffing)
  - `Content-Security-Policy` (CSP XSS restriction)
  - `Permissions-Policy` (Device features restrictions)
- **Cookie Security:** Cookie sesi tanpa atribut `HttpOnly`, `SameSite=Lax/Strict`, atau `Secure`.

### A06:2021 – Vulnerable and Outdated Components (WSTG-CONF)
- Pustaka/dependensi pihak ketiga dengan CVE publik yang belum ditambal (*Known Vulnerabilities*).
- Pemeriksaan berkala manifest dependensi:
  - PHP: `composer audit`
  - Node.js: `npm audit` / `pnpm audit`
  - Python: `pip-audit` / `safety check`

### A07:2021 – Identification and Authentication Failures (WSTG-ATHN)
- **Brute Force & Credential Stuffing:** Endpoint `/login` dan `/api/auth` tanpa pembatasan rate limit (`throttle`), penalti waktu jeda, atau proteksi CAPTCHA/Honeypot.
- **Session Management:** Session ID tidak diregenerasi saat pergantian status otentikasi (login/logout), menyebabkan potensi *Session Fixation*.
- **JWT Flaws:** Token otentikasi rentan manipulasi algoritma (*None Algorithm*), ketiadaan masa kedaluwarsa (`exp`), atau rahasia penandatanganan (*secret key*) yang lemah.

### A08:2021 – Software and Data Integrity Failures (WSTG-INPV)
- **Insecure Deserialization:** Memproses objek berseri yang tidak dipercaya (`unserialize()` di PHP, `pickle.loads()` di Python, `eval()` di JS).
- **Auto-Update & Plugin Integritas:** Pengunduhan dependensi atau berkas update dari sumber eksternal tanpa validasi hash (SHA-256) atau tanda tangan digital.

### A09:2021 – Security Logging and Monitoring Failures (NIST DE.AE / WSTG-LOGG)
- Ketiadaan audit trail / log aktivitas kritis (login gagal, perubahan role, penghapusan data massal).
- **Log Injection:** Data masukan pengguna ditulis ke berkas log tanpa pembersihan karakter *newline* (`\r\n`), memungkinkan pemalsuan entri log.

### A10:2021 – Server-Side Request Forgery (SSRF) (WSTG-INPV)
- Fitur web yang mengunduh URL/Webhook eksternal atas permintaan pengguna tanpa pembatasan IP:
  - Uji akses ke alamat IP internal (*Loopback/Private IP*): `http://127.0.0.1`, `http://10.0.0.1`, `http://192.168.1.1`.
  - Uji akses ke *Cloud Metadata Services*: `http://169.254.169.254/latest/meta-data/` (AWS/GCP/Azure).

---

## 🚦 Matriks CVSS v3.1 & Pemetaan NIST Cybersecurity Framework (CSF)

| Severity | CVSS v3.1 | Prioritas | NIST CSF 2.0 Mapping | Deskripsi Dampak |
|:---:|:---:|:---:|:---|:---|
| **CRITICAL** | 9.0 – 10.0 | **P0 (Blocker)** | **PR.AC / PR.DS** (Akses & Proteksi Data) | RCE, SQLi Unauthenticated, Pengambilalihan Penuh Hak Akses Root/Admin, File `.env` terbuka publik. |
| **HIGH** | 7.0 – 8.9 | **P1 (Urgent)** | **PR.AC** (Manajemen Identitas & Akses) | Stored XSS di Dashboard Admin, IDOR pengubahan akun lain, Otentikasi bypass parsial, SSRF internal. |
| **MEDIUM** | 4.0 – 6.9 | **P2 (Normal)** | **PR.IP** (Prosedur Proteksi Informasi) | Reflected XSS, CSRF pada fungsionalitas moderat, CORS liar dengan credentials, Brute force tanpa throttle. |
| **LOW / INFO**| 0.1 – 3.9 | **P3 (Hardening)**| **PR.PT** (Teknologi Proteksi & Hygiene) | Security headers hilang (CSP, HSTS), Fingerprint server bocor, Cookie SameSite belum dikonfigurasi. |

---

## 📊 Format Standar Laporan Audit (Executive & Technical Matrix)

Laporan hasil asesmen wajib disajikan dalam bentuk matriks terstruktur:

| No | Modul / Titik Uji | Kategori OWASP | Standar NIST | Severity (CVSS) | Status | Tindakan Perbaikan (*Remediation*) |
| :-: | :--- | :--- | :--- | :---: | :---: | :--- |
| **1** | Endpoint `/.env` | A05: Security Misconfiguration | PR.AC-4 / PR.DS-5 | **CRITICAL (9.1)** | **FIXED** | Blokir akses webserver terhadap semua berkas dotfile (*dot-files*). |
| **2** | Proteksi CSRF | A01: Broken Access Control | PR.IP-1 | **MEDIUM (5.4)** | **FIXED** | Terapkan token CSRF wajib pada seluruh permintaan POST/PUT/DELETE. |
| **3** | Kebijakan CSP | A05: Security Misconfiguration | PR.PT-4 | **LOW (3.2)** | **OPEN** | Pasang header `Content-Security-Policy` untuk membatasi script eksternal. |

---

## 🛠️ Snippet Remediasi Kepatuhan OWASP & NIST

### 1. Nginx: Hardening Dotfiles & Security Headers
```nginx
# Blokir dotfiles (.env, .git, .htaccess)
location ~ /\.(?!well-known).* {
    deny all;
    access_log off;
    log_not_found off;
}

# Header Keamanan Standar OWASP / NIST
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self' data: https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### 2. Laravel: Secure Session Cookie (`config/session.php`)
```php
'secure' => env('SESSION_SECURE_COOKIE', true), // Wajib true di HTTPS
'http_only' => true,
'same_site' => 'lax',
```

### 3. Node.js (Express + Helmet): OWASP Hardening
```javascript
const helmet = require('helmet');
app.use(helmet({
    contentSecurityPolicy: true,
    crossOriginEmbedderPolicy: false,
    frameguard: { action: 'sameorigin' }
}));
```
