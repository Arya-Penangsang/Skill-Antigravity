---
name: web-blue-teaming
description: >-
  Metodologi Blue Teaming, Defensif Hardening, Threat Detection, Incident Response,
  dan penguatan keamanan aplikasi web berdasarkan CIS Benchmarks, NIST CSF 2.0 (PROTECT & DETECT),
  OWASP Defense in Depth, dan standar BSSN.
  Gunakan skill ini saat pengguna meminta penguatan sistem (hardening), perbaikan celah pasca-audit (remediation),
  konfigurasi firewall/security headers, pemantauan integritas berkas (FIM), analisis log insiden,
  atau isolasi dan penanganan serangan (incident response).
---

# 🛡️ Web Blue Teaming & Defensive Security Runbook

Panduan metodologi operasional untuk pertahanan keamanan siber (*cyber defense*), penguatan sistem (*hardening*), pemantauan ancaman (*threat detection*), dan penutupan celah (*remediation*) berbasis standar **CIS Benchmarks**, **NIST CSF 2.0**, dan **OWASP Defense-in-Depth**.

---

## 🏛️ 4 Pilar Utama Web Blue Teaming

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   1. HARDENING   │ ──> │   2. DETECTION   │ ──> │   3. RESPONSE    │ ──> │   4. RECOVERY    │
│  Attack Surface  │     │ Logs & Integrity │     │ Contain & Isolate│     │ Patch & Restore  │
│    Reduction     │     │ Monitoring (FIM) │     │ Leaked Secrets   │     │ Lessons Learned  │
└──────────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────┘
```

---

## 🔒 Pilar 1: System & Web Hardening (Pencegahan)

### 1.1 Webserver Hardening (Nginx & Apache)
- **Blokir Akses Berkas Tersembunyi (Dotfiles & VCS):**
  Pastikan `/.env`, `/.git`, `/.svn`, `web.config` diblokir permanen dengan respons `403 Forbidden` atau `404 Not Found`.
- **Isolasi Direktori Unggahan (Uploads Sandboxing):**
  Matikan eksekusi skrip PHP di folder media/uploads publik (`public/uploads`, `storage/app/public`):
  - *Apache (.htaccess di folder upload):*
    ```apache
    <FilesMatch "\.(php|phtml|php3|php4|php5|phar|inc|cgi|pl|py)$">
        Order Deny,Allow
        Deny from all
    </FilesMatch>
    php_flag engine off
    ```
  - *Nginx:*
    ```nginx
    location ^~ /uploads/ {
        location ~ \.(php|phtml|phar)$ {
            deny all;
        }
    }
    ```

### 1.2 HTTP Security Headers Baseline (OWASP Secure Headers)
Wajib diterapkan di gateway middleware atau reverse proxy:
- `X-Frame-Options: SAMEORIGIN` (Mitigasi Clickjacking)
- `X-Content-Type-Options: nosniff` (Mitigasi MIME-Sniffing)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self' data: https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Wajib di HTTPS)
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### 1.3 PHP Runtime Hardening (`php.ini`)
- `expose_php = Off` (Sembunyikan header `X-Powered-By`)
- `display_errors = Off` (Cegah kebocoran stack trace error ke pengguna)
- `log_errors = On` (Simpan seluruh error ke log internal)
- `allow_url_fopen = Off` & `allow_url_include = Off` (Cegah RFI & LFI wrapper)
- `disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source`

### 1.4 Sesi & Autentikasi Defensif
- **Cookie Flags:** Wajib `HttpOnly; SameSite=Lax` dan `Secure=true` (di HTTPS).
- **Session Regeneration:** Wajib memanggil `session()->regenerate()` setiap kali status otentikasi berubah (cegah *Session Fixation*).
- **Anti-Brute Force (Throttling):** Batasi maksimal 5 percobaan login per menit per IP/akun dengan penalti *exponential backoff*.

---

## 👁️ Pilar 2: Detection & Threat Monitoring

### 2.1 File Integrity Monitoring (FIM)
- Jalankan pemantauan berkala terhadap hash SHA-256 berkas sistem inti (`app/`, `routes/`, `config/`).
- Deteksi berkas baru yang tidak lazim di folder web publik (indikasi dropper atau backdoor webshell).

### 2.2 Security Event Logging & Audit Trail
Pastikan aplikasi mencatat (*audit log*) kejadian kritis:
- Percobaan login gagal beruntun (*brute force attempt*).
- Perubahan hak akses / peran pengguna (*privilege escalation*).
- Percobaan akses ke rute terlarang (*403 forbidden spikes*).
- Pembaruan atau penghapusan data massal.

---

## 🚨 Pilar 3: Incident Response & Mitigation (Penanganan Serangan)

Langkah isolasi cepat saat terdeteksi indikasi penyusupan:
1. **Isolasi Akses (Containment):**
   - Blokir IP penyerang di firewall / webserver (`deny <IP>;`).
   - Ubah sementara aplikasi ke *Maintenance Mode* jika terdapat celah aktif yang belum tertambal (`php artisan down`).
2. **Rotasi Kredensial (Secret Invalidation):**
   - Segera rotasi `APP_KEY`, password database, API keys pihak ketiga, dan secret JWT di file `.env`.
   - Hancurkan seluruh sesi pengguna aktif di database/Redis (`session:flush`).
3. **Pembersihan Berkas (Sanitization):**
   - Hapus berkas backdoor atau webshell yang teridentifikasi.
   - Bandingkan source code saat ini dengan commit terakhir di Git yang bersih (`git status`, `git diff`).

---

## 🛠️ Perkakas Otomatisasi Blue Team (Scripts)
Skill ini dilengkapi skrip bantu pertahanan:
- `scripts/hardening_checker.php`: Menguji kepatuhan konfigurasi hardening lokal dan menghasilkan snippet proteksi siap pakai.
- `scripts/fim_quick_audit.php`: Memeriksa integritas berkas dan mendeteksi berkas skrip mencurigakan di luar folder resmi.
