<?php
/**
 * Comprehensive Web VAPT & Security Auditor (OWASP Top 10 & NIST SP 800-115)
 * Part of web-red-teaming skill.
 * Usage: php audit_target.php --url=http://localhost:8000 [--token="Bearer ..."]
 */

$options = getopt("", ["url:", "token::", "help::"]);

if (isset($options['help']) || empty($options['url'])) {
    echo "Usage: php audit_target.php --url=<target_url> [--token=<bearer_token>]\n";
    echo "Example: php audit_target.php --url=http://127.0.0.1:8001\n";
    exit(0);
}

$baseUrl = rtrim($options['url'], '/');
$token = $options['token'] ?? null;

echo "\n========================================================================================\n";
echo "  [Web Red Teaming] Comprehensive OWASP Top 10 & NIST Security Assessment\n";
echo "  Target URL : $baseUrl\n";
echo "  Waktu Uji  : " . date('Y-m-d H:i:s') . "\n";
echo "========================================================================================\n\n";

function makeRequest($url, $method = 'GET', $headers = [], $postData = null) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 6);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    $reqHeaders = [
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecAuditor/2.0'
    ];
    foreach ($headers as $h) {
        $reqHeaders[] = $h;
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);

    if ($postData !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    }

    $raw = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($raw === false) {
        return ['code' => 0, 'headers' => [], 'raw_headers' => '', 'body' => '', 'error' => $err];
    }

    $headerStr = substr($raw, 0, $headerSize);
    $body = substr($raw, $headerSize);

    $parsedHeaders = [];
    $rawCookies = [];
    foreach (explode("\r\n", $headerStr) as $line) {
        if (strpos($line, ':') !== false) {
            list($k, $v) = explode(':', $line, 2);
            $key = strtolower(trim($k));
            $val = trim($v);
            if ($key === 'set-cookie') {
                $rawCookies[] = $val;
            } else {
                $parsedHeaders[$key] = $val;
            }
        }
    }
    if (!empty($rawCookies)) {
        $parsedHeaders['set-cookie'] = $rawCookies;
    }

    return [
        'code' => $httpCode,
        'headers' => $parsedHeaders,
        'raw_headers' => $headerStr,
        'body' => $body,
        'error' => null
    ];
}

$results = [];

// ==========================================
// 1. A05: SECURITY MISCONFIGURATION & RECON
// ==========================================
echo "[*] [A05 / NIST PR.PT] Memeriksa Security Headers & Fingerprinting...\n";
$rootRes = makeRequest($baseUrl . '/');
if ($rootRes['code'] === 0) {
    echo "[-] Gagal terhubung ke target: " . $rootRes['error'] . "\n";
    exit(1);
}

$headers = $rootRes['headers'];

// Security Headers Matrix
$secHeaders = [
    'x-frame-options'        => ['name' => 'A05: X-Frame-Options (Clickjacking)', 'rec' => 'SAMEORIGIN / DENY'],
    'x-content-type-options' => ['name' => 'A05: X-Content-Type-Options (MIME)', 'rec' => 'nosniff'],
    'content-security-policy'=> ['name' => 'A05: Content-Security-Policy (CSP)', 'rec' => "default-src 'self' ..."],
    'referrer-policy'        => ['name' => 'A05: Referrer-Policy', 'rec' => 'strict-origin-when-cross-origin'],
    'strict-transport-security' => ['name' => 'A02: Strict-Transport-Security (HSTS)', 'rec' => 'max-age=31536000; includeSubDomains']
];

foreach ($secHeaders as $hdr => $meta) {
    if (isset($headers[$hdr])) {
        $results[] = [
            'category' => explode(':', $meta['name'])[0],
            'item' => $meta['name'],
            'status' => 'PASS',
            'severity' => 'INFO',
            'detail' => $headers[$hdr]
        ];
    } else {
        $isHsts = ($hdr === 'strict-transport-security');
        $results[] = [
            'category' => explode(':', $meta['name'])[0],
            'item' => $meta['name'],
            'status' => 'FAIL',
            'severity' => $isHsts ? 'LOW' : 'MEDIUM',
            'detail' => 'Header tidak ditemukan. ' . $meta['rec']
        ];
    }
}

// Fingerprint check
if (isset($headers['x-powered-by'])) {
    $results[] = [
        'category' => 'A05',
        'item' => 'A05: Server Fingerprint (X-Powered-By)',
        'status' => 'FAIL',
        'severity' => 'LOW',
        'detail' => 'Teknologi terekspos: ' . $headers['x-powered-by']
    ];
} else {
    $results[] = [
        'category' => 'A05',
        'item' => 'A05: Server Fingerprint (X-Powered-By)',
        'status' => 'PASS',
        'severity' => 'INFO',
        'detail' => 'Header versi berhasil disembunyikan'
    ];
}

// Cookie Flags check (A07)
if (isset($headers['set-cookie'])) {
    foreach ((array)$headers['set-cookie'] as $cookieStr) {
        $isHttpOnly = stripos($cookieStr, 'httponly') !== false;
        $isSecure   = stripos($cookieStr, 'secure') !== false;
        $hasSameSite= stripos($cookieStr, 'samesite') !== false;
        
        $cName = explode('=', explode(';', $cookieStr)[0])[0];
        $flags = [];
        if (!$isHttpOnly) $flags[] = 'HttpOnly missing';
        if (!$isSecure && parse_url($baseUrl, PHP_URL_SCHEME) === 'https') $flags[] = 'Secure missing';
        if (!$hasSameSite) $flags[] = 'SameSite missing';

        if (empty($flags)) {
            $results[] = [
                'category' => 'A07',
                'item' => "A07: Cookie Security ($cName)",
                'status' => 'PASS',
                'severity' => 'INFO',
                'detail' => 'Atribut keamanan lengkap (HttpOnly, SameSite)'
            ];
        } else {
            $results[] = [
                'category' => 'A07',
                'item' => "A07: Cookie Security ($cName)",
                'status' => 'FAIL',
                'severity' => 'MEDIUM',
                'detail' => implode(', ', $flags)
            ];
        }
    }
}

// Dotfiles Check (A05)
echo "[*] [A05 / NIST PR.AC] Memindai Kebocoran Berkas Sensitif & Dotfiles...\n";
$sensitivePaths = [
    '/.env'             => ['name' => 'A05: Env Secrets File (/.env)', 'severity' => 'CRITICAL'],
    '/.git/HEAD'        => ['name' => 'A05: Git Repo Leak (/.git/HEAD)', 'severity' => 'CRITICAL'],
    '/database.sqlite'  => ['name' => 'A05: Database Dump Leak (.sqlite)', 'severity' => 'CRITICAL'],
    '/package.json'     => ['name' => 'A05: Dependency Manifest (package.json)', 'severity' => 'LOW']
];

foreach ($sensitivePaths as $path => $meta) {
    $res = makeRequest($baseUrl . $path);
    if ($res['code'] === 200 && !empty($res['body'])) {
        $results[] = [
            'category' => 'A05',
            'item' => $meta['name'],
            'status' => 'FAIL',
            'severity' => $meta['severity'],
            'detail' => "Status 200 OK! Berkas terbuka ke publik di: $path"
        ];
    } else {
        $results[] = [
            'category' => 'A05',
            'item' => $meta['name'],
            'status' => 'PASS',
            'severity' => 'INFO',
            'detail' => "Akses diblokir (HTTP " . $res['code'] . ")"
        ];
    }
}

// ==========================================
// 2. A05: DEBUG MODE & ERROR EXPOSURE
// ==========================================
echo "[*] [A05 / NIST PR.IP] Menguji Debug Mode & Stack Trace Disclosure...\n";
$malformedRes = makeRequest($baseUrl . '/_trigger_404_error_test_' . time());
$isIgnitionExposed = (stripos($malformedRes['body'], 'Ignition') !== false || stripos($malformedRes['body'], 'Whoops! There was an error') !== false || stripos($malformedRes['body'], 'Environment & details') !== false);
if ($isIgnitionExposed) {
    $results[] = [
        'category' => 'A05',
        'item' => 'A05: Debug Mode / Stack Trace Leak',
        'status' => 'FAIL',
        'severity' => 'HIGH',
        'detail' => 'APP_DEBUG aktif! Stack trace dan konfigurasi server bocor ke publik.'
    ];
} else {
    $results[] = [
        'category' => 'A05',
        'item' => 'A05: Debug Mode / Stack Trace Leak',
        'status' => 'PASS',
        'severity' => 'INFO',
        'detail' => 'Halaman error ramah publik (tidak membocorkan stack trace).'
    ];
}

// ==========================================
// 3. A01: BROKEN ACCESS CONTROL & IDOR
// ==========================================
echo "[*] [A01 / NIST PR.AC] Menguji Akses Endpoint Terproteksi Tanpa Kredensial...\n";
foreach (['/dashboard', '/admin', '/dashboard/arsip/create'] as $adminPath) {
    $adminRes = makeRequest($baseUrl . $adminPath);
    if ($adminRes['code'] === 200) {
        $results[] = [
            'category' => 'A01',
            'item' => "A01: Access Control ($adminPath)",
            'status' => 'FAIL',
            'severity' => 'HIGH',
            'detail' => "Celah Akses! Endpoint terproteksi terbuka ke publik (HTTP 200)."
        ];
    } elseif (in_array($adminRes['code'], [301, 302, 307, 308, 401, 403])) {
        $results[] = [
            'category' => 'A01',
            'item' => "A01: Access Control ($adminPath)",
            'status' => 'PASS',
            'severity' => 'INFO',
            'detail' => "Rute terproteksi otentikasi (HTTP " . $adminRes['code'] . ")"
        ];
    }
}

// ==========================================
// 4. A03: INJECTION & REFLECTED XSS PROBE
// ==========================================
echo "[*] [A03 / NIST PR.IP] Melakukan Probe Reflected XSS & SQLi pada Parameter Publik...\n";
$xssProbeString = 'xss_probe_' . rand(1000, 9999) . '<svg/onload=alert(1)>';
$xssRes = makeRequest($baseUrl . '/?q=' . urlencode($xssProbeString) . '&search=' . urlencode($xssProbeString));

if (strpos($xssRes['body'], '<svg/onload=alert(1)>') !== false) {
    $results[] = [
        'category' => 'A03',
        'item' => 'A03: Reflected XSS Parameter Probe',
        'status' => 'FAIL',
        'severity' => 'HIGH',
        'detail' => 'Payload karakter tag HTML dipantulkan langsung tanpa sanitasi/escaping!'
    ];
} else {
    $results[] = [
        'category' => 'A03',
        'item' => 'A03: Reflected XSS Parameter Probe',
        'status' => 'PASS',
        'severity' => 'INFO',
        'detail' => 'Parameter diproses dengan aman (HTML disanitasi / di-escape)'
    ];
}

// SQL Error Probe
$sqliProbe = makeRequest($baseUrl . '/?q=' . urlencode("' OR 1=1-- -"));
$sqlErrorFound = false;
$sqlSignatures = ['SQLSTATE', 'syntax error', 'sqlite3::', 'unclosed quotation', 'mysql_fetch'];
foreach ($sqlSignatures as $sig) {
    if (stripos($sqliProbe['body'], $sig) !== false) {
        $sqlErrorFound = true;
        break;
    }
}

if ($sqlErrorFound) {
    $results[] = [
        'category' => 'A03',
        'item' => 'A03: SQL Injection Error Disclosure',
        'status' => 'FAIL',
        'severity' => 'HIGH',
        'detail' => 'Query bermasalah membocorkan sintaks SQL internal!'
    ];
} else {
    $results[] = [
        'category' => 'A03',
        'item' => 'A03: SQL Injection Error Disclosure',
        'status' => 'PASS',
        'severity' => 'INFO',
        'detail' => 'Tidak ditemukan kebocoran error SQL mentah.'
    ];
}

// ==========================================
// 5. A07: CORS & PERMISSIVE CROSS-ORIGIN
// ==========================================
echo "[*] [A07 / NIST PR.AC] Menguji CORS Misconfiguration (Wildcard Cross-Origin)...\n";
$corsRes = makeRequest($baseUrl . '/api/arsip', 'GET', ['Origin: https://attacker-evil-site.com']);
$allowOrigin = $corsRes['headers']['access-control-allow-origin'] ?? null;
$allowCreds = $corsRes['headers']['access-control-allow-credentials'] ?? null;

if ($allowOrigin === 'https://attacker-evil-site.com' && $allowCreds === 'true') {
    $results[] = [
        'category' => 'A07',
        'item' => 'A07: CORS Misconfiguration (Arbitrary Origin)',
        'status' => 'FAIL',
        'severity' => 'HIGH',
        'detail' => 'Situs pihak ketiga dapat membajak request sesi pengguna!'
    ];
} else {
    $results[] = [
        'category' => 'A07',
        'item' => 'A07: CORS Policy Cross-Origin Check',
        'status' => 'PASS',
        'severity' => 'INFO',
        'detail' => 'Kebijakan CORS aman (tidak mengizinkan arbitrary origin dengan credential)'
    ];
}

// ==========================================
// 6. OUTPUT COMPREHENSIVE MATRIX
// ==========================================
echo "\n========================================================================================\n";
echo sprintf("%-6s | %-42s | %-6s | %-8s | %s\n", "OWASP", "PARAMETER UJI & KELAYAKAN", "STATUS", "SEVERITY", "OBSERVASI & KETERANGAN");
echo "----------------------------------------------------------------------------------------\n";
foreach ($results as $r) {
    $statusColor = $r['status'] === 'PASS' ? '[PASS]' : ($r['status'] === 'WARN' ? '[WARN]' : '[FAIL]');
    echo sprintf("%-6s | %-42s | %-6s | %-8s | %s\n", 
        $r['category'],
        substr($r['item'], 0, 42), 
        $statusColor, 
        $r['severity'], 
        substr($r['detail'], 0, 75)
    );
}
echo "========================================================================================\n";
echo "Ringkasan: Asesmen selesai untuk modul OWASP A01, A02, A03, A05, A07 (NIST SP 800-115).\n\n";
