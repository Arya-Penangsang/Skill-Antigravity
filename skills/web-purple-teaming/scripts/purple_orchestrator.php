<?php
/**
 * Purple Team Unified Security Orchestrator (Red + Blue + Purple Triad)
 * Part of web-purple-teaming skill.
 * Usage: php purple_orchestrator.php --path="G:\path\to\project" --target-url="http://127.0.0.1:8001"
 */

$options = getopt("", ["path:", "target-url:", "output::", "help::"]);

if (isset($options['help']) || empty($options['path']) || empty($options['target-url'])) {
    echo "Usage: php purple_orchestrator.php --path=<project_folder> --target-url=<url> [--output=<file.md>]\n";
    echo "Example: php purple_orchestrator.php --path=\"G:\\project\\ANTIGRAVIT PROJECT\\mahameru-bootstrap\" --target-url=\"http://127.0.0.1:8001\"\n";
    exit(0);
}

$projectPath = rtrim($options['path'], "\\/");
$targetUrl = rtrim($options['target-url'], '/');
$outputReportFile = $options['output'] ?? null;

echo "\n========================================================================================\n";
echo "  [PURPLE TEAM] UNIFIED SECURITY ASSESSMENT ORCHESTRATOR\n";
echo "  Target URL : $targetUrl\n";
echo "  Path Proyek: $projectPath\n";
echo "  Waktu Uji  : " . date('Y-m-d H:i:s') . "\n";
echo "========================================================================================\n\n";

if (!is_dir($projectPath)) {
    echo "[-] Direktori proyek tidak ditemukan: $projectPath\n";
    exit(1);
}

// -----------------------------------------------------------------------------
// HELPER: CURL REQUEST
// -----------------------------------------------------------------------------
function sendProbe($url, $method = 'GET', $headers = [], $postData = null) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    $reqHeaders = ['User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PurpleTeamOrchestrator/1.0'];
    foreach ($headers as $h) { $reqHeaders[] = $h; }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);

    if ($postData !== null) { curl_setopt($ch, CURLOPT_POSTFIELDS, $postData); }

    $raw = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($raw === false) {
        return ['code' => 0, 'headers' => [], 'body' => '', 'error' => $err];
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
            if ($key === 'set-cookie') { $rawCookies[] = $val; }
            else { $parsedHeaders[$key] = $val; }
        }
    }
    if (!empty($rawCookies)) { $parsedHeaders['set-cookie'] = $rawCookies; }

    return ['code' => $httpCode, 'headers' => $parsedHeaders, 'body' => $body, 'error' => null];
}

// =============================================================================
// 1. 🔴 RED TEAM DOMAIN: EXPLOITATION, PROBING & CVE CHECKS
// =============================================================================
echo "[1/3] 🔴 Menjalankan Domain RED TEAM (Serangan Etis & Probe Kerentanan)...\n";
$redResults = [];

// Probe Root & Headers
$root = sendProbe($targetUrl . '/');
$rootHeaders = $root['headers'];

// Dotfiles probe
$dotRes = sendProbe($targetUrl . '/.env');
$redResults['dotfiles'] = [
    'name' => 'Sensitif Dotfiles Leak (/.env)',
    'status' => in_array($dotRes['code'], [403, 404]) ? 'PASS' : 'FAIL',
    'code' => $dotRes['code'],
    'detail' => in_array($dotRes['code'], [403, 404]) ? 'Akses diblokir (HTTP ' . $dotRes['code'] . ')' : 'File .env dapat diunduh (HTTP 200)!'
];

// Reflected XSS Probe
$xssTag = '<svg/onload=confirm(1)>';
$xssRes = sendProbe($targetUrl . '/?q=' . urlencode($xssTag));
$isXssReflected = strpos($xssRes['body'], $xssTag) !== false;
$redResults['xss'] = [
    'name' => 'Reflected XSS Input Sanitization',
    'status' => !$isXssReflected ? 'PASS' : 'FAIL',
    'code' => $xssRes['code'],
    'detail' => !$isXssReflected ? 'Karakter HTML di-escape secara aman' : 'Payload script dipantulkan mentah ke DOM!'
];

// SQL Injection Error Probe
$sqlRes = sendProbe($targetUrl . '/?q=' . urlencode("' OR 1=1-- -"));
$sqlLeak = (stripos($sqlRes['body'], 'SQLSTATE') !== false || stripos($sqlRes['body'], 'syntax error') !== false);
$redResults['sqli'] = [
    'name' => 'SQLi Error & Injection Probe',
    'status' => !$sqlLeak ? 'PASS' : 'FAIL',
    'code' => $sqlRes['code'],
    'detail' => !$sqlLeak ? 'Tidak ada kebocoran error SQL internal' : 'Query error mengekspos detail database!'
];

// Access Control
$dashRes = sendProbe($targetUrl . '/dashboard');
$redResults['auth_bypass'] = [
    'name' => 'Broken Access Control (/dashboard)',
    'status' => in_array($dashRes['code'], [301, 302, 401, 403]) ? 'PASS' : 'FAIL',
    'code' => $dashRes['code'],
    'detail' => in_array($dashRes['code'], [301, 302, 401, 403]) ? 'Endpoint admin wajib login (HTTP ' . $dashRes['code'] . ')' : 'Endpoint admin terbuka ke publik (HTTP 200)!'
];

// Uploads Malicious Files Scan
$uploadDir = $projectPath . '/public/assets/uploads';
$maliciousCount = 0;
$totalUploadFiles = 0;
if (is_dir($uploadDir)) {
    $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploadDir, FilesystemIterator::SKIP_DOTS));
    foreach ($iter as $f) {
        if ($f->isFile()) {
            $totalUploadFiles++;
            $ext = strtolower($f->getExtension());
            if (in_array($ext, ['php', 'phtml', 'phar', 'inc', 'exe', 'sh'])) {
                $maliciousCount++;
            }
        }
    }
}
$redResults['webshell_scan'] = [
    'name' => "Malicious Webshell Scan ($totalUploadFiles berkas dipindai)",
    'status' => ($maliciousCount === 0) ? 'PASS' : 'FAIL',
    'code' => 200,
    'detail' => ($maliciousCount === 0) ? 'Tidak ditemukan webshell / file executable' : "$maliciousCount file berbahaya terdeteksi!"
];

// =============================================================================
// 2. 🔵 BLUE TEAM DOMAIN: DEFENSIVE HARDENING & CONTROL POSTURE
// =============================================================================
echo "[2/3] 🔵 Menjalankan Domain BLUE TEAM (Verifikasi Hardening & Kontrol Pertahanan)...\n";
$blueResults = [];

// Uploads Sandboxing (.htaccess)
$htaccessUpload = $uploadDir . '/.htaccess';
$isHtaccessLocked = false;
if (file_exists($htaccessUpload)) {
    $c = file_get_contents($htaccessUpload);
    if (stripos($c, 'Deny from all') !== false || stripos($c, 'php_flag engine off') !== false) {
        $isHtaccessLocked = true;
    }
}
$blueResults['upload_sandbox'] = [
    'name' => 'Uploads Execution Sandboxing (.htaccess)',
    'status' => $isHtaccessLocked ? 'PASS' : 'WARN',
    'detail' => $isHtaccessLocked ? 'Eksekusi engine PHP di folder uploads dimatikan' : 'Belum ada .htaccess pengunci eksekusi di folder uploads'
];

// Security Headers (CSP, XFO, nosniff)
$hasXfo = isset($rootHeaders['x-frame-options']);
$hasNosniff = isset($rootHeaders['x-content-type-options']);
$hasCsp = isset($rootHeaders['content-security-policy']);

$blueResults['xfo'] = [
    'name' => 'Clickjacking Defense (X-Frame-Options)',
    'status' => $hasXfo ? 'PASS' : 'FAIL',
    'detail' => $hasXfo ? $rootHeaders['x-frame-options'] : 'Header X-Frame-Options tidak ditemukan'
];
$blueResults['nosniff'] = [
    'name' => 'MIME Sniffing Defense (nosniff)',
    'status' => $hasNosniff ? 'PASS' : 'FAIL',
    'detail' => $hasNosniff ? $rootHeaders['x-content-type-options'] : 'Header X-Content-Type-Options tidak ditemukan'
];
$blueResults['csp'] = [
    'name' => 'Content-Security-Policy (CSP)',
    'status' => $hasCsp ? 'PASS' : 'WARN',
    'detail' => $hasCsp ? 'CSP aktif membatasi sumber script' : 'CSP belum terpasang'
];

// Fingerprinting X-Powered-By
$hasPoweredBy = isset($rootHeaders['x-powered-by']);
$blueResults['fingerprint'] = [
    'name' => 'Server Fingerprint Concealment',
    'status' => !$hasPoweredBy ? 'PASS' : 'WARN',
    'detail' => !$hasPoweredBy ? 'Header versi PHP/Laravel disembunyikan' : 'Versi server terekspos: ' . $rootHeaders['x-powered-by']
];

// Cookie Flags
$sessionCookieProtected = false;
if (isset($rootHeaders['set-cookie'])) {
    foreach ((array)$rootHeaders['set-cookie'] as $ck) {
        if (stripos($ck, 'httponly') !== false && stripos($ck, 'samesite') !== false) {
            $sessionCookieProtected = true;
            break;
        }
    }
}
$blueResults['cookie_sec'] = [
    'name' => 'Session Cookie Isolation (HttpOnly; SameSite)',
    'status' => $sessionCookieProtected ? 'PASS' : 'WARN',
    'detail' => $sessionCookieProtected ? 'Cookie sesi terisolasi dari pencurian skrip client' : 'Atribut cookie belum optimal'
];

// =============================================================================
// 3. 🟣 PURPLE TEAM DOMAIN: MITRE ATT&CK MAPPING & GAP ANALYSIS
// =============================================================================
echo "[3/3] 🟣 Menjalankan Domain PURPLE TEAM (Pemetaan MITRE ATT&CK & Gap Analysis)...\n";

$mitreMatrix = [
    [
        'tactic' => 'Initial Access',
        'tech_id' => 'T1190',
        'tech_name' => 'Exploit Public-Facing App',
        'red_test' => 'SQLi & XSS Parameter Injection',
        'blue_defense' => 'Input Escaping & WAF/Middleware',
        'status' => ($redResults['xss']['status'] === 'PASS' && $redResults['sqli']['status'] === 'PASS') ? 'MITIGATED' : 'VULNERABLE'
    ],
    [
        'tactic' => 'Reconnaissance',
        'tech_id' => 'T1595',
        'tech_name' => 'Active Scanning & Fingerprinting',
        'red_test' => 'Exposure of .env & Server Tech',
        'blue_defense' => 'Dotfiles Webserver Drop & Header Stripping',
        'status' => ($redResults['dotfiles']['status'] === 'PASS' && $blueResults['fingerprint']['status'] === 'PASS') ? 'BLOCKED' : 'EXPOSED'
    ],
    [
        'tactic' => 'Persistence',
        'tech_id' => 'T1505.003',
        'tech_name' => 'Server Component: Web Shell',
        'red_test' => 'Uploads Directory Script Execution',
        'blue_defense' => 'Upload Sandboxing (.htaccess / Engine Off)',
        'status' => ($redResults['webshell_scan']['status'] === 'PASS' && $blueResults['upload_sandbox']['status'] === 'PASS') ? 'BLOCKED' : 'AT RISK'
    ],
    [
        'tactic' => 'Privilege Escalation',
        'tech_id' => 'T1078',
        'tech_name' => 'Valid Accounts / Access Bypass',
        'red_test' => 'Direct Access to /dashboard without Auth',
        'blue_defense' => 'Auth Middleware Enforcement (302 Redirect)',
        'status' => ($redResults['auth_bypass']['status'] === 'PASS') ? 'BLOCKED' : 'VULNERABLE'
    ],
    [
        'tactic' => 'Credential Access',
        'tech_id' => 'T1539',
        'tech_name' => 'Steal Web Session Cookie',
        'red_test' => 'XSS-based Cookie Access',
        'blue_defense' => 'HttpOnly, SameSite Flag & CSP Enforce',
        'status' => ($blueResults['cookie_sec']['status'] === 'PASS' && $blueResults['xfo']['status'] === 'PASS') ? 'MITIGATED' : 'PARTIAL'
    ]
];

// Calculate Overall Triad Score
$totalControls = count($redResults) + count($blueResults);
$passedControls = 0;
foreach ($redResults as $r) { if ($r['status'] === 'PASS') $passedControls++; }
foreach ($blueResults as $b) { if ($b['status'] === 'PASS') $passedControls++; }
$triadScore = round(($passedControls / $totalControls) * 100);

// =============================================================================
// OUTPUT UNIFIED TRIAD REPORT
// =============================================================================
echo "\n========================================================================================\n";
echo "              LAPORAN KEAMANAN TERPADU TRIAD (RED + BLUE + PURPLE)                      \n";
echo "========================================================================================\n";
echo " Skor Indeks Pertahanan Triad: $triadScore% ($passedControls/$totalControls Kontrol Pertahanan Lolos)\n";
echo " Status Kelayakan Produksi   : " . ($triadScore >= 80 ? "LAYAK RILIS / HARDENED" : "PERLU PENGETATAN") . "\n";
echo "----------------------------------------------------------------------------------------\n\n";

echo "--- [1] TEMUAN RED TEAM (Offensive Validation) ---\n";
foreach ($redResults as $r) {
    echo sprintf("  [%s] %-38s : %s\n", $r['status'], $r['name'], $r['detail']);
}

echo "\n--- [2] STATUS KONTROL BLUE TEAM (Defensive Posture) ---\n";
foreach ($blueResults as $b) {
    echo sprintf("  [%s] %-38s : %s\n", $b['status'], $b['name'], $b['detail']);
}

echo "\n--- [3] MATRIKS PURPLE TEAM (Pemetaan MITRE ATT&CK for Web) ---\n";
echo sprintf("  %-12s | %-10s | %-28s | %-12s\n", "TAKTIK", "ID TEKNIK", "NAMA TEKNIK", "STATUS PERTAHANAN");
echo "  --------------------------------------------------------------------------------------\n";
foreach ($mitreMatrix as $m) {
    echo sprintf("  %-12s | %-10s | %-28s | [%s]\n", 
        substr($m['tactic'], 0, 12),
        $m['tech_id'],
        substr($m['tech_name'], 0, 28),
        $m['status']
    );
}
echo "========================================================================================\n";
echo "Laporan terpadu selesai dibuat.\n\n";
