<?php
/**
 * Automated Blue Team Hardening & Posture Auditor
 * Part of web-blue-teaming skill.
 * Usage: php hardening_checker.php --path="G:\path\to\project"
 */

$options = getopt("", ["path:", "help::"]);

if (isset($options['help']) || empty($options['path'])) {
    echo "Usage: php hardening_checker.php --path=<project_folder>\n";
    echo "Example: php hardening_checker.php --path=\"G:\\project\\ANTIGRAVIT PROJECT\\mahameru-bootstrap\"\n";
    exit(0);
}

$projectPath = rtrim($options['path'], "\\/");

echo "\n========================================================================================\n";
echo "  [Web Blue Teaming] Defensive Hardening & Security Baseline Auditor\n";
echo "  Direktori Proyek : $projectPath\n";
echo "  Waktu Audit      : " . date('Y-m-d H:i:s') . "\n";
echo "========================================================================================\n\n";

if (!is_dir($projectPath)) {
    echo "[-] Direktori tidak ditemukan: $projectPath\n";
    exit(1);
}

$checklist = [];

// 1. AUDIT PHP RUNTIME HARDENING (php.ini)
echo "[*] [CIS Benchmark 2.1] Memeriksa Konfigurasi Runtime PHP (php.ini)...\n";
$exposePhp = ini_get('expose_php');
$displayErrors = ini_get('display_errors');
$allowUrlInclude = ini_get('allow_url_include');
$disabledFunctions = explode(',', ini_get('disable_functions'));
$disabledFunctions = array_map('trim', $disabledFunctions);

$checklist[] = [
    'pillar' => 'Runtime',
    'control' => 'expose_php = Off (Sembunyikan Versi)',
    'status' => empty($exposePhp) ? 'PASS' : 'WARN',
    'severity' => 'LOW',
    'detail' => empty($exposePhp) ? 'Versi PHP disembunyikan' : 'expose_php aktif (header X-Powered-By mengekspos versi)'
];

$checklist[] = [
    'pillar' => 'Runtime',
    'control' => 'allow_url_include = Off (Anti-RFI)',
    'status' => empty($allowUrlInclude) ? 'PASS' : 'FAIL',
    'severity' => 'CRITICAL',
    'detail' => empty($allowUrlInclude) ? 'allow_url_include mati (Aman)' : 'allow_url_include aktif! Rentan Remote File Inclusion.'
];

$criticalDangerFuncs = ['exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen'];
$unblockedFuncs = [];
foreach ($criticalDangerFuncs as $f) {
    if (!in_array($f, $disabledFunctions) && function_exists($f)) {
        $unblockedFuncs[] = $f;
    }
}

$checklist[] = [
    'pillar' => 'Runtime',
    'control' => 'disable_functions (Sistem Shell)',
    'status' => empty($unblockedFuncs) ? 'PASS' : 'WARN',
    'severity' => 'MEDIUM',
    'detail' => empty($unblockedFuncs) ? 'Fungsi shell sistem diblokir' : 'Fungsi aktif: ' . implode(', ', array_slice($unblockedFuncs, 0, 4))
];

// 2. AUDIT FRAMEWORK ENVIRONMENT & CONFIG (.env)
echo "[*] [NIST PR.IP] Memeriksa Pengerasan Konfigurasi .env...\n";
$envPath = $projectPath . '/.env';
if (file_exists($envPath)) {
    $env = parse_ini_file($envPath, false, INI_SCANNER_RAW);
    
    $appDebug = strtolower($env['APP_DEBUG'] ?? 'false');
    $appEnv = strtolower($env['APP_ENV'] ?? 'local');
    $sessionSecure = strtolower($env['SESSION_SECURE_COOKIE'] ?? 'false');

    $checklist[] = [
        'pillar' => 'Config',
        'control' => 'APP_DEBUG = false di Produksi',
        'status' => ($appEnv === 'production' && $appDebug === 'true') ? 'FAIL' : 'PASS',
        'severity' => 'HIGH',
        'detail' => "APP_ENV=$appEnv, APP_DEBUG=$appDebug"
    ];

    $checklist[] = [
        'pillar' => 'Config',
        'control' => 'SESSION_SECURE_COOKIE (HTTPS)',
        'status' => ($sessionSecure === 'true' || $appEnv !== 'production') ? 'PASS' : 'WARN',
        'severity' => 'MEDIUM',
        'detail' => "SESSION_SECURE_COOKIE=$sessionSecure (Wajib true saat deploy SSL)"
    ];
}

// 3. AUDIT UPLOAD DIRECTORY EXECUTION RESTRICTION
echo "[*] [OWASP A08 / Defense-in-Depth] Memeriksa Proteksi Folder Unggahan...\n";
$uploadDirs = [
    $projectPath . '/public/assets/uploads',
    $projectPath . '/public/uploads'
];

foreach ($uploadDirs as $dir) {
    if (is_dir($dir)) {
        $htaccess = $dir . '/.htaccess';
        $isProtected = false;
        if (file_exists($htaccess)) {
            $htContent = file_get_contents($htaccess);
            if (stripos($htContent, 'Deny from all') !== false || stripos($htContent, 'php_flag engine off') !== false) {
                $isProtected = true;
            }
        }

        $checklist[] = [
            'pillar' => 'Sandboxing',
            'control' => 'Uploads Execution Lock (' . basename($dir) . ')',
            'status' => $isProtected ? 'PASS' : 'WARN',
            'severity' => 'HIGH',
            'detail' => $isProtected ? '.htaccess pemblokir eksekusi PHP aktif' : 'Belum ada .htaccess proteksi eksekusi PHP di folder ini'
        ];
    }
}

// 4. OUTPUT SCORECARD
echo "\n========================================================================================\n";
echo sprintf("%-10s | %-42s | %-6s | %-8s | %s\n", "PILAR", "KONTROL PERTAHANAN (DEFENSE CONTROL)", "STATUS", "SEVERITY", "KETERANGAN");
echo "----------------------------------------------------------------------------------------\n";
$passCount = 0;
foreach ($checklist as $c) {
    if ($c['status'] === 'PASS') $passCount++;
    $statusColor = $c['status'] === 'PASS' ? '[PASS]' : ($c['status'] === 'WARN' ? '[WARN]' : '[FAIL]');
    echo sprintf("%-10s | %-42s | %-6s | %-8s | %s\n", 
        $c['pillar'],
        substr($c['control'], 0, 42), 
        $statusColor, 
        $c['severity'], 
        substr($c['detail'], 0, 75)
    );
}
echo "========================================================================================\n";
$score = count($checklist) > 0 ? round(($passCount / count($checklist)) * 100) : 0;
echo "Blue Team Hardening Score: $score% ($passCount/" . count($checklist) . " lolos kontrol pertahanan)\n";
echo "Gunakan panduan remedi di SKILL.md untuk menutup temuan berstatus [WARN] atau [FAIL].\n\n";
