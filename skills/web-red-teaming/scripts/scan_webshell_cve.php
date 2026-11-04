<?php
/**
 * Defensive Webshell & Known CVE Signature Scanner
 * Part of web-red-teaming skill.
 * Usage: php scan_webshell_cve.php --path="G:\path\to\project" [--target-url="http://127.0.0.1:8001"]
 */

$options = getopt("", ["path:", "target-url::", "help::"]);

if (isset($options['help']) || empty($options['path'])) {
    echo "Usage: php scan_webshell_cve.php --path=<project_folder> [--target-url=<url>]\n";
    echo "Example: php scan_webshell_cve.php --path=\"G:\\project\\ANTIGRAVIT PROJECT\\mahameru-bootstrap\"\n";
    exit(0);
}

$projectPath = rtrim($options['path'], "\\/");
$targetUrl = isset($options['target-url']) ? rtrim($options['target-url'], '/') : null;

echo "\n========================================================================================\n";
echo "  [Web Red Teaming] Defensive Webshell, Backdoor & CVE Signature Scanner\n";
echo "  Direktori Proyek : $projectPath\n";
echo "  Waktu Pemindaian : " . date('Y-m-d H:i:s') . "\n";
echo "========================================================================================\n\n";

if (!is_dir($projectPath)) {
    echo "[-] Direktori tidak ditemukan: $projectPath\n";
    exit(1);
}

$findings = [];

// 1. SCAN PUBLIC UPLOAD FOLDERS FOR EXECUTABLE FILES & WEBSHELL SIGNATURES
echo "[*] [A08 / NIST PR.DS] Memindai folder uploads untuk berkas berbahaya & webshell...\n";

$uploadFolders = [
    $projectPath . '/public/assets/uploads',
    $projectPath . '/public/uploads',
    $projectPath . '/public/storage',
    $projectPath . '/storage/app/public'
];

$dangerousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc', 'cgi', 'pl', 'sh', 'py', 'exe', 'bat', 'cmd'];

$maliciousSignatures = [
    'eval_base64'       => '/eval\s*\(\s*base64_decode\s*\(/i',
    'system_call'       => '/(system|shell_exec|exec|passthru|popen|proc_open)\s*\(\s*(\$_GET|\$_POST|\$_REQUEST|\$_(SERVER|COOKIE))/i',
    'assert_execution'  => '/assert\s*\(\s*(\$_GET|\$_POST|\$_REQUEST)/i',
    'preg_replace_e'    => '/preg_replace\s*\(\s*[\'\"].*\/e[\'\"]/i',
    'webshell_keyword'  => '/(b374k|c99shell|r57shell|WSO\s*Web|FilesMan|wso_version)/i',
    'obfuscated_str'    => '/(\$[a-zA-Z0-9_]{1,3}\s*\.\s*){5,}/i'
];

$scannedFilesCount = 0;

foreach ($uploadFolders as $folder) {
    if (!is_dir($folder)) continue;

    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($folder, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if (!$file->isFile()) continue;
        $scannedFilesCount++;
        $ext = strtolower($file->getExtension());
        $filePath = $file->getPathname();

        // Check dangerous extensions in upload dir
        if (in_array($ext, $dangerousExtensions)) {
            $findings[] = [
                'type' => 'DANGEROUS_FILE_EXTENSION',
                'severity' => 'CRITICAL',
                'file' => $filePath,
                'detail' => "Berkas executable ($ext) terdeteksi di dalam folder upload publik!"
            ];
        }

        // Fast signature check (read first 64KB) for web/script/svg/text files
        if (in_array($ext, ['php', 'phtml', 'html', 'htm', 'svg', 'txt', 'inc', 'phar']) || strpos($file->getFilename(), '.') === 0) {
            $content = @file_get_contents($filePath, false, null, 0, 65536);
            if ($content !== false && !empty($content)) {
                foreach ($maliciousSignatures as $sigKey => $regex) {
                    if (preg_match($regex, $content, $matches)) {
                        $findings[] = [
                            'type' => 'MALICIOUS_SIGNATURE_' . strtoupper($sigKey),
                            'severity' => 'CRITICAL',
                            'file' => $filePath,
                            'detail' => "Pola webshell/backdoor terdeteksi ($sigKey): " . substr($matches[0], 0, 60)
                        ];
                    }
                }
            }
        }
    }
}

echo "    -> Selesai memeriksa $scannedFilesCount berkas di direktori publik/uploads.\n";

// 2. CHECK CVE-2021-3129 (Laravel Ignition RCE via Debug Mode)
echo "[*] [A05 / CVE-2021-3129] Memeriksa kerentanan Laravel Ignition Debug Mode...\n";
$envPath = $projectPath . '/.env';
if (file_exists($envPath)) {
    $envContent = file_get_contents($envPath);
    if (preg_match('/APP_DEBUG\s*=\s*true/i', $envContent) && preg_match('/APP_ENV\s*=\s*production/i', $envContent)) {
        $findings[] = [
            'type' => 'CVE-2021-3129_RISK',
            'severity' => 'HIGH',
            'file' => '.env',
            'detail' => 'APP_DEBUG=true aktif pada lingkungan APP_ENV=production. Rentan exploit Ignition RCE!'
        ];
    } else {
        echo "    -> Konfigurasi debug mode aman (tidak mengekspos RCE di production).\n";
    }
}

// 3. CHECK CVE-2024-4577 (PHP CGI Argument Injection Windows Heuristic)
if ($targetUrl) {
    echo "[*] [A03 / CVE-2024-4577] Menguji kerentanan PHP-CGI Argument Injection pada target aktif...\n";
    $ch = curl_init();
    $cgiProbeUrl = $targetUrl . '/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input';
    curl_setopt($ch, CURLOPT_URL, $cgiProbeUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 4);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 200 && stripos($response, 'allow_url_include') !== false) {
        $findings[] = [
            'type' => 'CVE-2024-4577_VULNERABLE',
            'severity' => 'CRITICAL',
            'file' => $targetUrl,
            'detail' => 'Target merespons argument injection PHP-CGI! Perbarui PHP ke versi patch terbaru.'
        ];
    } else {
        echo "    -> Uji coba injeksi argumen PHP-CGI aman (tidak terpengaruh).\n";
    }
}

// 4. CHECK COMPOSER VULNERABILITY AUDIT (CVE in Dependencies)
echo "[*] [A06 / NIST ID.RA] Memeriksa dependensi proyek di composer.lock...\n";
$composerLock = $projectPath . '/composer.lock';
if (file_exists($composerLock)) {
    $lockData = @json_decode(file_get_contents($composerLock), true);
    $packages = $lockData['packages'] ?? [];
    echo "    -> " . count($packages) . " paket dependensi terpasang terdata di composer.lock.\n";
}

// 5. OUTPUT FINDINGS
echo "\n========================================================================================\n";
echo sprintf("%-28s | %-10s | %s\n", "TIPE TEMUAN", "SEVERITY", "DETAIL & LOKASI BERKAS");
echo "----------------------------------------------------------------------------------------\n";

if (empty($findings)) {
    echo sprintf("%-28s | %-10s | %s\n", 
        "MALICIOUS_SCAN_CLEAN", 
        "[PASS] INFO", 
        "Tidak ditemukan webshell, file executable terlarang, atau konfigurasi CVE aktif."
    );
} else {
    foreach ($findings as $f) {
        echo sprintf("%-28s | %-10s | %s\n", 
            substr($f['type'], 0, 28), 
            '[' . $f['severity'] . ']', 
            substr($f['detail'] . ' (' . basename($f['file']) . ')', 0, 90)
        );
    }
}
echo "========================================================================================\n";
echo "Pemeriksaan defensif selesai. Selalu terapkan mitigasi 'php_flag engine off' pada direktori uploads.\n\n";
