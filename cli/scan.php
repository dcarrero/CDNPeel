<?php
declare(strict_types=1);

// Ensure we are running from CLI
if (PHP_SAPI !== 'cli') {
    echo "This script can only be run from the command line.\n";
    exit(1);
}

// Import libraries
require_once __DIR__ . '/../api/lib/ip-safety.php';
require_once __DIR__ . '/../api/lib/dns.php';
require_once __DIR__ . '/../api/lib/cdn-ranges.php';
require_once __DIR__ . '/../api/lib/extractor.php';
require_once __DIR__ . '/../api/lib/http.php';
require_once __DIR__ . '/../api/lib/osint.php';
require_once __DIR__ . '/../api/lib/free-osint.php';

// Define ANSI Colors
define('C_RESET', "\033[0m");
define('C_BOLD', "\033[1m");
define('C_RED', "\033[31m");
define('C_GREEN', "\033[32m");
define('C_YELLOW', "\033[33m");
define('C_BLUE', "\033[34m");
define('C_MAGENTA', "\033[35m");
define('C_CYAN', "\033[36m");
define('C_GRAY', "\033[90m");

// Parse arguments
$shortopts = "d:s:hm:";
$longopts = [
    "domain:",
    "shodan:",
    "censys-id:",
    "censys-secret:",
    "otx:",
    "use-hackertarget",
    "manual-title:",
    "help"
];
$options = getopt($shortopts, $longopts);

function show_help(): void {
    echo C_BOLD . C_CYAN . "=====================================================" . C_RESET . "\n";
    echo C_BOLD . C_YELLOW . "  CDNPeel CLI Help Guide" . C_RESET . "\n";
    echo C_BOLD . C_CYAN . "=====================================================" . C_RESET . "\n";
    echo C_BOLD . "Usage:" . C_RESET . " php cli/scan.php -d <domain> [options]\n\n";
    echo C_BOLD . "Required Options:" . C_RESET . "\n";
    echo "  -d, --domain <domain>        Target domain to scan\n\n";
    echo C_BOLD . "Configurable Options:" . C_RESET . "\n";
    echo "  -s, --shodan <key>           Shodan API key for DNS and favicon searches\n";
    echo "      --censys-id <id>         Censys API ID\n";
    echo "      --censys-secret <secret> Censys API Secret\n";
    echo "      --otx <key>              AlienVault OTX API key\n";
    echo "  -h, --use-hackertarget       Enable HackerTarget search (subject to rate limit)\n";
    echo "  -m, --manual-title <title>   Manually specify baseline title (bypasses CDN block)\n";
    echo "      --help                   Show this help menu\n\n";
    echo C_BOLD . "Example:" . C_RESET . "\n";
    echo "  php cli/scan.php -d target.com -h -s YOUR_SHODAN_KEY -m \"Welcome to Target\"\n";
    echo C_BOLD . C_CYAN . "=====================================================" . C_RESET . "\n";
}

if (isset($options['help']) || (!isset($options['d']) && !isset($options['domain']))) {
    show_help();
    exit(0);
}

$domain = isset($options['d']) ? (string)$options['d'] : (string)($options['domain'] ?? '');
$shodanKey = isset($options['s']) ? (string)$options['s'] : (string)($options['shodan'] ?? '');
$censysId = (string)($options['censys-id'] ?? '');
$censysSecret = (string)($options['censys-secret'] ?? '');
$otxKey = (string)($options['otx'] ?? '');
$useHackerTarget = isset($options['h']) || isset($options['use-hackertarget']);
$manualTitle = isset($options['m']) ? (string)$options['m'] : (string)($options['manual-title'] ?? '');

$domain = strtolower(trim($domain));
$domain = preg_replace('#^https?://#', '', $domain);
$domain = rtrim($domain, '/');

if ($domain === '' || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
    echo C_BOLD . C_RED . "[-] Error: Invalid target domain." . C_RESET . "\n";
    exit(1);
}

/**
 * Quita códigos de control (ANSI/OSC/etc.) de cadenas que vienen de orígenes
 * no confiables: el dominio puede devolver títulos con secuencias que
 * spoofeen la tabla de resultados o abusen del terminal del analista.
 */
function sanitize_terminal_text(string $s): string
{
    return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '?', $s) ?? '';
}

// Banner display
echo C_BOLD . C_CYAN . "=====================================================" . C_RESET . "\n";
echo C_BOLD . C_YELLOW . "  CDNPeel " . C_RESET . C_GRAY . "- Origin IP Discovery CLI (v1.9.2)\n" . C_RESET;
echo C_BOLD . C_CYAN . "=====================================================" . C_RESET . "\n";
echo C_BOLD . "Target:  " . C_RESET . C_CYAN . $domain . C_RESET . "\n";
if ($manualTitle !== '') {
    echo C_BOLD . "Manual baseline title: " . C_RESET . C_YELLOW . '"' . sanitize_terminal_text($manualTitle) . '"' . C_RESET . "\n";
}
echo C_BOLD . C_CYAN . "-----------------------------------------------------" . C_RESET . "\n\n";

function log_step(string $prefix, string $msg, string $color = C_BLUE): void {
    echo $color . $prefix . C_RESET . " " . $msg . "\n";
}

// 1) Resolve A + AAAA via DoH (ambas familias filtradas por ip_filter_safe).
log_step("[*]", "Resolving A/AAAA records via DoH...");
$aIpsRaw = array_values(array_unique(array_merge(dns_get_a($domain), dns_get_aaaa($domain))));
$aIps = ip_filter_safe($aIpsRaw);
$unsafeA = array_values(array_diff($aIpsRaw, $aIps));
if (empty($aIps)) {
    if (!empty($unsafeA)) {
        log_step("[-]", "Domain resolves only to private/reserved IP ranges. SSRF attempt detected. Aborting.", C_RED);
    } else {
        log_step("[-]", "Domain has no A/AAAA records.", C_RED);
    }
    exit(1);
}
log_step("[+]", count($aIps) . " A/AAAA record(s) resolved" . (empty($unsafeA) ? "" : " (" . count($unsafeA) . " unsafe filtered)"), C_GREEN);

// 2) Classify CDN
log_step("[*]", "Checking CDN IP ranges...");
$cls = classify_cdn_ips($aIps);
$providerCounts = [];
foreach ($cls['by_provider'] as $pid => $ips) {
    $providerCounts[] = cdn_provider_name($pid) . ': ' . count($ips);
}
$cdnMsg = empty($providerCounts) ? 'No CDN detected by IP' : implode(' · ', $providerCounts);
log_step("[+]", $cdnMsg . " · " . count($cls['non_cdn']) . " non-CDN IP(s)", C_GREEN);
$detectedProviders = array_keys($cls['by_provider']);
$behindCdn = !empty($detectedProviders);

// 3) TXT records
log_step("[*]", "Resolving TXT records...");
$txt = dns_get_txt($domain);
log_step("[+]", count($txt) . " TXT record(s) found", C_GREEN);

// 4) Extract IPs from TXT/SPF
log_step("[*]", "Extracting IPs from TXT/SPF...");
$txtIps = extract_ips_from_txt($txt);
log_step("[+]", count($txtIps) . " IP(s) extracted", C_GREEN);

// 5a) crt.sh subdomains
log_step("[*]", "Querying Certificate Transparency (crt.sh)...");
$crt = crtsh_subdomains($domain);
$subdomains = [];
if ($crt['ok']) {
    $subdomains = $crt['subdomains'];
    log_step("[+]", count($subdomains) . " subdomain(s) from crt.sh", C_GREEN);
} else {
    log_step("[!]", "crt.sh failed: " . ($crt['error'] ?? 'unknown error'), C_YELLOW);
}

// 5b) HackerTarget hostsearch
$htIps = [];
if ($useHackerTarget) {
    log_step("[*]", "Querying HackerTarget hostsearch...");
    $ht = hackertarget_hostsearch($domain);
    if ($ht['ok']) {
        $htIps = $ht['ips'];
        foreach ($ht['pairs'] as $p) {
            if (!in_array($p['host'], $subdomains, true)) $subdomains[] = $p['host'];
        }
        log_step("[+]", count($ht['pairs']) . " host/IP pair(s) from HackerTarget", C_GREEN);
    } else {
        log_step("[!]", "HackerTarget failed: " . ($ht['error'] ?: 'unknown error'), C_YELLOW);
    }
} else {
    log_step("[!]", "HackerTarget skipped (opt-in)", C_YELLOW);
}

// 5c) Resolve subdomains in parallel
$subdomainNonCfIps = [];
$subdomainSources = [];
if (!empty($subdomains)) {
    log_step("[*]", "Resolving " . count($subdomains) . " subdomain(s) in parallel...");
    $resolved = dns_multi_resolve_a($subdomains);
    $resolvedCount = array_sum(array_map('count', $resolved));
    log_step("[+]", count($resolved) . "/" . count($subdomains) . " subdomains resolved, " . $resolvedCount . " IP(s) found", C_GREEN);

    log_step("[*]", "Filtering CDN IPs from subdomains (all 13 providers)...");
    foreach ($resolved as $host => $ips) {
        foreach ($ips as $ip) {
            // No solo Cloudflare: una IP de borde de Fastly/CloudFront/Akamai
            // puede devolver el title de la página pública y falsear "origen".
            if (!is_cdn_ip($ip)) {
                $subdomainNonCfIps[] = $ip;
                $subdomainSources[$ip][] = $host;
            }
        }
    }
    $subdomainNonCfIps = array_values(array_unique($subdomainNonCfIps));
    log_step("[+]", count($subdomainNonCfIps) . " non-CF IP(s) from related subdomains", C_GREEN);
}

// 5d) OTX passive DNS
$otxIps = [];
if ($otxKey !== '') {
    log_step("[*]", "Querying AlienVault OTX passive DNS...");
    $otx = otx_passive_dns($domain, $otxKey);
    if ($otx['ok']) {
        $otxIps = $otx['ips'];
        log_step("[+]", count($otxIps) . " historical IP(s) from OTX", C_GREEN);
    } else {
        log_step("[!]", "OTX failed: " . ($otx['error'] ?: 'unknown error'), C_YELLOW);
    }
} else {
    log_step("[!]", "OTX skipped (no API key provided)", C_YELLOW);
}

// Favicon Hashing
$faviconMd5 = null;
$faviconMmh3 = null;
log_step("[*]", "Downloading and hashing favicon...");
$faviconBytes = fetch_favicon_bytes($domain, $aIps);
if ($faviconBytes !== null) {
    $hashes = calculate_favicon_hashes($faviconBytes);
    $faviconMd5 = $hashes['md5'];
    $faviconMmh3 = $hashes['mmh3'];
    log_step("[+]", "Favicon hashes: MMH3 {$faviconMmh3} · MD5 {$faviconMd5}", C_GREEN);
} else {
    log_step("[!]", "Favicon not found or download failed", C_YELLOW);
}

// Shodan DNS + Favicon
$shodanDnsIps = [];
$shFavIps = [];
if ($shodanKey !== '') {
    log_step("[*]", "Querying Shodan...");
    $sh = shodan_lookup($domain, $shodanKey);
    if ($sh['ok']) {
        $shodanDnsIps = $sh['ips'];
    }
    
    $favMsg = '';
    if ($faviconMmh3 !== null) {
        $shFav = shodan_favicon_search($faviconMmh3, $shodanKey);
        if ($shFav['ok'] && !empty($shFav['ips'])) {
            $shFavIps = $shFav['ips'];
            $favMsg = ' · ' . count($shFavIps) . ' from favicon hash';
        }
    }
    
    $shTotalIps = array_values(array_unique(array_merge($shodanDnsIps, $shFavIps)));
    if ($sh['ok'] || !empty($shFavIps)) {
        log_step("[+]", count($shTotalIps) . " IP(s) from Shodan (DNS: " . count($shodanDnsIps) . $favMsg . ")", C_GREEN);
    } else {
        log_step("[!]", "Shodan query failed: " . ($sh['error'] ?: 'unknown error'), C_YELLOW);
    }
} else {
    log_step("[!]", "Shodan skipped (no key provided)", C_YELLOW);
}

// Censys DNS + Favicon
$censysDnsIps = [];
$csFavIps = [];
if ($censysId !== '' && $censysSecret !== '') {
    log_step("[*]", "Querying Censys...");
    $cs = censys_lookup($domain, $censysId, $censysSecret);
    if ($cs['ok']) {
        $censysDnsIps = $cs['ips'];
    }
    
    $favMsg = '';
    if ($faviconMd5 !== null) {
        $csFav = censys_favicon_search($faviconMd5, $censysId, $censysSecret);
        if ($csFav['ok'] && !empty($csFav['ips'])) {
            $csFavIps = $csFav['ips'];
            $favMsg = ' · ' . count($csFavIps) . ' from favicon hash';
        }
    }
    
    $csTotalIps = array_values(array_unique(array_merge($censysDnsIps, $csFavIps)));
    if ($cs['ok'] || !empty($csFavIps)) {
        log_step("[+]", count($csTotalIps) . " IP(s) from Censys (DNS: " . count($censysDnsIps) . $favMsg . ")", C_GREEN);
    } else {
        log_step("[!]", "Censys query failed: " . ($cs['error'] ?: 'unknown error'), C_YELLOW);
    }
} else {
    log_step("[!]", "Censys skipped (no credentials provided)", C_YELLOW);
}

// Fetch Baseline Title
log_step("[*]", "Fetching baseline title...");
$baseline = fetch_title_direct($domain, $aIps);
$headerProviders = [];
if ($manualTitle !== '') {
    if ($baseline['ok'] && !empty($baseline['headers'])) {
        $headerProviders = detect_cdn_from_headers($baseline['headers']);
    }
    log_step("[+]", "Using manual baseline title: \"" . sanitize_terminal_text($manualTitle) . "\"" . ($baseline['ok'] ? " (HTTP {$baseline['status']})" : " (Fetch failed)"), C_GREEN);
    $baselineTitle = $manualTitle;
} else {
    if (!$baseline['ok']) {
        log_step("[!]", "Baseline fetch failed: " . sanitize_terminal_text($baseline['error'] ?: 'unknown error'), C_YELLOW);
        $baselineTitle = null;
    } else {
        if (!empty($baseline['headers'])) {
            $headerProviders = detect_cdn_from_headers($baseline['headers']);
        }
        log_step("[+]", "Baseline fetched: " . ($baseline['title'] ? "\"" . sanitize_terminal_text($baseline['title']) . "\"" : "[No title]") . " (HTTP {$baseline['status']})", C_GREEN);
        $baselineTitle = $baseline['title'] ?? null;
    }
}

// Merge header providers
$detectedProviders = array_values(array_unique(array_merge($detectedProviders, $headerProviders)));
$behindCdn = !empty($detectedProviders);

// Merge all candidate sources
$candidates = [];
$mark = function (string $ip, string $source, ?string $note = null) use (&$candidates) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return;
    if (!ip_is_safe_target($ip)) return;
    // Filtramos cualquier CDN reconocido, no solo Cloudflare.
    if (is_cdn_ip($ip)) return;
    if (!isset($candidates[$ip])) {
        $candidates[$ip] = ['ip' => $ip, 'sources' => [], 'notes' => []];
    }
    if (!in_array($source, $candidates[$ip]['sources'], true)) {
        $candidates[$ip]['sources'][] = $source;
    }
    if ($note !== null && !in_array($note, $candidates[$ip]['notes'], true)) {
        $candidates[$ip]['notes'][] = $note;
    }
};

foreach ($cls['non_cdn'] as $ip) $mark($ip, 'A');
foreach ($txtIps as $ip) $mark($ip, 'TXT');
foreach ($subdomainNonCfIps as $ip) {
    $hosts = $subdomainSources[$ip] ?? [];
    $note = empty($hosts) ? null : 'via ' . implode(',', array_slice($hosts, 0, 2));
    $mark($ip, 'subdomain', $note);
}
foreach ($otxIps as $ip) $mark($ip, 'OTX');
foreach ($htIps as $ip) $mark($ip, 'HackerTarget');
foreach ($shodanDnsIps as $ip) $mark($ip, 'Shodan');
foreach ($shFavIps as $ip) $mark($ip, 'Shodan', 'favicon');
foreach ($censysDnsIps as $ip) $mark($ip, 'Censys');
foreach ($csFavIps as $ip) $mark($ip, 'Censys', 'favicon');

log_step("[+]", count($candidates) . " candidate IP(s) found", C_GREEN);

// Shodan InternetDB Enrichment
$candidateIps = array_keys($candidates);
$idbMap = [];
if (!empty($candidateIps)) {
    log_step("[*]", "Enriching candidates with Shodan InternetDB...");
    $idbMap = shodan_internetdb_multi($candidateIps);
    $hits = count(array_filter($idbMap));
    log_step("[+]", "$hits/" . count($candidateIps) . " IP(s) enriched", C_GREEN);
}

// Probing candidate IPs
$results = [];
if (!empty($candidates)) {
    log_step("[*]", "Probing candidate IPs in parallel...");
    
    $onResult = function (string $ip, array $probe) use ($candidates, $baselineTitle, $idbMap, &$results) {
        $meta = $candidates[$ip] ?? ['sources' => [], 'notes' => []];
        $idb = $idbMap[$ip] ?? null;
        
        if (!$probe['ok']) {
            $results[] = [
                'ip' => $ip,
                'sources' => $meta['sources'],
                'notes' => $meta['notes'],
                'reachable' => false,
                'status' => 0,
                'title' => null,
                'match' => false,
                'verdict' => 'unreachable',
                'internetdb' => $idb,
                'error' => $probe['error'] ?: 'unreachable'
            ];
            // Live validation feedback
            echo C_RED . "  [-] " . str_pad($ip, 15) . C_RESET . " | Unreachable (" . sanitize_terminal_text($probe['error'] ?: 'timeout') . ")\n";
            return;
        }
        
        $match = $baselineTitle !== null && titles_match($baselineTitle, $probe['title']);
        $verdict = $match ? 'origin_ip' : 'no_match';
        
        $results[] = [
            'ip' => $ip,
            'sources' => $meta['sources'],
            'notes' => $meta['notes'],
            'reachable' => true,
            'status' => $probe['status'],
            'title' => $probe['title'],
            'match' => $match,
            'verdict' => $verdict,
            'internetdb' => $idb,
            'scheme' => $probe['scheme']
        ];
        
        // Live validation feedback
        $safeTitle = $probe['title'] ? sanitize_terminal_text($probe['title']) : '[No title]';
        if ($match) {
            echo C_GREEN . C_BOLD . "  [+] " . str_pad($ip, 15) . C_RESET . C_GREEN . " | HTTP " . $probe['status'] . " | MATCH! 🌟 (" . $safeTitle . ")\n" . C_RESET;
        } else {
            echo C_YELLOW . "  [!] " . str_pad($ip, 15) . C_RESET . " | HTTP " . $probe['status'] . " | No match (" . $safeTitle . ")\n";
        }
    };
    
    fetch_titles_via_ips_multi($domain, $candidateIps, $onResult, concurrency: 12, timeout: 6);
}

// Print Report Table
echo "\n" . C_BOLD . C_CYAN . "======================================= RESULTS SUMMARY =======================================" . C_RESET . "\n";
if (empty($results)) {
    echo C_YELLOW . "No non-CDN candidate IPs discovered." . C_RESET . "\n";
} else {
    // Print ASCII Table
    $ipWidth = 15;
    $statusWidth = 6;
    $verdictWidth = 15;
    $sourcesWidth = 18;
    $titleWidth = 35;
    
    $line = "+" . str_repeat("-", $ipWidth + 2) . "+" . str_repeat("-", $statusWidth + 2) . "+" . str_repeat("-", $verdictWidth + 2) . "+" . str_repeat("-", $sourcesWidth + 2) . "+" . str_repeat("-", $titleWidth + 2) . "+\n";
    
    echo $line;
    echo sprintf("| %-" . $ipWidth . "s | %-" . $statusWidth . "s | %-" . $verdictWidth . "s | %-" . $sourcesWidth . "s | %-" . $titleWidth . "s |\n", "IP", "Status", "Verdict", "Sources", "Title");
    echo $line;
    
    foreach ($results as $r) {
        $ip = $r['ip'];
        $status = $r['status'] > 0 ? (string)$r['status'] : '—';
        
        if ($r['verdict'] === 'origin_ip') {
            $verdict = "ORIGIN IP ✅";
            $vColor = C_GREEN . C_BOLD;
        } elseif ($r['verdict'] === 'no_match') {
            $verdict = "NO MATCH ⚠️";
            $vColor = C_YELLOW;
        } else {
            $verdict = "UNREACHABLE ❌";
            $vColor = C_RED;
        }
        
        $srcs = implode(',', $r['sources']);
        if (!empty($r['notes'])) {
            $srcs .= " (" . implode(',', $r['notes']) . ")";
        }
        
        $title = $r['title'] !== null ? sanitize_terminal_text($r['title']) : '';
        if (mb_strlen($title) > $titleWidth) {
            $title = mb_substr($title, 0, $titleWidth - 3) . '...';
        }
        
        // Print with ANSI colors for the verdict
        echo sprintf(
            "| %-" . $ipWidth . "s | %-" . $statusWidth . "s | %s%-" . $verdictWidth . "s%s | %-" . $sourcesWidth . "s | %-" . $titleWidth . "s |\n",
            $ip,
            $status,
            $vColor,
            $verdict,
            C_RESET,
            mb_strimwidth($srcs, 0, $sourcesWidth),
            $title
        );
    }
    echo $line;
}
echo C_BOLD . C_CYAN . "===============================================================================================" . C_RESET . "\n\n";
