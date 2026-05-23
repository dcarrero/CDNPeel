<?php
declare(strict_types=1);

require __DIR__ . '/lib/ip-safety.php';
require __DIR__ . '/lib/ratelimit.php';
require __DIR__ . '/lib/dns.php';
require __DIR__ . '/lib/cdn-ranges.php';
require __DIR__ . '/lib/extractor.php';
require __DIR__ . '/lib/http.php';
require __DIR__ . '/lib/osint.php';
require __DIR__ . '/lib/free-osint.php';

set_time_limit(0);
ignore_user_abort(false);

header('Content-Type: text/event-stream; charset=utf-8');
header('Cache-Control: no-cache, no-transform');
header('Connection: keep-alive');
header('X-Accel-Buffering: no'); // nginx: desactivar buffering
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

while (ob_get_level() > 0) { ob_end_flush(); }
@ob_implicit_flush(true);

function emit(string $id, string $status, string $message = '', array $data = []): void
{
    $payload = json_encode(['id' => $id, 'status' => $status, 'message' => $message, 'data' => $data], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    echo "event: step\n";
    echo "data: " . $payload . "\n\n";
    @flush();
}

function fail(string $message): void
{
    emit('fatal', 'error', $message);
    exit;
}

$domain = strtolower(trim((string)($_GET['domain'] ?? '')));
$domain = preg_replace('#^https?://#', '', $domain);
$domain = rtrim($domain, '/');

if ($domain === '' || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
    fail('Invalid domain');
}

// Rate-limit por IP. El SSE ya está abierto, así que devolvemos el motivo
// como evento SSE (id=fatal) en vez de HTTP 429: EventSource no expone el
// status code y, de este modo, el cliente puede mostrar un mensaje útil.
$rl = rl_check(rl_client_ip());
if (!$rl['ok']) {
    rl_audit('rate_limited', ['domain' => $domain, 'retry_after' => $rl['retry_after']]);
    emit('fatal', 'error',
        'Rate limit exceeded: try again in ' . $rl['retry_after'] . 's',
        ['retry_after' => $rl['retry_after'], 'limit' => $rl['limit']]
    );
    exit;
}

// Audit trail mínimo (A09). No registramos keys ni cuerpos, solo IP y dominio.
rl_audit('scan_start', ['domain' => $domain]);

// Las API keys nunca viajan por la URL (quedarían en access logs). El cliente
// las envía por POST a init.php, que devuelve un scan_id one-shot. Aquí
// consumimos ese archivo y lo borramos inmediatamente.
$shodanKey = '';
$censysId = '';
$censysSecret = '';
$otxKey = '';

$scanId = trim((string)($_GET['scan_id'] ?? ''));
if ($scanId !== '') {
    if (!preg_match('/^[a-f0-9]{32}$/', $scanId)) {
        fail('Invalid scan_id format');
    }
    $tokenFile = sys_get_temp_dir() . '/cdnpeel-scans/' . $scanId . '.json';
    if (!is_file($tokenFile)) {
        fail('Unknown or expired scan_id');
    }
    // Expiración: 120 s desde la creación del archivo.
    if (filemtime($tokenFile) < time() - 120) {
        @unlink($tokenFile);
        fail('Expired scan_id');
    }
    $ctx = json_decode((string)file_get_contents($tokenFile), true);
    // One-shot: borramos antes de usarlo para que un reintento no reaproveche.
    @unlink($tokenFile);
    if (is_array($ctx)) {
        $shodanKey    = isset($ctx['shodan_key'])    ? trim((string)$ctx['shodan_key'])    : '';
        $censysId     = isset($ctx['censys_id'])     ? trim((string)$ctx['censys_id'])     : '';
        $censysSecret = isset($ctx['censys_secret']) ? trim((string)$ctx['censys_secret']) : '';
        $otxKey       = isset($ctx['otx_key'])       ? trim((string)$ctx['otx_key'])       : '';
    }
}

$useHackerTarget = ($_GET['use_hackertarget'] ?? '') === '1';
$manualTitle = trim((string)($_GET['manual_title'] ?? ''));

emit('start', 'info', "Scanning $domain", ['domain' => $domain]);

// 1) Registros A
emit('resolve_a', 'running', 'Resolving A records via DoH');
$aIpsRaw = dns_get_a($domain);
$aIps = ip_filter_safe($aIpsRaw);
$unsafeA = array_values(array_diff($aIpsRaw, $aIps));
if (!empty($unsafeA) && empty($aIps)) {
    // El dominio apunta exclusivamente a rangos privados/loopback/metadata:
    // un atacante está intentando convertir el servidor en proxy SSRF.
    fail('Domain resolves only to private/reserved IP ranges — refusing to scan');
}
emit('resolve_a', 'done',
    count($aIps) . ' A record(s)' . (empty($unsafeA) ? '' : ' (' . count($unsafeA) . ' unsafe filtered)'),
    ['ips' => $aIps, 'filtered_unsafe' => $unsafeA]
);

// 2) Clasificación multi-CDN
emit('classify_cdn', 'running', 'Comparing against known CDN ranges');
$cls = classify_cdn_ips($aIps);
$providerCounts = [];
foreach ($cls['by_provider'] as $pid => $ips) {
    $providerCounts[] = cdn_provider_name($pid) . ': ' . count($ips);
}
$cdnMsg = empty($providerCounts) ? 'no CDN detected by IP' : implode(' · ', $providerCounts);
emit('classify_cdn', 'done',
    $cdnMsg . ' · ' . count($cls['non_cdn']) . ' non-CDN',
    [
        'by_provider' => $cls['by_provider'],
        'provider_names' => array_combine(array_keys($cls['by_provider']),
            array_map('cdn_provider_name', array_keys($cls['by_provider']))),
        'non_cdn' => $cls['non_cdn'],
    ]
);

$detectedProviders = array_keys($cls['by_provider']);
$behindCdn = !empty($detectedProviders);
if (!$behindCdn && count($aIps) > 0) {
    emit('cdn_check', 'info', 'Domain does not appear to be behind a known CDN', []);
}

// 3) TXT records
emit('resolve_txt', 'running', 'Resolving TXT records');
$txt = dns_get_txt($domain);
emit('resolve_txt', 'done', count($txt) . ' TXT record(s)', ['records' => $txt]);

// 4) Extraer IPs de TXT/SPF
emit('extract_txt_ips', 'running', 'Extracting IPs from TXT/SPF');
$txtIps = extract_ips_from_txt($txt);
emit('extract_txt_ips', 'done', count($txtIps) . ' IP(s) extracted', ['ips' => $txtIps]);

// === Fuentes gratuitas sin API key ===

// 5a) crt.sh — Certificate Transparency
emit('crtsh_subdomains', 'running', 'Querying Certificate Transparency (crt.sh)');
$crt = crtsh_subdomains($domain);
$subdomains = [];
if ($crt['ok']) {
    $subdomains = $crt['subdomains'];
    emit('crtsh_subdomains', 'done', count($subdomains) . ' subdomain(s) from CT logs', ['subdomains' => $subdomains]);
} else {
    emit('crtsh_subdomains', 'error', $crt['error'] ?? 'crt.sh failed', []);
}

// 5b) HackerTarget hostsearch (opt-in por rate limit)
$htIps = [];
$htPairs = [];
if ($useHackerTarget) {
    emit('hackertarget', 'running', 'Querying HackerTarget hostsearch');
    $ht = hackertarget_hostsearch($domain);
    if ($ht['ok']) {
        $htPairs = $ht['pairs'];
        $htIps = $ht['ips'];
        foreach ($htPairs as $p) {
            if (!in_array($p['host'], $subdomains, true)) $subdomains[] = $p['host'];
        }
        emit('hackertarget', 'done', count($htPairs) . ' host/IP pair(s)', ['pairs' => array_slice($htPairs, 0, 30)]);
    } else {
        emit('hackertarget', 'error', $ht['error'] ?: 'HackerTarget failed', []);
    }
} else {
    emit('hackertarget', 'skipped', 'HackerTarget disabled (opt-in due to 50/day rate limit)');
}

// 5c) Resolver subdominios en paralelo y clasificar
$subdomainNonCfIps = [];
$subdomainSources = []; // ip => [host, host, ...]
if (!empty($subdomains)) {
    emit('resolve_subdomains', 'running', 'Resolving ' . count($subdomains) . ' subdomain(s) in parallel');
    $resolved = dns_multi_resolve_a($subdomains);
    $resolvedCount = array_sum(array_map('count', $resolved));
    emit('resolve_subdomains', 'done',
        count($resolved) . '/' . count($subdomains) . ' resolved, ' . $resolvedCount . ' total IP(s)',
        ['resolved' => $resolved]);

    emit('classify_subdomains', 'running', 'Filtering non-Cloudflare IPs from subdomains');
    foreach ($resolved as $host => $ips) {
        foreach ($ips as $ip) {
            if (!is_cloudflare_ip($ip)) {
                $subdomainNonCfIps[] = $ip;
                $subdomainSources[$ip][] = $host;
            }
        }
    }
    $subdomainNonCfIps = array_values(array_unique($subdomainNonCfIps));
    emit('classify_subdomains', 'done',
        count($subdomainNonCfIps) . ' non-CF IP(s) from related subdomains',
        ['ips' => $subdomainNonCfIps, 'by_ip' => $subdomainSources]);
}

// 5d) OTX passive DNS (sólo si key gratis del usuario)
$otxIps = [];
if ($otxKey !== '') {
    emit('osint_otx', 'running', 'Querying AlienVault OTX passive DNS');
    $otx = otx_passive_dns($domain, $otxKey);
    if ($otx['ok']) {
        $otxIps = $otx['ips'];
        emit('osint_otx', 'done', count($otxIps) . ' historical IP(s) from OTX', ['ips' => $otxIps]);
    } else {
        emit('osint_otx', 'error', $otx['error'] ?: 'OTX failed', []);
    }
} else {
    emit('osint_otx', 'skipped', 'OTX requires free key (otx.alienvault.com)');
}

// === Fuentes con API key (opcionales) ===
$shodanIps = [];
if ($shodanKey !== '') {
    emit('osint_shodan', 'running', 'Querying Shodan');
    $sh = shodan_lookup($domain, $shodanKey);
    if ($sh['ok']) {
        $shodanIps = $sh['ips'];
        emit('osint_shodan', 'done', count($shodanIps) . ' IP(s) from Shodan', ['ips' => $shodanIps]);
    } else {
        emit('osint_shodan', 'error', $sh['error'] ?: 'Shodan error', []);
    }
} else {
    emit('osint_shodan', 'skipped', 'No Shodan key provided');
}

$censysIps = [];
if ($censysId !== '' && $censysSecret !== '') {
    emit('osint_censys', 'running', 'Querying Censys');
    $cs = censys_lookup($domain, $censysId, $censysSecret);
    if ($cs['ok']) {
        $censysIps = $cs['ips'];
        emit('osint_censys', 'done', count($censysIps) . ' IP(s) from Censys', ['ips' => $censysIps]);
    } else {
        emit('osint_censys', 'error', $cs['error'] ?: 'Censys error', []);
    }
} else {
    emit('osint_censys', 'skipped', 'No Censys credentials provided');
}

// 6) Baseline title (a través del CDN si aplica) + detección por headers.
//     Forzamos CURLOPT_RESOLVE a las IPs A ya validadas para evitar DNS rebinding
//     (resolver del sistema podría devolver IPs internas distintas a las de DoH).
emit('fetch_baseline', 'running', "Fetching baseline title for $domain" . ($manualTitle !== '' ? ' (Manual override provided)' : ''));
$baseline = fetch_title_direct($domain, $aIps);
$headerProviders = [];
if ($manualTitle !== '') {
    if ($baseline['ok'] && !empty($baseline['headers'])) {
        $headerProviders = detect_cdn_from_headers($baseline['headers']);
    }
    emit('fetch_baseline', 'done', 'Using manual baseline title: "' . $manualTitle . '"' . ($baseline['ok'] ? ' (HTTP ' . $baseline['status'] . ')' : ' (Fetch failed)'), [
        'title' => $manualTitle,
        'status' => $baseline['status'] ?? 0,
        'header_providers' => $headerProviders,
        'header_provider_names' => array_map('cdn_provider_name', $headerProviders),
    ]);
    $baselineTitle = $manualTitle;
} else {
    if (!$baseline['ok']) {
        emit('fetch_baseline', 'error', $baseline['error'] ?: 'baseline failed');
    } else {
        if (!empty($baseline['headers'])) {
            $headerProviders = detect_cdn_from_headers($baseline['headers']);
        }
        emit('fetch_baseline', 'done', 'HTTP ' . $baseline['status'] . ($baseline['title'] ? ' — ' . $baseline['title'] : ''), [
            'title' => $baseline['title'],
            'status' => $baseline['status'],
            'header_providers' => $headerProviders,
            'header_provider_names' => array_map('cdn_provider_name', $headerProviders),
        ]);
    }
    $baselineTitle = $baseline['title'] ?? null;
}

// Fusionar CDNs detectados por IP y por headers
$detectedProviders = array_values(array_unique(array_merge($detectedProviders, $headerProviders)));
$behindCdn = !empty($detectedProviders);

// 7) Candidatas a IP real: non-CF A + TXT-extracted + OSINT, descartando CF
$candidates = [];
$mark = function (string $ip, string $source, ?string $note = null) use (&$candidates) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return;
    // Bloqueo central de SSRF: rangos privados, loopback, link-local (incluida
    // metadata cloud 169.254.169.254), CGNAT, multicast, reservados y v6 análogos.
    if (!ip_is_safe_target($ip)) return;
    if (is_cloudflare_ip($ip)) return; // descartamos CF
    if (!isset($candidates[$ip])) $candidates[$ip] = ['ip' => $ip, 'sources' => [], 'notes' => []];
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
foreach ($shodanIps as $ip) $mark($ip, 'Shodan');
foreach ($censysIps as $ip) $mark($ip, 'Censys');

emit('candidates', 'done', count($candidates) . ' candidate IP(s)', ['ips' => array_values($candidates)]);

// 8) Enriquecimiento masivo con Shodan InternetDB (paralelo, gratis)
$candidateIps = array_keys($candidates);
$idbMap = [];
if (!empty($candidateIps)) {
    emit('enrich_internetdb', 'running', 'Querying Shodan InternetDB in parallel for ' . count($candidateIps) . ' IP(s)');
    $idbMap = shodan_internetdb_multi($candidateIps);
    $hits = count(array_filter($idbMap));
    emit('enrich_internetdb', 'done', $hits . '/' . count($candidateIps) . ' IP(s) with InternetDB data', []);
}

// 9) Validar todas las candidatas en paralelo (curl_multi)
$results = [];
$totalCandidates = count($candidates);

if ($totalCandidates > 0) {
    // Emitir "running" para todas de golpe (visualización inicial)
    foreach ($candidates as $ip => $meta) {
        $stepId = 'validate_' . preg_replace('/[^a-zA-Z0-9]/', '_', $ip);
        emit($stepId, 'running', "Probing $ip with Host: $domain", [
            'ip' => $ip,
            'sources' => $meta['sources'],
            'notes' => $meta['notes'],
            'internetdb' => $idbMap[$ip] ?? null,
        ]);
    }

    $onResult = function (string $ip, array $probe) use ($candidates, $baselineTitle, $idbMap, &$results) {
        $meta = $candidates[$ip] ?? ['sources' => [], 'notes' => []];
        $stepId = 'validate_' . preg_replace('/[^a-zA-Z0-9]/', '_', $ip);
        $idb = $idbMap[$ip] ?? null;

        if (!$probe['ok']) {
            emit($stepId, 'error', $probe['error'] ?: 'unreachable', [
                'ip' => $ip,
                'sources' => $meta['sources'],
                'notes' => $meta['notes'],
                'internetdb' => $idb,
            ]);
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
            ];
            return;
        }

        $match = $baselineTitle !== null && titles_match($baselineTitle, $probe['title']);
        $verdict = $match ? 'origin_ip' : 'no_match';
        emit($stepId, $match ? 'match' : 'no-match',
            ($probe['scheme'] . ' ' . $probe['status']) . ($probe['title'] ? ' — ' . $probe['title'] : ''),
            [
                'ip' => $ip,
                'sources' => $meta['sources'],
                'notes' => $meta['notes'],
                'status' => $probe['status'],
                'title' => $probe['title'],
                'scheme' => $probe['scheme'],
                'match' => $match,
                'internetdb' => $idb,
            ]);
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
        ];
    };

    fetch_titles_via_ips_multi($domain, $candidateIps, $onResult, concurrency: 12, timeout: 6);
}

emit('summary', 'done', 'Scan complete', [
    'domain' => $domain,
    'behind_cdn' => $behindCdn,
    'cdn_providers' => $detectedProviders,
    'cdn_provider_names' => array_map('cdn_provider_name', $detectedProviders),
    'baseline_title' => $baselineTitle,
    'results' => $results,
]);
