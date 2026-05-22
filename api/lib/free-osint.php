<?php
declare(strict_types=1);

require_once __DIR__ . '/curl-safe.php';

/**
 * Fuentes de OSINT gratuitas y sin API key.
 *
 * - crt.sh           → subdominios desde Certificate Transparency
 * - AlienVault OTX   → passive DNS histórico (sin key, lectura anónima)
 * - HackerTarget     → hostsearch (gratis pero rate-limit duro: 50/día por IP)
 * - Shodan InternetDB→ enriquecimiento por IP (hostnames, ports, vulns)
 */

// crt.sh bloquea UAs no-navegador; usamos uno realista para todas las llamadas.
const FOSINT_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
const FOSINT_MAX_SUBDOMAINS = 100;   // tope para evitar dominios enormes (google, fb…)
const FOSINT_RESOLVE_CONCURRENCY = 12;
const FOSINT_RESOLVE_TIMEOUT = 5;

/**
 * Resuelve en paralelo registros A para una lista de hostnames vía DoH.
 * Devuelve ['hostname' => [ip, ip, ...], ...] sólo para los que respondieron con IPs válidas.
 */
function dns_multi_resolve_a(array $names, int $concurrency = FOSINT_RESOLVE_CONCURRENCY, int $timeout = FOSINT_RESOLVE_TIMEOUT): array
{
    $names = array_values(array_unique(array_filter(array_map('strtolower', $names))));
    $results = [];
    if (empty($names)) return $results;

    $multi = curl_multi_init();
    $active = [];

    $start = function (string $name) use (&$multi, &$active, $timeout) {
        $url = 'https://cloudflare-dns.com/dns-query?' . http_build_query(['name' => $name, 'type' => 'A']);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => FOSINT_UA,
        ]);
        curl_multi_add_handle($multi, $ch);
        $active[spl_object_id($ch)] = ['handle' => $ch, 'name' => $name];
    };

    $idx = 0;
    while ($idx < count($names) && count($active) < $concurrency) {
        $start($names[$idx++]);
    }

    do {
        do {
            $status = curl_multi_exec($multi, $running);
        } while ($status === CURLM_CALL_MULTI_PERFORM);

        if ($running) curl_multi_select($multi, 0.5);

        while ($info = curl_multi_info_read($multi)) {
            $ch = $info['handle'];
            $oid = spl_object_id($ch);
            $name = $active[$oid]['name'] ?? '';
            $body = curl_multi_getcontent($ch);
            $ips = [];
            if (is_string($body) && $body !== '') {
                $json = json_decode($body, true);
                foreach (($json['Answer'] ?? []) as $ans) {
                    if ((int)($ans['type'] ?? 0) === 1 && !empty($ans['data'])) {
                        $ip = trim((string)$ans['data']);
                        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            $ips[] = $ip;
                        }
                    }
                }
            }
            if (!empty($ips)) $results[$name] = array_values(array_unique($ips));
            curl_multi_remove_handle($multi, $ch);
            unset($active[$oid]);

            if ($idx < count($names)) $start($names[$idx++]);
        }
    } while ($running > 0 || !empty($active));

    curl_multi_close($multi);
    return $results;
}

/**
 * crt.sh — subdominios desde Certificate Transparency logs.
 * Devuelve hostnames únicos del dominio objetivo (filtrados al sufijo).
 */
function crtsh_subdomains(string $domain, int $timeout = 18, int $max = FOSINT_MAX_SUBDOMAINS): array
{
    // crt.sh está crónicamente inestable (502/timeouts). Hacemos 2 intentos con backoff corto.
    $url = 'https://crt.sh/?q=' . rawurlencode('%.' . $domain) . '&output=json';
    $body = null;
    $code = 0;
    $err = '';
    for ($attempt = 1; $attempt <= 2; $attempt++) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => FOSINT_UA,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_ENCODING => '', // permite gzip
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $errno = curl_errno($ch);
        $err = curl_error($ch);
        unset($ch);
        if ($body !== false && $code === 200) break;
        if ($attempt === 1) usleep(800_000); // 0.8s antes del retry
    }

    if ($body === false || $code !== 200) {
        $safe = safe_curl_error($errno, $err);
        return ['ok' => false, 'subdomains' => [], 'error' => $safe ?: "HTTP $code (crt.sh suele estar inestable)"];
    }

    // crt.sh a veces devuelve JSON inválido cuando hay miles de filas;
    // intentamos un fallback "pegando" objetos separados por }{ → },{ y envolviendo.
    $json = json_decode($body, true);
    if (!is_array($json)) {
        $fixed = '[' . preg_replace('/}\s*\{/', '},{', trim($body)) . ']';
        $json = json_decode($fixed, true);
    }
    if (!is_array($json)) {
        return ['ok' => false, 'subdomains' => [], 'error' => 'invalid JSON from crt.sh'];
    }

    $set = [];
    $suffix = '.' . strtolower($domain);
    foreach ($json as $row) {
        $val = (string)($row['name_value'] ?? '');
        if ($val === '') continue;
        foreach (preg_split('/\s+/', $val) as $name) {
            $name = strtolower(trim($name, " \t.\n\r"));
            if ($name === '') continue;
            if ($name[0] === '*') continue; // descartamos wildcards
            if ($name === strtolower($domain) || str_ends_with($name, $suffix)) {
                if (filter_var($name, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                    $set[$name] = true;
                }
            }
        }
        if (count($set) >= $max * 3) break; // pre-corte para no acumular millones
    }

    $subdomains = array_keys($set);
    sort($subdomains);
    if (count($subdomains) > $max) $subdomains = array_slice($subdomains, 0, $max);

    return ['ok' => true, 'subdomains' => $subdomains, 'error' => null];
}

/**
 * AlienVault OTX — passive DNS.
 * NOTA: OTX dejó de permitir acceso anónimo. Si se pasa $key se usa; si no, se omite.
 * Registro gratuito en https://otx.alienvault.com/ (toma 1 min).
 */
function otx_passive_dns(string $domain, ?string $key = null, int $timeout = 12): array
{
    if ($key === null || trim($key) === '') {
        return ['ok' => false, 'ips' => [], 'records' => [], 'error' => 'requires free OTX key'];
    }
    $url = 'https://otx.alienvault.com/api/v1/indicators/domain/' . rawurlencode($domain) . '/passive_dns';
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'X-OTX-API-KEY: ' . trim($key)],
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 6,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => FOSINT_UA,
    ]);
    $body = curl_exec($ch);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    unset($ch);

    if ($body === false || $code !== 200) {
        $safe = safe_curl_error($errno, $err);
        return ['ok' => false, 'ips' => [], 'records' => [], 'error' => $safe ?: "HTTP $code"];
    }
    $json = json_decode($body, true);
    if (!is_array($json)) {
        return ['ok' => false, 'ips' => [], 'records' => [], 'error' => 'invalid JSON'];
    }

    $records = [];
    $ips = [];
    foreach (($json['passive_dns'] ?? []) as $r) {
        $addr = (string)($r['address'] ?? '');
        $type = strtoupper((string)($r['record_type'] ?? ''));
        if (!in_array($type, ['A', 'AAAA'], true)) continue;
        if (!filter_var($addr, FILTER_VALIDATE_IP)) continue;
        $records[] = [
            'ip' => $addr,
            'hostname' => $r['hostname'] ?? '',
            'first' => $r['first'] ?? null,
            'last' => $r['last'] ?? null,
        ];
        $ips[] = $addr;
    }
    return ['ok' => true, 'ips' => array_values(array_unique($ips)), 'records' => $records, 'error' => null];
}

/**
 * HackerTarget hostsearch — devuelve pares hostname,ip.
 * Rate limit duro (50/día por IP). Si se agota, devuelve texto que detectamos.
 */
function hackertarget_hostsearch(string $domain, int $timeout = 10): array
{
    $url = 'https://api.hackertarget.com/hostsearch/?q=' . rawurlencode($domain);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 6,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => FOSINT_UA,
    ]);
    $body = curl_exec($ch);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    unset($ch);

    if ($body === false || $code !== 200) {
        $safe = safe_curl_error($errno, $err);
        return ['ok' => false, 'pairs' => [], 'ips' => [], 'error' => $safe ?: "HTTP $code"];
    }
    $body = trim($body);

    if ($body === '' || stripos($body, 'API count exceeded') !== false || stripos($body, 'error') === 0) {
        return ['ok' => false, 'pairs' => [], 'ips' => [], 'error' => 'rate limit or error: ' . substr($body, 0, 80)];
    }

    $pairs = [];
    $ips = [];
    foreach (preg_split('/\r?\n/', $body) as $line) {
        $parts = explode(',', trim($line));
        if (count($parts) !== 2) continue;
        [$host, $ip] = $parts;
        $host = trim($host);
        $ip = trim($ip);
        if ($host !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $pairs[] = ['host' => $host, 'ip' => $ip];
            $ips[] = $ip;
        }
    }
    return ['ok' => true, 'pairs' => $pairs, 'ips' => array_values(array_unique($ips)), 'error' => null];
}

/**
 * Shodan InternetDB — gratis, sin key. Una llamada por IP.
 * Devuelve hostnames, puertos abiertos, tags y CVEs vistos.
 */
function shodan_internetdb(string $ip, int $timeout = 4): array
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return ['ok' => false, 'data' => null, 'error' => 'invalid IP'];

    $url = 'https://internetdb.shodan.io/' . $ip;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => FOSINT_UA,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    unset($ch);

    if ($body === false) return ['ok' => false, 'data' => null, 'error' => safe_curl_error($errno, $err) ?: 'request failed'];
    if ($code === 404) return ['ok' => true, 'data' => null, 'error' => null]; // sin info
    if ($code !== 200) return ['ok' => false, 'data' => null, 'error' => "HTTP $code"];

    $json = json_decode($body, true);
    if (!is_array($json)) return ['ok' => false, 'data' => null, 'error' => 'invalid JSON'];

    return ['ok' => true, 'data' => [
        'hostnames' => $json['hostnames'] ?? [],
        'ports' => $json['ports'] ?? [],
        'tags' => $json['tags'] ?? [],
        'vulns' => $json['vulns'] ?? [],
        'cpes' => $json['cpes'] ?? [],
    ], 'error' => null];
}

/**
 * Lookup paralelo de Shodan InternetDB para una lista de IPs.
 * Devuelve [ip => data|null], data como en shodan_internetdb().
 */
function shodan_internetdb_multi(array $ips, int $concurrency = 20, int $timeout = 4): array
{
    $ips = array_values(array_filter(array_unique($ips), fn($ip) => filter_var($ip, FILTER_VALIDATE_IP) !== false));
    $results = [];
    if (empty($ips)) return $results;

    $multi = curl_multi_init();
    $active = [];
    $idx = 0;

    $start = function (string $ip) use (&$multi, &$active, $timeout) {
        $ch = curl_init('https://internetdb.shodan.io/' . $ip);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => FOSINT_UA,
        ]);
        curl_multi_add_handle($multi, $ch);
        $active[spl_object_id($ch)] = ['handle' => $ch, 'ip' => $ip];
    };

    while ($idx < count($ips) && count($active) < $concurrency) {
        $start($ips[$idx++]);
    }

    do {
        do { $status = curl_multi_exec($multi, $running); } while ($status === CURLM_CALL_MULTI_PERFORM);
        if ($running) curl_multi_select($multi, 0.3);

        while ($info = curl_multi_info_read($multi)) {
            $ch = $info['handle'];
            $oid = spl_object_id($ch);
            $ip = $active[$oid]['ip'] ?? '';
            $body = curl_multi_getcontent($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_multi_remove_handle($multi, $ch);
            unset($active[$oid]);

            if ($code === 200 && is_string($body)) {
                $json = json_decode($body, true);
                if (is_array($json)) {
                    $results[$ip] = [
                        'hostnames' => $json['hostnames'] ?? [],
                        'ports' => $json['ports'] ?? [],
                        'tags' => $json['tags'] ?? [],
                        'vulns' => $json['vulns'] ?? [],
                        'cpes' => $json['cpes'] ?? [],
                    ];
                } else {
                    $results[$ip] = null;
                }
            } else {
                $results[$ip] = null; // 404 = sin datos, otros errores también null
            }

            if ($idx < count($ips)) $start($ips[$idx++]);
        }
    } while ($running > 0 || !empty($active));

    curl_multi_close($multi);
    return $results;
}
