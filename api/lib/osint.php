<?php
declare(strict_types=1);

require_once __DIR__ . '/curl-safe.php';

/**
 * Integraciones opcionales con buscadores de internet.
 * Las API keys vienen por request; nunca se persisten en servidor.
 */

function http_json_get(string $url, array $headers = [], int $timeout = 10, ?string $basicAuth = null): array
{
    $ch = curl_init($url);
    $allHeaders = array_merge(['Accept: application/json'], $headers);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $allHeaders,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'backcf/0.1',
    ]);
    if ($basicAuth !== null) {
        curl_setopt($ch, CURLOPT_USERPWD, $basicAuth);
    }
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    unset($ch);

    if ($body === false) return ['ok' => false, 'status' => 0, 'error' => safe_curl_error($errno, $err), 'json' => null];
    $json = json_decode($body, true);
    return ['ok' => $code >= 200 && $code < 300, 'status' => $code, 'error' => $code >= 400 ? "HTTP $code" : null, 'json' => $json];
}

/**
 * Shodan: /dns/domain/{domain}. Devuelve subdominios con sus IPs (A).
 */
function shodan_lookup(string $domain, string $key): array
{
    $key = trim($key);
    if ($key === '') return ['ok' => false, 'ips' => [], 'error' => 'missing key'];

    $url = 'https://api.shodan.io/dns/domain/' . rawurlencode($domain) . '?key=' . rawurlencode($key);
    $res = http_json_get($url);
    if (!$res['ok']) {
        return ['ok' => false, 'ips' => [], 'error' => $res['error'] ?: 'shodan failed'];
    }
    $ips = [];
    foreach (($res['json']['data'] ?? []) as $entry) {
        if (!empty($entry['type']) && in_array($entry['type'], ['A', 'AAAA'], true)) {
            $val = $entry['value'] ?? '';
            if (filter_var($val, FILTER_VALIDATE_IP)) $ips[] = $val;
        }
    }
    return ['ok' => true, 'ips' => array_values(array_unique($ips)), 'error' => null];
}

/**
 * Censys Search v2 (hosts) buscando por hostname.
 */
function censys_lookup(string $domain, string $id, string $secret): array
{
    $id = trim($id);
    $secret = trim($secret);
    if ($id === '' || $secret === '') {
        return ['ok' => false, 'ips' => [], 'error' => 'missing credentials'];
    }

    $url = 'https://search.censys.io/api/v2/hosts/search?'
        . http_build_query(['q' => 'names: ' . $domain, 'per_page' => 50]);

    $res = http_json_get($url, [], 12, $id . ':' . $secret);
    if (!$res['ok']) {
        return ['ok' => false, 'ips' => [], 'error' => $res['error'] ?: 'censys failed'];
    }
    $hits = $res['json']['result']['hits'] ?? [];
    $ips = [];
    foreach ($hits as $hit) {
        if (!empty($hit['ip']) && filter_var($hit['ip'], FILTER_VALIDATE_IP)) {
            $ips[] = $hit['ip'];
        }
    }
    return ['ok' => true, 'ips' => array_values(array_unique($ips)), 'error' => null];
}

/**
 * Shodan: buscar hosts que expongan el mismo favicon hash (MurmurHash3).
 */
function shodan_favicon_search(int $mmh3Hash, string $key): array
{
    $key = trim($key);
    if ($key === '') return ['ok' => false, 'ips' => [], 'error' => 'missing key'];

    $url = 'https://api.shodan.io/shodan/host/search?' . http_build_query([
        'key' => $key,
        'query' => 'http.favicon.hash:' . $mmh3Hash,
        'fields' => 'ip_str',
    ]);
    $res = http_json_get($url);
    if (!$res['ok']) {
        return ['ok' => false, 'ips' => [], 'error' => $res['error'] ?: 'shodan favicon search failed'];
    }
    $ips = [];
    foreach (($res['json']['matches'] ?? []) as $match) {
        $ip = $match['ip_str'] ?? '';
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $ips[] = $ip;
        }
    }
    return ['ok' => true, 'ips' => array_values(array_unique($ips)), 'error' => null];
}

/**
 * Censys: buscar hosts que expongan el mismo favicon MD5 hash.
 */
function censys_favicon_search(string $md5Hash, string $id, string $secret): array
{
    $id = trim($id);
    $secret = trim($secret);
    if ($id === '' || $secret === '') {
        return ['ok' => false, 'ips' => [], 'error' => 'missing credentials'];
    }

    $url = 'https://search.censys.io/api/v2/hosts/search?'
        . http_build_query([
            'q' => 'services.http.response.favicons.md5_hash: ' . $md5Hash,
            'per_page' => 50,
        ]);

    $res = http_json_get($url, [], 12, $id . ':' . $secret);
    if (!$res['ok']) {
        return ['ok' => false, 'ips' => [], 'error' => $res['error'] ?: 'censys favicon search failed'];
    }
    $hits = $res['json']['result']['hits'] ?? [];
    $ips = [];
    foreach ($hits as $hit) {
        if (!empty($hit['ip']) && filter_var($hit['ip'], FILTER_VALIDATE_IP)) {
            $ips[] = $hit['ip'];
        }
    }
    return ['ok' => true, 'ips' => array_values(array_unique($ips)), 'error' => null];
}
