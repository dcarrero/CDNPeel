<?php
declare(strict_types=1);

require_once __DIR__ . '/curl-safe.php';

/**
 * Resolución DNS vía DNS-over-HTTPS (Cloudflare 1.1.1.1).
 * No depende del resolver del sistema y evita interferencias locales.
 */

function dns_doh_query(string $name, string $type = 'A', int $timeout = 5): array
{
    $url = 'https://cloudflare-dns.com/dns-query?' . http_build_query([
        'name' => $name,
        'type' => $type,
    ]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'backcf/0.1',
    ]);

    $body = curl_exec($ch);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    unset($ch);

    if ($body === false) {
        return ['ok' => false, 'error' => safe_curl_error($errno, $err) ?: 'DoH request failed', 'records' => []];
    }

    $json = json_decode($body, true);
    if (!is_array($json)) {
        return ['ok' => false, 'error' => 'Invalid DoH response', 'records' => []];
    }

    $answers = $json['Answer'] ?? [];
    $records = [];
    foreach ($answers as $ans) {
        $records[] = [
            'name' => $ans['name'] ?? '',
            'type' => $ans['type'] ?? 0,
            'data' => isset($ans['data']) ? trim((string)$ans['data'], '"') : '',
        ];
    }

    return ['ok' => true, 'error' => null, 'records' => $records];
}

function dns_get_a(string $name): array
{
    $res = dns_doh_query($name, 'A');
    if (!$res['ok']) return [];
    $ips = [];
    foreach ($res['records'] as $r) {
        if ((int)$r['type'] === 1 && filter_var($r['data'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ips[] = $r['data'];
        }
    }
    return array_values(array_unique($ips));
}

function dns_get_aaaa(string $name): array
{
    $res = dns_doh_query($name, 'AAAA');
    if (!$res['ok']) return [];
    $ips = [];
    foreach ($res['records'] as $r) {
        if ((int)$r['type'] === 28 && filter_var($r['data'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ips[] = $r['data'];
        }
    }
    return array_values(array_unique($ips));
}

function dns_get_txt(string $name): array
{
    $res = dns_doh_query($name, 'TXT');
    if (!$res['ok']) return [];
    $txts = [];
    foreach ($res['records'] as $r) {
        if ((int)$r['type'] === 16) {
            $txts[] = preg_replace('/"\s*"/', '', $r['data']);
        }
    }
    return $txts;
}
