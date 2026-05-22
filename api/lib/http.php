<?php
declare(strict_types=1);

/**
 * Peticiones HTTP/HTTPS para descubrir si una IP responde al hostname objetivo.
 *
 * Clave: CURLOPT_RESOLVE permite forzar la pareja host:port:ip dentro de cURL.
 * Con eso cURL conecta a la IP indicada pero envía Host y SNI = hostname,
 * que es exactamente la técnica que CF-Hero implementa a mano en Go.
 */

require_once __DIR__ . '/ip-safety.php';

const BACKCF_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0';

function extract_title(string $html): ?string
{
    if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $html, $m)) {
        $t = html_entity_decode(trim($m[1]), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $t = preg_replace('/\s+/u', ' ', $t);
        return $t !== '' ? $t : null;
    }
    return null;
}

function normalize_title(?string $t): string
{
    if ($t === null) return '';
    $t = mb_strtolower($t, 'UTF-8');
    $t = preg_replace('/\s+/u', ' ', $t);
    return trim($t);
}

function titles_match(?string $a, ?string $b): bool
{
    $A = normalize_title($a);
    $B = normalize_title($b);
    if ($A === '' || $B === '') return false;
    if ($A === $B) return true;
    // Tolerancia: uno contiene al otro (sufijos tipo " - Inicio" cambian entre rutas).
    if (mb_strlen($A) >= 8 && mb_strlen($B) >= 8) {
        if (str_contains($A, $B) || str_contains($B, $A)) return true;
    }
    return false;
}

/**
 * Petición HTTPS directa al dominio. Si se pasan $resolveIps (IPs ya validadas
 * como seguras por ip_is_safe_target), se usa CURLOPT_RESOLVE para forzar la
 * conexión a esas IPs y blindar el baseline frente a DNS rebinding (el resolver
 * del sistema podría dar IPs internas distintas de las que devolvió DoH).
 */
function fetch_title_direct(string $domain, array $resolveIps = [], int $timeout = 8): array
{
    // Si recibimos lista de IPs, descartamos cualquier insegura por defensa en profundidad.
    $resolveIps = ip_filter_safe($resolveIps);

    $url = 'https://' . $domain . '/';
    $headerBlob = '';
    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => BACKCF_UA,
        CURLOPT_HEADERFUNCTION => function ($ch, $header) use (&$headerBlob) {
            $headerBlob .= $header;
            return strlen($header);
        },
    ];
    if (!empty($resolveIps)) {
        $resolve = [];
        foreach ($resolveIps as $ip) {
            $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
            $host = $isV6 ? "[$ip]" : $ip;
            $resolve[] = "$domain:443:$host";
            $resolve[] = "$domain:80:$host";
        }
        $opts[CURLOPT_RESOLVE] = $resolve;
    }
    curl_setopt_array($ch, $opts);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = curl_error($ch);
    unset($ch);

    if ($body === false) {
        return ['ok' => false, 'error' => $err ?: 'request failed', 'status' => 0, 'title' => null, 'headers' => ''];
    }
    return [
        'ok' => true,
        'error' => null,
        'status' => $code,
        'title' => extract_title($body),
        'headers' => $headerBlob,
    ];
}

/**
 * Conecta a $ip pero envía Host/SNI = $domain. Devuelve el title de la respuesta.
 * Si la IP responde con el mismo title que el dominio detrás de CF → muy probablemente
 * es la IP de origen.
 *
 * Probamos primero HTTPS y, si falla a nivel de conexión, hacemos un intento HTTP.
 */
function fetch_title_via_ip(string $domain, string $ip, int $timeout = 6): array
{
    if (!ip_is_safe_target($ip)) {
        return ['ok' => false, 'scheme' => null, 'status' => 0, 'title' => null, 'error' => 'blocked: unsafe target IP'];
    }
    $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    $resolveHost = $isV6 ? "[$ip]" : $ip;

    foreach (['https' => 443, 'http' => 80] as $scheme => $port) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => "$scheme://$domain/",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => BACKCF_UA,
            CURLOPT_RESOLVE => ["$domain:$port:$resolveHost"],
            CURLOPT_HEADER => false,
            CURLOPT_NOBODY => false,
            CURLOPT_HTTPHEADER => ['Accept: text/html,*/*'],
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        $errno = curl_errno($ch);
        unset($ch);

        if ($body !== false && $code > 0) {
            return [
                'ok' => true,
                'scheme' => $scheme,
                'status' => $code,
                'title' => extract_title($body),
                'error' => null,
            ];
        }

        // Si es timeout o connection refused, ya con HTTPS, intentamos HTTP en la siguiente iteración.
        if (!in_array($errno, [CURLE_OPERATION_TIMEDOUT, CURLE_COULDNT_CONNECT, CURLE_SSL_CONNECT_ERROR], true)) {
            return [
                'ok' => false,
                'scheme' => $scheme,
                'status' => $code,
                'title' => null,
                'error' => $err ?: 'request failed',
            ];
        }
    }

    return ['ok' => false, 'scheme' => null, 'status' => 0, 'title' => null, 'error' => 'unreachable'];
}

/**
 * Versión paralela con curl_multi.
 * Para cada IP intenta HTTPS primero; si falla a nivel de conexión, encola HTTP.
 * Llama a $onResult($ip, $result) en cuanto cada IP termina (orden no garantizado).
 */
function fetch_titles_via_ips_multi(string $domain, array $ips, callable $onResult, int $concurrency = 12, int $timeout = 5): void
{
    $ips = array_values(array_unique($ips));
    // Defensa en profundidad: aunque scan.php filtra en $mark(), nunca disparamos
    // cURL contra una IP no apta. Las inseguras se entregan como error y siguen.
    $safeIps = [];
    foreach ($ips as $ip) {
        if (ip_is_safe_target($ip)) {
            $safeIps[] = $ip;
        } else {
            $onResult($ip, ['ok' => false, 'scheme' => null, 'status' => 0, 'title' => null, 'error' => 'blocked: unsafe target IP']);
        }
    }
    $ips = $safeIps;
    if (empty($ips)) return;

    $multi = curl_multi_init();
    $active = []; // oid => ['handle','ip','scheme']
    $queue = [];
    foreach ($ips as $ip) $queue[] = ['ip' => $ip, 'scheme' => 'https'];

    $build = function (string $ip, string $scheme) use ($domain, $timeout) {
        $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        $resolveHost = $isV6 ? "[$ip]" : $ip;
        $port = $scheme === 'https' ? 443 : 80;
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => "$scheme://$domain/",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => BACKCF_UA,
            CURLOPT_RESOLVE => ["$domain:$port:$resolveHost"],
            CURLOPT_HTTPHEADER => ['Accept: text/html,*/*'],
        ]);
        return $ch;
    };

    $launch = function (string $ip, string $scheme) use (&$multi, &$active, $build) {
        $ch = $build($ip, $scheme);
        curl_multi_add_handle($multi, $ch);
        $active[spl_object_id($ch)] = ['handle' => $ch, 'ip' => $ip, 'scheme' => $scheme];
    };

    $pump = function () use (&$queue, &$active, $concurrency, $launch) {
        while (count($active) < $concurrency && !empty($queue)) {
            $t = array_shift($queue);
            $launch($t['ip'], $t['scheme']);
        }
    };
    $pump();

    do {
        do { $status = curl_multi_exec($multi, $running); } while ($status === CURLM_CALL_MULTI_PERFORM);
        if ($running > 0) curl_multi_select($multi, 0.3);

        while ($info = curl_multi_info_read($multi)) {
            $ch = $info['handle'];
            $oid = spl_object_id($ch);
            $task = $active[$oid] ?? null;
            $ip = $task['ip'] ?? '';
            $scheme = $task['scheme'] ?? 'https';
            $body = curl_multi_getcontent($ch);
            $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $errno = curl_errno($ch);
            $err = curl_error($ch);

            curl_multi_remove_handle($multi, $ch);
            unset($active[$oid]);

            if ($body !== false && $code > 0) {
                $onResult($ip, [
                    'ok' => true,
                    'scheme' => $scheme,
                    'status' => $code,
                    'title' => extract_title($body),
                    'error' => null,
                ]);
            } elseif ($scheme === 'https' && in_array($errno, [CURLE_OPERATION_TIMEDOUT, CURLE_COULDNT_CONNECT, CURLE_SSL_CONNECT_ERROR], true)) {
                // Encolamos fallback HTTP
                $queue[] = ['ip' => $ip, 'scheme' => 'http'];
            } else {
                $onResult($ip, [
                    'ok' => false,
                    'scheme' => $scheme,
                    'status' => $code,
                    'title' => null,
                    'error' => $err ?: 'unreachable',
                ]);
            }

            $pump();
        }
    } while ($running > 0 || !empty($active) || !empty($queue));

    curl_multi_close($multi);
}
