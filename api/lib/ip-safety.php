<?php
declare(strict_types=1);

/**
 * Filtro de IPs no aptas como destino HTTP/HTTPS desde el servidor.
 *
 * CDNPeel hace cURL a IPs derivadas (in)directamente de la entrada del usuario:
 * registros A, IPs sueltas en TXT/SPF, OSINT de terceros (OTX, HackerTarget,
 * Shodan, Censys). Sin este filtro, un atacante puede dirigir el servidor contra
 * loopback, RFC1918, link-local y, en particular, 169.254.169.254 (metadata
 * de EC2/GCP/Azure). Esto bloquea esa clase de SSRF de raíz.
 *
 * Rechazamos:
 *   IPv4: 0/8, 10/8, 100.64/10 (CGNAT), 127/8, 169.254/16, 172.16/12,
 *         192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24,
 *         203.0.113/24, 224/4 (multicast), 240/4 (reserved), 255.255.255.255
 *   IPv6: ::, ::1, fc00::/7 (ULA), fe80::/10 (link-local), ff00::/8 (multicast),
 *         2001:db8::/32 (doc), y cualquier IPv4-mapped (::ffff:...) que apunte
 *         a un rango bloqueado tras la conversión a IPv4.
 */

function ip_is_safe_target(string $ip): bool
{
    $ip = trim($ip);
    if ($ip === '') return false;

    // IPv4-mapped IPv6 (::ffff:1.2.3.4) — convertir a IPv4 y volver a evaluar
    // para que un atacante no esquive el filtro v4 escribiendo la IP en forma v6.
    if (stripos($ip, '::ffff:') === 0) {
        $v4 = substr($ip, 7);
        if (filter_var($v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ip_is_safe_target($v4);
        }
        return false;
    }

    // PHP cubre con NO_PRIV_RANGE + NO_RES_RANGE: RFC1918, loopback, link-local
    // (169.254/16, fe80::/10), multicast (224/4, ff00::/8), reservado (240/4),
    // documentation (192.0.2/24, 2001:db8::/32), ULA (fc00::/7), ::, ::1.
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return false;
    }

    // Rangos IPv4 adicionales no contemplados de forma fiable por NO_RES_RANGE
    // en todas las versiones de PHP (multicast, CGNAT, benchmark, TEST-NETs).
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        $a = (int)$parts[0];
        $b = (int)$parts[1];
        $c = (int)$parts[2];
        // Multicast 224.0.0.0/4 (224.0.0.0 – 239.255.255.255)
        if ($a >= 224 && $a <= 239) return false;
        // CGNAT 100.64.0.0/10
        if ($a === 100 && $b >= 64 && $b <= 127) return false;
        // Benchmarking 198.18.0.0/15
        if ($a === 198 && ($b === 18 || $b === 19)) return false;
        // TEST-NET-2  198.51.100.0/24
        if ($a === 198 && $b === 51 && $c === 100) return false;
        // TEST-NET-3  203.0.113.0/24
        if ($a === 203 && $b === 0 && $c === 113) return false;
    } else {
        // IPv6 — refuerzo explícito de multicast y documentation.
        $low = strtolower($ip);
        // Multicast ff00::/8
        if (str_starts_with($low, 'ff')) {
            $first = substr($low, 0, 2);
            if (ctype_xdigit($first) && hexdec($first) >= 0xff00 >> 8) return false;
        }
        // Documentation 2001:db8::/32
        if (str_starts_with($low, '2001:db8:') || $low === '2001:db8::' || str_starts_with($low, '2001:0db8:')) {
            return false;
        }
    }

    return true;
}

/**
 * Filtra una lista de IPs dejando sólo las seguras como destino HTTP.
 * Conserva el orden, deduplica.
 */
function ip_filter_safe(array $ips): array
{
    $out = [];
    foreach ($ips as $ip) {
        $ip = (string)$ip;
        if (ip_is_safe_target($ip) && !in_array($ip, $out, true)) {
            $out[] = $ip;
        }
    }
    return $out;
}
