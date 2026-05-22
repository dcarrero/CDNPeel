<?php
declare(strict_types=1);

/**
 * Extrae IPs (v4 y v6) de registros TXT, especialmente SPF.
 * Las IPs en SPF aparecen como `ip4:1.2.3.4` o `ip4:1.2.3.0/24` y análogo para `ip6:`.
 * También recoge IPs sueltas en otros TXT por si acaso.
 */

function extract_ips_from_txt(array $txtRecords): array
{
    $ips = [];

    foreach ($txtRecords as $txt) {
        $txt = (string)$txt;

        // SPF style: ip4:X.X.X.X(/N)?  e ip6:....
        if (preg_match_all('/ip4:([0-9.]+)(?:\/\d+)?/i', $txt, $m4)) {
            foreach ($m4[1] as $cand) {
                if (filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $ips[] = $cand;
                }
            }
        }
        if (preg_match_all('/ip6:([0-9a-f:]+)(?:\/\d+)?/i', $txt, $m6)) {
            foreach ($m6[1] as $cand) {
                if (filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    $ips[] = $cand;
                }
            }
        }

        // IPv4 sueltas en cualquier TXT.
        if (preg_match_all('/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/', $txt, $mloose)) {
            foreach ($mloose[1] as $cand) {
                if (filter_var($cand, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $ips[] = $cand;
                }
            }
        }
    }

    return array_values(array_unique($ips));
}
