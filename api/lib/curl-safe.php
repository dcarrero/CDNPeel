<?php
declare(strict_types=1);

/**
 * Mapeo de cURL errno a categorías genéricas seguras para devolver al cliente.
 *
 * Motivo: el mensaje detallado de curl_error() distingue "Connection refused",
 * "No route to host", "Operation timed out" y otros, que combinados con la
 * elección de IP por parte del usuario (TXT/SPF, OSINT) convierten cada
 * petición en un canal de exfiltración para mapear servicios internos.
 *
 * Devolvemos al cliente sólo cuatro categorías: timeout, dns error, tls error
 * o network error. El detalle se conserva en error_log para auditoría.
 */

function safe_curl_error(int $errno, string $detail = ''): string
{
    if ($errno === 0) return '';

    if ($detail !== '') {
        error_log(sprintf('[cdnpeel] curl errno=%d detail=%s', $errno, $detail));
    }

    switch ($errno) {
        case CURLE_OPERATION_TIMEDOUT:
            return 'timeout';

        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
            return 'dns error';

        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CACERT:
        case CURLE_PEER_FAILED_VERIFICATION:
            return 'tls error';

        default:
            return 'network error';
    }
}
