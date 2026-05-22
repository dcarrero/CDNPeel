<?php
declare(strict_types=1);

/**
 * Rate-limit por IP basado en archivos. Sin dependencias (sin APCu).
 *
 * Motivo: scan.php es un endpoint abierto que lanza decenas de peticiones
 * salientes por invocación. Sin tope un atacante lo usa como proxy de
 * reconocimiento contra terceros (con tu IP como atribución) o lo satura.
 *
 * Por defecto: 30 scans por hora por IP. Configurable via constantes.
 *
 * Se almacena un archivo por IP con la lista de timestamps recientes.
 * En cada comprobación se descartan timestamps fuera de la ventana.
 */

const RL_DEFAULT_LIMIT  = 30;
const RL_WINDOW_SECONDS = 3600;
const RL_GC_PROBABILITY = 20; // 1/N de probabilidad de hacer GC al llamar

function rl_client_ip(): string
{
    // Solo confiamos en REMOTE_ADDR. Si el operador despliega detrás de un proxy
    // de confianza, debe documentarse en el README y mapear con set_real_ip_from
    // (nginx) o mod_remoteip (Apache) antes de llegar a PHP.
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function rl_dir(): string
{
    return sys_get_temp_dir() . '/cdnpeel-rl';
}

function rl_path(string $ip): string
{
    // Hash → no escribimos la IP en disco (privacidad + filename safety).
    return rl_dir() . '/' . hash('sha256', $ip) . '.json';
}

/**
 * Devuelve ['ok' => bool, 'retry_after' => int, 'count' => int, 'limit' => int].
 * Si ok=true, ya cuenta esta solicitud en el bucket. Si ok=false, retry_after
 * indica los segundos hasta que el hit más viejo de la ventana expire.
 */
function rl_check(string $ip, int $limit = RL_DEFAULT_LIMIT, int $window = RL_WINDOW_SECONDS): array
{
    $dir = rl_dir();
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    @chmod($dir, 0700);

    // GC oportunista (1/N).
    if (random_int(1, RL_GC_PROBABILITY) === 1) rl_gc($window);

    $path = rl_path($ip);
    $now  = time();
    $hits = [];

    if (is_file($path)) {
        $data = json_decode((string)@file_get_contents($path), true);
        if (is_array($data) && isset($data['hits']) && is_array($data['hits'])) {
            $hits = array_values(array_filter(
                $data['hits'],
                static fn($t) => is_int($t) && $t > $now - $window
            ));
        }
    }

    if (count($hits) >= $limit) {
        sort($hits);
        $retryAfter = max(1, $hits[0] + $window - $now);
        return ['ok' => false, 'retry_after' => $retryAfter, 'count' => count($hits), 'limit' => $limit];
    }

    $hits[] = $now;
    @file_put_contents($path, json_encode(['hits' => $hits]), LOCK_EX);
    @chmod($path, 0600);

    return ['ok' => true, 'retry_after' => 0, 'count' => count($hits), 'limit' => $limit];
}

/**
 * Borra archivos de buckets cuyo último timestamp salió de la ventana.
 */
function rl_gc(int $window = RL_WINDOW_SECONDS): void
{
    $cutoff = time() - $window;
    foreach (glob(rl_dir() . '/*.json') ?: [] as $f) {
        if (@filemtime($f) < $cutoff) @unlink($f);
    }
}

/**
 * Audit log mínimo en error_log() — útil para A09 (Security Logging).
 * No registra API keys (nunca llegan aquí) ni cuerpos. Solo IP + acción + target.
 */
function rl_audit(string $action, array $context = []): void
{
    $ip = rl_client_ip();
    $line = sprintf(
        '[cdnpeel] %s ip=%s %s',
        $action,
        $ip,
        http_build_query($context, '', ' ')
    );
    error_log($line);
}
