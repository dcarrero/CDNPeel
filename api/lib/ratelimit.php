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

    // Read-modify-write atómico bajo flock exclusivo. Sin esto, varias
    // requests concurrentes leen el mismo estado pre-límite y todas se
    // auto-admiten, dejando el bucket inservible bajo bursts.
    $fp = @fopen($path, 'c+');
    if ($fp === false) {
        // Si no podemos abrir el archivo (permisos, etc.), fallamos cerrado:
        // mejor rechazar una request legítima que servir un bypass de RL.
        return ['ok' => false, 'retry_after' => 60, 'count' => 0, 'limit' => $limit];
    }
    if (!@flock($fp, LOCK_EX)) {
        fclose($fp);
        return ['ok' => false, 'retry_after' => 60, 'count' => 0, 'limit' => $limit];
    }
    @chmod($path, 0600);

    rewind($fp);
    $raw = stream_get_contents($fp);
    if (is_string($raw) && $raw !== '') {
        $data = json_decode($raw, true);
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
        // Persistimos el bucket podado para que el GC no recicle el archivo
        // antes de que expire la ventana.
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode(['hits' => $hits]));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        return ['ok' => false, 'retry_after' => $retryAfter, 'count' => count($hits), 'limit' => $limit];
    }

    $hits[] = $now;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode(['hits' => $hits]));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

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
