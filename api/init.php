<?php
declare(strict_types=1);

/**
 * Endpoint POST que recibe las API keys del cliente y devuelve un scan_id
 * de un solo uso. scan.php lee y borra el archivo asociado al consumir el id.
 *
 * Motivo: EventSource sólo soporta GET, así que si las keys viajaran en la URL
 * del scan, quedarían registradas en access logs de Apache/nginx y en cualquier
 * proxy intermedio. Este flujo de dos pasos mantiene las credenciales fuera
 * de la URL y, por tanto, fuera de los logs por defecto.
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    echo json_encode(['error' => 'method not allowed']);
    exit;
}

$rawLen = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($rawLen > 16384) { // 16 KiB cap — las keys más largas conocidas no llegan a 200 chars
    http_response_code(413);
    echo json_encode(['error' => 'payload too large']);
    exit;
}

$raw = file_get_contents('php://input', false, null, 0, 16384) ?: '';
$body = json_decode($raw, true);
if (!is_array($body)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid JSON body']);
    exit;
}

// Sólo aceptamos las claves esperadas. Cualquier otra se descarta en silencio.
$payload = [
    'shodan_key'    => isset($body['shodan_key'])    ? trim((string)$body['shodan_key'])    : '',
    'censys_id'     => isset($body['censys_id'])     ? trim((string)$body['censys_id'])     : '',
    'censys_secret' => isset($body['censys_secret']) ? trim((string)$body['censys_secret']) : '',
    'otx_key'       => isset($body['otx_key'])       ? trim((string)$body['otx_key'])       : '',
];

// Cap defensivo en longitud por campo.
foreach ($payload as $k => $v) {
    if (strlen($v) > 512) {
        http_response_code(400);
        echo json_encode(['error' => "field $k too long"]);
        exit;
    }
}

// Si no llega ninguna key con valor, no creamos archivo. El cliente puede
// simplemente abrir EventSource sin scan_id en ese caso.
if ($payload['shodan_key'] === '' && $payload['censys_id'] === '' && $payload['censys_secret'] === '' && $payload['otx_key'] === '') {
    echo json_encode(['scan_id' => null]);
    exit;
}

$dir = sys_get_temp_dir() . '/cdnpeel-scans';
if (!is_dir($dir)) {
    @mkdir($dir, 0700, true);
}
@chmod($dir, 0700);

// Limpieza oportunista de archivos abandonados (>120 s) en cada init.
$cutoff = time() - 120;
foreach (glob($dir . '/*.json') ?: [] as $stale) {
    if (@filemtime($stale) < $cutoff) @unlink($stale);
}

// Token: 32 hex chars de random_bytes. Cryptographically secure.
$token = bin2hex(random_bytes(16));
$file = $dir . '/' . $token . '.json';

$json = json_encode($payload, JSON_UNESCAPED_SLASHES);
$written = @file_put_contents($file, $json, LOCK_EX);
if ($written === false) {
    http_response_code(500);
    echo json_encode(['error' => 'failed to persist scan context']);
    exit;
}
@chmod($file, 0600);

echo json_encode(['scan_id' => $token]);
