<?php
declare(strict_types=1);

/**
 * Multi-CDN classifier.
 *
 * Embedded IP ranges for major CDN providers. Ranges go stale over time; refresh
 * with tools/update-cdn-ranges.php when needed.
 *
 * Sources:
 *  - Cloudflare:  https://www.cloudflare.com/ips-v4 / ips-v6
 *  - Fastly:      https://api.fastly.com/public-ip-list
 *  - AWS CloudFront: https://ip-ranges.amazonaws.com/ip-ranges.json (service=CLOUDFRONT)
 *  - Akamai:      no public list (limited prefixes + rDNS + Server header detection)
 *  - Imperva (Incapsula): https://my.imperva.com/api/integration/v1/ips
 *  - Sucuri:      docs.sucuri.net + public posts
 *  - BunnyCDN:    https://api.bunny.net/system/edgeserverlist
 *  - KeyCDN:      public docs
 *  - CDN77:       public docs
 *  - StackPath / Highwinds: public docs
 *  - TransparentEdge (Spain): public reverse DNS + ASN AS264643
 *  - Google Cloud Front: https://www.gstatic.com/ipranges/cloud.json
 *  - Azure Front Door:  partial sample
 */

const CDN_PROVIDERS = [
    'cloudflare' => [
        'name' => 'Cloudflare',
        'v4' => [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        ],
        'v6' => [
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
            '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
        ],
        'headers' => ['server:cloudflare', 'cf-ray', 'cf-cache-status', 'cf-connecting-ip'],
        'rdns' => [],
    ],

    'fastly' => [
        'name' => 'Fastly',
        'v4' => [
            '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23',
            '103.245.224.0/24', '104.156.80.0/20', '140.248.64.0/18', '140.248.128.0/17',
            '146.75.0.0/17', '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
            '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20', '172.111.64.0/18',
            '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16',
        ],
        'v6' => [
            '2a04:4e40::/32', '2a04:4e42::/32',
        ],
        'headers' => ['x-served-by:cache-', 'fastly-debug-digest', 'x-cache:hit, hit', 'x-timer'],
        'rdns' => ['fastly.net'],
    ],

    'cloudfront' => [
        'name' => 'AWS CloudFront',
        'v4' => [
            '13.32.0.0/15', '13.35.0.0/16', '13.224.0.0/14', '13.249.0.0/16',
            '18.64.0.0/14', '18.154.0.0/15', '18.160.0.0/15', '18.164.0.0/15',
            '18.172.0.0/15', '18.238.0.0/15', '18.244.0.0/15', '52.46.0.0/18',
            '52.84.0.0/15', '52.124.128.0/17', '52.222.128.0/17', '54.182.0.0/16',
            '54.192.0.0/16', '54.230.0.0/16', '54.239.128.0/18', '54.239.192.0/19',
            '54.240.128.0/18', '64.252.64.0/18', '64.252.128.0/18', '99.84.0.0/16',
            '99.86.0.0/16', '108.156.0.0/14', '108.138.0.0/15', '108.158.0.0/15',
            '108.162.236.0/22', '120.52.22.96/27', '130.176.0.0/17', '143.204.0.0/16',
            '204.246.164.0/22', '204.246.168.0/22', '204.246.172.0/24', '204.246.174.0/23',
            '204.246.176.0/20', '205.251.192.0/19', '205.251.249.0/24', '205.251.250.0/23',
            '205.251.252.0/23', '205.251.254.0/24', '216.137.32.0/19',
        ],
        'v6' => [
            '2600:9000::/28',
        ],
        'headers' => ['x-amz-cf-id', 'x-amz-cf-pop', 'via:cloudfront'],
        'rdns' => ['cloudfront.net'],
    ],

    'akamai' => [
        'name' => 'Akamai',
        // Akamai does not publish CIDRs. Below are commonly observed prefixes; rDNS
        // and Server header are the reliable signals.
        'v4' => [
            '2.16.0.0/13', '23.0.0.0/12', '23.32.0.0/11', '23.192.0.0/11',
            '60.254.128.0/17', '69.31.0.0/16', '72.246.0.0/15', '88.221.0.0/16',
            '92.122.0.0/15', '95.100.0.0/15', '96.6.0.0/15', '96.16.0.0/15',
            '104.64.0.0/10', '118.214.0.0/16', '173.222.0.0/15', '184.24.0.0/13',
            '184.50.0.0/15', '184.84.0.0/14',
        ],
        'v6' => [],
        'headers' => ['server:akamaighost', 'server:akamainetstorage', 'x-akamai-transformed', 'akamai-x-cache-on'],
        'rdns' => ['akamaitechnologies.com', 'akamaiedge.net', 'akamaized.net', 'akamai.net'],
    ],

    'imperva' => [
        'name' => 'Imperva (Incapsula)',
        'v4' => [
            '199.83.128.0/21', '198.143.32.0/19', '149.126.72.0/21', '103.28.248.0/22',
            '185.11.124.0/22', '192.230.64.0/18', '45.64.64.0/22', '107.154.0.0/16',
            '45.60.0.0/16', '45.223.0.0/16', '131.125.128.0/17',
        ],
        'v6' => [
            '2a02:e980::/29',
        ],
        'headers' => ['x-iinfo', 'x-cdn:incapsula', 'set-cookie:visid_incap', 'set-cookie:incap_ses'],
        'rdns' => ['incapdns.net'],
    ],

    'sucuri' => [
        'name' => 'Sucuri',
        'v4' => [
            '192.124.249.0/24', '185.93.228.0/22', '66.248.200.0/22', '208.109.0.0/22',
            '193.16.236.0/24',
        ],
        'v6' => [
            '2a02:fe80::/29',
        ],
        'headers' => ['server:sucuri/cloudproxy', 'x-sucuri-cache', 'x-sucuri-id'],
        'rdns' => ['cloudproxy.net', 'sucuri.net'],
    ],

    'bunnycdn' => [
        'name' => 'BunnyCDN',
        'v4' => [
            '5.181.190.0/24', '23.227.39.0/24', '64.190.65.0/24', '68.235.32.0/20',
            '94.249.176.0/20', '108.181.0.0/16', '143.244.0.0/16', '169.150.232.0/22',
            '185.93.0.0/16', '188.114.96.0/20',
        ],
        'v6' => [
            '2a02:6b8::/32',
        ],
        'headers' => ['server:bunnycdn', 'cdn-pullzone', 'cdn-uid', 'cdn-cachedat'],
        'rdns' => ['bunnyinfra.net', 'b-cdn.net'],
    ],

    'keycdn' => [
        'name' => 'KeyCDN',
        'v4' => [
            '94.247.172.0/23', '37.235.96.0/20', '185.92.220.0/22', '212.32.224.0/19',
        ],
        'v6' => [],
        'headers' => ['server:keycdn-engine'],
        'rdns' => ['kxcdn.com', 'keycdn.com'],
    ],

    'cdn77' => [
        'name' => 'CDN77',
        'v4' => [
            '185.59.220.0/22', '185.93.0.0/22', '193.169.84.0/22',
        ],
        'v6' => [],
        'headers' => ['server:cdn77', 'x-77-cache', 'x-cdn:cdn77'],
        'rdns' => ['cdn77.org', 'cdn77.com'],
    ],

    'stackpath' => [
        'name' => 'StackPath / MaxCDN',
        'v4' => [
            '69.16.175.0/24', '69.16.190.0/24', '94.31.27.0/24', '94.31.29.0/24',
            '108.161.176.0/20', '146.88.16.0/22', '151.139.0.0/16', '152.195.0.0/16',
            '199.114.221.0/24', '205.185.208.0/20',
        ],
        'v6' => [
            '2606:2800:4000::/40',
        ],
        'headers' => ['server:netdna-cache', 'x-cache:hit from netdna', 'x-cdn:stackpath'],
        'rdns' => ['stackpathdns.com', 'netdna-cdn.com', 'stackpathcdn.com'],
    ],

    'transparentedge' => [
        'name' => 'TransparentEdge',
        // Spanish CDN. Limited public CIDR data; AS264643 + rDNS more reliable.
        'v4' => [
            '5.45.103.0/24', '145.239.235.0/24', '147.78.142.0/24',
        ],
        'v6' => [],
        'headers' => ['server:transparentedge', 'x-transparent-cache', 'x-trtc-cache'],
        'rdns' => ['transparentedge.eu', 'transparentcdn.com'],
    ],

    'googlefe' => [
        'name' => 'Google Cloud Front-End',
        // Subset; full list at https://www.gstatic.com/ipranges/cloud.json (filter for "Global Frontends")
        'v4' => [
            '34.96.0.0/14', '34.102.0.0/15', '34.104.0.0/15', '35.190.0.0/17',
            '35.191.0.0/16', '130.211.0.0/22', '142.250.0.0/15', '172.217.0.0/16',
        ],
        'v6' => [
            '2600:1900::/28',
        ],
        'headers' => ['via:google', 'server:gws'],
        'rdns' => ['1e100.net', 'googleusercontent.com'],
    ],

    'azurefd' => [
        'name' => 'Azure Front Door',
        // Subset; full ServiceTag AzureFrontDoor.Frontend updates weekly.
        'v4' => [
            '13.107.42.0/24', '13.107.213.0/24', '20.45.0.0/16', '40.126.0.0/18',
            '52.146.130.0/24', '147.243.0.0/16',
        ],
        'v6' => [
            '2603:1030::/24',
        ],
        'headers' => ['x-azure-ref', 'x-cache:tcp_hit from azure'],
        'rdns' => ['azureedge.net', 'azurefd.net', 'msedge.net'],
    ],
];

// === CIDR matching ===

function cidr_match_v4(string $ip, string $cidr): bool
{
    if (!str_contains($cidr, '/')) return false;
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ipLong = ip2long($ip);
    $subnetLong = ip2long($subnet);
    if ($ipLong === false || $subnetLong === false) return false;
    if ($bits === 0) return true;
    $mask = -1 << (32 - $bits);
    return (($ipLong & $mask) === ($subnetLong & $mask));
}

function cidr_match_v6(string $ip, string $cidr): bool
{
    if (!str_contains($cidr, '/')) return false;
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ipBin = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false) return false;
    if (strlen($ipBin) !== 16 || strlen($subnetBin) !== 16) return false;

    $bytes = intdiv($bits, 8);
    $remaining = $bits % 8;

    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
        return false;
    }
    if ($remaining === 0) return true;

    $maskByte = chr(0xFF << (8 - $remaining) & 0xFF);
    return ((ord($ipBin[$bytes]) & ord($maskByte)) === (ord($subnetBin[$bytes]) & ord($maskByte)));
}

// === Provider lookup ===

function which_cdn(string $ip): ?string
{
    $isV4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    $isV6 = !$isV4 && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    if (!$isV4 && !$isV6) return null;

    foreach (CDN_PROVIDERS as $id => $p) {
        $ranges = $isV4 ? ($p['v4'] ?? []) : ($p['v6'] ?? []);
        foreach ($ranges as $cidr) {
            if ($isV4 ? cidr_match_v4($ip, $cidr) : cidr_match_v6($ip, $cidr)) {
                return $id;
            }
        }
    }
    return null;
}

function is_cdn_ip(string $ip): bool
{
    return which_cdn($ip) !== null;
}

function cdn_provider_name(string $id): string
{
    return CDN_PROVIDERS[$id]['name'] ?? $id;
}

/**
 * Classify a list of IPs by CDN provider.
 * Returns ['by_provider' => ['cloudflare' => [...], ...], 'non_cdn' => [...]]
 */
function classify_cdn_ips(array $ips): array
{
    $by = [];
    $nonCdn = [];
    foreach ($ips as $ip) {
        $id = which_cdn($ip);
        if ($id === null) {
            $nonCdn[] = $ip;
        } else {
            $by[$id][] = $ip;
        }
    }
    return ['by_provider' => $by, 'non_cdn' => array_values(array_unique($nonCdn))];
}

/**
 * Detect CDN provider(s) from HTTP response headers.
 * Accepts ['header-name' => 'value', ...] (lowercased keys) or raw header string.
 * Returns array of provider IDs detected.
 */
function detect_cdn_from_headers(array|string $headers): array
{
    // Normalise to "name: value" lowercase string for substring matching.
    if (is_array($headers)) {
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = strtolower((string)$k) . ': ' . strtolower((string)$v);
        }
        $blob = "\n" . implode("\n", $lines) . "\n";
    } else {
        $blob = "\n" . strtolower($headers) . "\n";
    }

    $detected = [];
    foreach (CDN_PROVIDERS as $id => $p) {
        foreach (($p['headers'] ?? []) as $sig) {
            $sig = strtolower($sig);
            // Header signatures of two shapes:
            //   "name:value"  → require "name:" present AND value substring on same line
            //   "name"        → just require presence of header name
            if (str_contains($sig, ':')) {
                [$h, $vsub] = explode(':', $sig, 2);
                $h = trim($h); $vsub = trim($vsub);
                if ($vsub === '') {
                    if (preg_match('/\n' . preg_quote($h, '/') . ':/', $blob)) {
                        $detected[$id] = true; break;
                    }
                } else {
                    if (preg_match('/\n' . preg_quote($h, '/') . ':[^\n]*' . preg_quote($vsub, '/') . '/', $blob)) {
                        $detected[$id] = true; break;
                    }
                }
            } else {
                if (preg_match('/\n' . preg_quote($sig, '/') . ':/', $blob)) {
                    $detected[$id] = true; break;
                }
            }
        }
    }
    return array_keys($detected);
}

/**
 * Reverse-DNS based detection. Best-effort; used for Akamai/Fastly when IPs
 * don't appear in our embedded ranges.
 */
function detect_cdn_from_rdns(string $ip): ?string
{
    $host = @gethostbyaddr($ip);
    if (!$host || $host === $ip) return null;
    $host = strtolower($host);
    foreach (CDN_PROVIDERS as $id => $p) {
        foreach (($p['rdns'] ?? []) as $domain) {
            if (str_ends_with($host, strtolower($domain))) return $id;
        }
    }
    return null;
}

// === Backward compatibility ===

function is_cloudflare_ip(string $ip): bool
{
    return which_cdn($ip) === 'cloudflare';
}

function classify_ips(array $ips): array
{
    // Legacy shape: {cf, non_cf}. Treats all CDN IPs as "cf" group to keep old
    // callers working without spurious "non-CF candidate" entries.
    $cf = [];
    $nonCf = [];
    foreach ($ips as $ip) {
        if (is_cdn_ip($ip)) $cf[] = $ip;
        else $nonCf[] = $ip;
    }
    return ['cf' => $cf, 'non_cf' => $nonCf];
}
