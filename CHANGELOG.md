# Changelog

All notable changes to CDNPeel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-05-23

### Added
- **Batch Mode**: Analyze multiple domains sequentially within a single browser session. Resolves each target domain sequentially to protect API rate limits and conserve client-side memory.
- **CSV & JSON Export**: Added buttons to instantly export discovered origin IPs and candidates (with open ports, web titles, and domain sources) into clean, standard CSV or JSON formats.
- **Localized UI Elements**: Full translations of batch mode and export strings across all 8 supported languages.

## [1.7.0] - 2026-05-23

### Added
- **Manual Baseline Title (Optional)**: Allows the user to specify a baseline title to bypass strict CDN protection/challenges (like captchas or interstitial pages) that block direct baseline fetches.
- **Favicon Hash Search (Shodan / Censys)**: Downloads the target favicon and calculates both MurmurHash3 (used by Shodan) and MD5 (used by Censys) in pure PHP. It queries Shodan and Censys APIs using these hashes to find hidden origin servers.
- **Favicon tagging in results**: Candidates discovered via favicon hash are labeled with the `favicon` note in the results table.
- **Persistent Scan History**: Stores up to 10 recent scans locally (completely client-side & private using `localStorage`). Clicking on any past scan instantly loads the cached results without consuming Shodan/Censys API limits. Added a button to clear history.
- **Localisation for history**: Translated history strings across all 8 supported languages.

## [1.6.0] - 2026-05-22

### Added
- **Per-IP rate limit** on `api/scan.php` (default: 30 scans / hour). When
  exceeded, the server emits an SSE `fatal` event with `retry_after` instead
  of an opaque HTTP 429, so the UI can show an actionable message.
- **Audit log via `error_log`**: every `scan_start` and `rate_limited` event
  is logged with IP and target domain (no API keys, no bodies) — covers
  OWASP A09.
- **HTTP security headers** on the PHP endpoints: `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **Content-Security-Policy** (`default-src 'self'`, no inline scripts/styles)
  and `<meta name="referrer">` in the HTML.
- **`api/lib/curl-safe.php`**: maps cURL `errno` to four generic categories
  (`timeout`, `dns error`, `tls error`, `network error`). Full detail kept
  only in `error_log` for audit.
- README section documenting recommended security headers and rate-limit
  configuration for nginx and Apache.

### Changed
- All client-facing cURL error strings in `dns.php`, `osint.php`,
  `free-osint.php` and `http.php` now go through `safe_curl_error()` — no
  more leaking of `"Connection refused"`, `"No route to host"` or specific
  TLS messages that an attacker could use as a covert channel for
  port-scanning internal services.
- Empty-results message in the table moved from inline `style.*` (which
  required `'unsafe-inline'` in CSP) to a dedicated `.results-empty` class.

### Security
- Closes finding **#2** of the security audit (open endpoint usable as a
  reconnaissance proxy / abuse vector).
- Closes finding **#5** (missing security headers / no CSP).
- Closes finding **#6** (cURL error reflection usable for internal-network
  enumeration).

## [1.5.0] - 2026-05-22

### Added
- **Sticky section nav** with anchors Form / Progress / Results. Active
  section is highlighted live via `IntersectionObserver`. The Results link
  is disabled until the scan emits its summary.
- **Live progress counter** (`12/15 · 1 err`) shown both in the nav chip
  and in the pipeline header.
- **Pipeline header** with "Expand all" / "Collapse all" controls.
- **Floating "↑ Top" button** after 400 px of scroll (label hidden on
  mobile).
- 6 new i18n strings (`nav.*`) translated across all 8 locales.

### Changed
- Each pipeline step is now a native `<details>` element:
  - Opens automatically while `running`.
  - Auto-collapses 450 ms after settling (`done`, `match`, `no-match`,
    `skipped`, `info`).
  - `error` steps stay open.
  - Once the user manually toggles a step, it never auto-closes again.
- `scrollIntoView` only fires when the pipeline section is actually the
  active one — no more stealing the scroll while the user is reading
  results.

## [1.0.x] - 2026-05-22 (security hardening between 1.0.0 and 1.5.0)

### Security
- **Finding #1 — SSRF hardening.** New `api/lib/ip-safety.php` with
  `ip_is_safe_target()` / `ip_filter_safe()`. Rejects RFC1918, loopback,
  CGNAT (`100.64/10`), link-local including cloud metadata
  (`169.254.169.254`), benchmark (`198.18/15`), TEST-NETs, multicast
  IPv4/IPv6, IPv6 ULA, documentation prefixes, and IPv4-mapped IPv6
  (`::ffff:...`) bypass attempts. Applied centrally in `$mark()` to every
  candidate source (A records, TXT/SPF, subdomain resolution, OTX,
  HackerTarget, Shodan, Censys) and defensively in `fetch_title_via_ip` /
  `fetch_titles_via_ips_multi`. Baseline request now uses
  `CURLOPT_RESOLVE` against the validated DoH IPs to prevent DNS rebinding.
- **Finding #3 — API keys moved out of the query string.** New
  `api/init.php` accepts the keys via POST, persists them at
  `sys_get_temp_dir()/cdnpeel-scans/{token}.json` with mode 0600 and 120 s
  TTL, returns a 32-hex-char one-shot `scan_id`. `api/scan.php` reads the
  file and deletes it before running the scan. Tokens are validated by
  `/^[a-f0-9]{32}$/` (no path traversal). Without keys, no init call is
  made — the URL only carries `domain` and `use_hackertarget`.

### Fixed
- Author surname corrected to "Fernández-Baillo" in LICENSE and README.

## [1.0.0] - 2026-05-22

Initial public release.

### Highlights
- Multi-CDN origin-IP discovery: Cloudflare, Fastly, Akamai, AWS
  CloudFront, Imperva, Sucuri, BunnyCDN, KeyCDN, CDN77, StackPath, Google
  Cloud Front-end, Azure Front Door, TransparentEdge.
- Pure PHP 8 + cURL. No Composer, no framework, no build step.
- Server-Sent Events live pipeline.
- Host-header bypass validation via `CURLOPT_RESOLVE`.
- 8-language UI: English, Spanish, French, German, Italian, Portuguese,
  Japanese, Korean.

[1.8.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.8.0
[1.7.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.7.0
[1.6.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.6.0
[1.5.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.5.0
[1.0.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.0.0
