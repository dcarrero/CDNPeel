# Changelog

All notable changes to CDNPeel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.2] - 2026-05-23

Patch release fixing two regressions/latent bugs exposed by end-to-end testing
of the 1.9.1 audit fixes.

### Fixed
- **`CURLOPT_RESOLVE` with mixed IPv4/IPv6**: `fetch_title_direct()` and `fetch_favicon_bytes()` were emitting one `host:port:ip` entry per IP. libcurl only honors the *last* entry for a given `host:port`, so on the new A+AAAA path (1.9.1) the IPv6 entry would always win and the request would fail on hosts without routable IPv6. Fixed by collapsing all IPs into a single comma-separated value per port and listing IPv4 before IPv6.
- **`CURLE_PEER_FAILED_VERIFICATION` undefined constant**: `api/lib/curl-safe.php` referenced this constant directly in a `case`. PHP 8.5 with libcurl 8.19 (and any build that does not expose it as a PHP constant) raised a fatal error on every TLS-level cURL failure. Replaced the `switch` with `if`s using the numeric code (51) as fallback so the helper degrades gracefully on any libcurl build.

Verified end-to-end against `colorvivo.com` with HackerTarget enabled: origin IP discovered correctly (`185.103.39.242`).

## [1.9.1] - 2026-05-23

Hardening release after a full audit (Claude Code + OpenAI Codex GPT-5.4) of the
backend, CLI, and frontend.

### Security
- **SSRF (AAAA path)**: `api/scan.php` and `cli/scan.php` now resolve A *and* AAAA records via DoH and run the combined set through `ip_filter_safe()`. Previously a domain advertising only AAAA records pointing to `::1` / `fc00::/7` could slip past the safety gate.
- **SSRF (redirect follow)**: `fetch_title_direct()` and `fetch_favicon_bytes()` in `api/lib/http.php` no longer follow HTTP redirects. A 302 to `http://169.254.169.254/` or any internal hostname would otherwise be resolved by the system resolver, bypassing `CURLOPT_RESOLVE`.
- **Memory DoS**: Both functions now enforce hard per-request byte caps (256 KB for titles, 512 KB for favicons) via `CURLOPT_WRITEFUNCTION`, so chunked responses without `Content-Length` cannot exhaust worker memory.
- **Rate limit bypass**: `api/lib/ratelimit.php` now wraps the read-modify-write of the bucket file in `flock(LOCK_EX)`. Without this, concurrent bursts from the same IP all admitted themselves.
- **Result integrity**: The candidate filter for IPs harvested from subdomains and OSINT now uses `is_cdn_ip()` (all 13 providers) instead of `is_cloudflare_ip()`. A Fastly/CloudFront/Akamai edge node could otherwise be reported as the "origin IP".
- **CSV injection**: `exportCSV()` in `public/app.js` now prefixes cells that start with `=`, `+`, `-`, `@`, tab, or CR with a single quote to neutralise spreadsheet formula execution.
- **Scan-id replay**: The one-shot token in `api/scan.php` is now claimed atomically via `rename()` instead of `is_file` + `file_get_contents` + `unlink`.
- **ANSI escape injection in CLI**: `cli/scan.php` now sanitises every untrusted string (manual title, remote `<title>`, error messages) before printing to the terminal.

### Fixed
- **Stop button race**: Stop now bumps a per-run generation counter; `runSSE()` checks it after the async `init.php` round-trip and refuses to open the `EventSource` if cancelled mid-init.
- **History rendering**: `renderHistoryUI()` builds rows with `createElement`/`textContent` rather than `innerHTML`, so a poisoned `cdnpeel:scans` value cannot inject UI markup.
- **Strict CSP follow-up**: Removed an inline `style="font-weight: 500;"` reintroduced by the Phase 4 results-row template; moved to `.domain-cell` in `public/style.css` so the meta CSP `style-src 'self'` (no `unsafe-inline`) is now satisfied throughout.

### Added
- **Client-side batch validation**: Batch mode now trims/normalises lines, strips schemes and paths, deduplicates, validates hostnames, and caps the queue at 50 domains as defense-in-depth.

### Docs
- Removed the Roadmap section from `README.md` (all listed items are either shipped or out of scope).

## [1.9.0] - 2026-05-23

### Added
- **CLI Runner**: Added `cli/scan.php` to run scans directly from the console. Supports customizable command line arguments (`-d`, `-s`, `--censys-id`, `--censys-secret`, `--otx`, `-h`, `-m`). Displays real-time progress indicators using colored ANSI codes and prints findings in an auto-aligning ASCII table.
- **Premium UI Aesthetics**: Upgraded dashboard cards with Glassmorphic backdrops, glowing active shadows, neon breathing pulses on running steps, and emerald green highlights for validated origin IPs.
- **Micro-Animations**: Introduced slide-in and fade-in animations for results table rows to make live discoveries appear organically.

### Security
- **Strict CSP Compliance**: Removed inline style attributes from the batch mode textarea in `public/index.html` and migrated styling to the stylesheet, adhering fully to the strict `style-src 'self'` directive.

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

[1.9.2]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.9.2
[1.9.1]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.9.1
[1.9.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.9.0
[1.8.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.8.0
[1.7.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.7.0
[1.6.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.6.0
[1.5.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.5.0
[1.0.0]: https://github.com/dcarrero/CDNPeel/releases/tag/v1.0.0
