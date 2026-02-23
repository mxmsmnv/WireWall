# WireWall Changelog

All notable changes to WireWall are documented here.

---

## 1.3.5 — February 23, 2026

### Bug Fix

**False positive blocks on localhost / private networks**

Browsers accessing a site over `http://localhost` or a local network do not send `Sec-CH-UA` (Client Hints) or `Sec-Fetch-*` headers — these are only transmitted over HTTPS or to public origins. The fake browser detection logic was checking for the presence of these headers unconditionally, causing any real Chrome browser on localhost to be flagged as headless automation and blocked immediately on the first visit.

Fixed by detecting whether `REMOTE_ADDR` is a loopback or RFC-1918 private address (`127.0.0.1`, `::1`, `192.168.*`, `10.*`, `172.16-31.*`) and skipping the Client Hints and Sec-Fetch presence checks for those requests. All other fake browser checks (headless UA patterns, missing Accept headers, outdated Chrome version heuristics) remain active.

---

## 1.3.4 — February 23, 2026

### Bug Fixes

**Logged-in users blocked by rate limiting**
Authenticated ProcessWire users are now unconditionally bypassed at priority level 3, before any rate limiting or blocking checks. Previously the documentation stated that logged-in users were whitelisted, but the code did not enforce this — a logged-in user who triggered the rate limit would be blocked and could not clear the ban even from the admin. Fixed.

**Eternal ban after rate limit expiry**
When a ban expired, the first subsequent request would immediately re-trigger a new ban because the rate limit counter file outlived the ban file. The counter is now deleted at the moment the ban is created, so after the ban duration elapses the IP starts fresh from zero.

**Silent 404 was not stealthy**
The "Return 404 silently (stealth mode)" option returned a full styled HTML page with WireWall branding, Google Fonts, and wave pattern animations — identical to the block page in everything except the HTTP status code. It now returns a plain-text `Not Found` body with no HTML, indistinguishable from a standard web server 404.

### New Features

**Disable AJAX Protection Completely**
New checkbox option: "Disable AJAX Protection Completely". When enabled, all AJAX requests (POST with `X-Requested-With: XMLHttpRequest` header) bypass WireWall entirely, regardless of path or module origin. This is a last-resort option for sites where AJAX issues cannot be resolved via Custom Trusted AJAX Paths. Located in module settings next to "Allow AJAX from trusted modules".

### Priority System Update

Added priority level 3: Logged-in ProcessWire users. The full priority order is now:

1. Admin area protection (URL-based)
2. Trusted ProcessWire module AJAX
3. Logged-in users (session-based)
4. IP whitelist
5. Allowed bots / IPs / ASNs
6. Rate limiting
7. IP blacklist
8. JS challenge
9. VPN / Proxy / Tor detection
10. Datacenter detection
11. ASN blocking
12. Global rules (bot patterns, paths, UA, referer)
13. Country blocking
14. City blocking
15. Subdivision blocking
16. Country-specific rules

---

## 1.3.3 — January 11, 2026

### New Features

- Added city-level blocking (requires GeoLite2-City database)
- Added subdivision / region blocking (requires GeoLite2-City database)
- Added IPv6 support with full CIDR notation (e.g. 2601:41:c780:6740::/64)
- Added ASN whitelist (Allowed ASNs field) — whitelist entire networks by autonomous system number
- Added Allowed User-Agents and Allowed IPs exception fields
- Cache management UI with per-type statistics and clear buttons

### Improvements

- GeoIP data now stored in `/site/assets/WireWall/` — survives module updates
- Composer dependencies moved to `/site/assets/WireWall/vendor/`
- Automatic migration from old module-directory paths on upgrade
- Improved fake browser detection with expanded headless browser patterns

---

## 1.3.2 — December 2025

### New Features

- AI bot blocking category (GPTBot, ClaudeBot, GrokBot, Perplexity, Google-Extended, etc.)
- Datacenter blocking via ASN keyword matching
- Custom API paths bypass (all HTTP methods)
- Custom trusted AJAX paths configuration

### Bug Fixes

- AJAX responses no longer corrupted by ProcessWire output buffering hook interference
- Rate limit counter now uses file locking (LOCK_EX) to prevent race conditions on high-traffic sites

---

## 1.3.0 — November 2025

### New Features

- MaxMind GeoLite2 integration (Country + ASN + City databases)
- HTTP API fallback (ip-api.com) when MaxMind not installed
- JS Challenge page for suspicious requests (headless browsers, missing UA, etc.)
- VPN / Proxy / Tor detection via multi-API chain (ip-api.com, ipinfo.io, ipapi.co)
- ASN blocking (block by autonomous system number or organisation name)
- Country-specific rules (block path / UA / referer per country)
- File-based cache replacing database cache — scales to 1M+ IPs
- 15-level priority system

### Breaking Changes

- Minimum PHP version raised to 8.1
- Minimum ProcessWire version raised to 3.0.200

---

## 1.2.0 — October 2025

### New Features

- Country blocking (blacklist and whitelist modes)
- Rate limiting with configurable ban duration
- IP whitelist and blacklist with CIDR support
- Bad bot blocking (scrapers, scanners, vulnerability tools)
- Search engine bot blocking / allowlist
- Block page with custom message
- Silent 404 mode
- Custom redirect on block
- Statistics logging

---

## 1.0.0 — September 2025

Initial release.

- Basic IP blocking
- Simple rate limiting
- ProcessWire admin area protection