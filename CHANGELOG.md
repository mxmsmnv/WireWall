# WireWall Changelog

All notable changes to WireWall are documented here.

---

## 1.6.1 — July 1, 2026

### Bug Fixes

- Prevent common browser family names such as Firefox, Brave, Chrome, Safari, and Edge from becoming full-firewall bypass rules when entered in Allowed User-Agents.
- Keep browser compatibility workarounds scoped to fake-browser detection instead of allowing spoofable browser User-Agent substrings to skip rate limits, trigger rules, VPN/proxy checks, and other protections.

---

## 1.6.0 — July 1, 2026

### New Features

- Added AI-friendly traffic history as daily JSONL files in `/site/assets/WireWall/traffic/`.
- Added `Save Traffic History` configuration, enabled by default for public allowed and blocked requests.
- Added traffic history status to the WireWall dashboard.
- Added `AGENTS.md` with Olivia/AI guidance, safe operations, risky operations, configuration keys, Blueprint guidance, and versioning rules.

### Improvements

- Redesigned the WireWall dashboard UI with a clearer status header, KPI metrics, responsive panels, improved lists, and a more readable recent-events table.
- Documented traffic history usage in `README.md`.

---

## 1.5.0 — June 7, 2026

### New Features

- Added URL/query trigger rules that can add strikes or immediately ban an IP when suspicious request strings match.
- Added User-Agent trigger rules with the same strike or immediate-ban behavior.
- Added configurable trigger action, strike threshold, strike window, and ban duration settings.
- Added pipe-separated trigger alternatives, so patterns like `wp-json|wp-admin|wp-login|wp-content|wp-includes` can be managed compactly.

### Bug Fixes

- Fixed a PHP 8.5 deprecation when a block page was rendered with an unknown country value.
- Rate-limit blocks now pass resolved country and ASN data to block rendering and logs.
- Temporary bans are now enforced independently from the rate-limiting toggle, so trigger bans remain active even when rate limiting is disabled.
- Wildcard path matching now escapes regex metacharacters correctly before expanding `*`.

---

## 1.4.0 — April 25, 2026

### New Module

**WireWall Dashboard (`ProcessWireWall`)**

New companion Process module that adds a real-time firewall dashboard at `Admin → Setup → WireWall`. Installs alongside the main module — no configuration required.

Features:
- **Stat cards** — Blocked, Allowed, Unique IPs blocked, Active Bans, Cache files
- **Hourly chart** — blocked requests over the last 24 hours (Chart.js, reads PW CSS vars for dark mode)
- **Top Block Reasons** — bar chart with counts
- **Top Countries** — bar chart with counts
- **Top Blocked IPs** — bar chart with counts
- **Active Bans** — live list with TTL countdown (`43m 26s` format)
- **Cache Breakdown** — Rate Limit / Bans / Proxy / GeoIP file counts
- **Recent Events** — last 50 log entries, sticky header, newest first, shows Time / Status / IP / Country / ASN / Reason / UA
- Dashboard uses UIkit + ProcessWire CSS design tokens throughout; adapts to light and dark admin themes automatically

Parser correctly handles ProcessWire's 4-column tab-separated log format (`timestamp \t user \t url \t message`).

### Refactored Settings Page

The module configuration page has been fully restructured into 10 logical sections, all collapsed to a single level:

1. **General** — Enable, Logging, Block Action, Block Page Message
2. **Rate Limiting** — Enable, Requests Per Minute, Ban Duration
3. **Bot Protection** — Bad Bots, AI Bots, Search Bots, JS Challenge, Custom Patterns
4. **VPN / Proxy / Datacenter** — Block VPN/Proxy/Tor, Block Datacenters, Blocked ASNs
5. **Geo Blocking** — MaxMind status inline, Country/City/Subdivision (City and Subdivision sections only shown when GeoLite2-City.mmdb is installed)
6. **IP Control** — Whitelist, Blacklist
7. **Exceptions** — Allowed UAs, Allowed IPs, Allowed ASNs (collapsed by default)
8. **Custom Block Rules** — Paths, User-Agents, Referers (collapsed by default)
9. **AJAX & API Settings** — Trusted modules, Custom paths, Disable AJAX protection (collapsed by default)
10. **Cache Management** — Statistics, Clear buttons (collapsed by default)

---

## 1.3.6 — April 24, 2026

### Security Fixes

**IP spoofing via proxy headers**

`getRealClientIP()` previously trusted `CF-Connecting-IP`, `Incap-Client-IP`, and `X-Sucuri-ClientIP` unconditionally. Any client reaching the server directly could set these headers and impersonate an arbitrary IP address — bypassing country blocks, rate limiting, and the IP blacklist.

Fixed by validating `REMOTE_ADDR` against published CDN IP ranges before trusting each header. Added helper `sanitizeIP()` for stripping ports, IPv6-mapped prefixes, and XFF list entries.

`X-Forwarded-For` and `X-Real-IP` are no longer trusted unless `$config->wireWallTrustProxy = true` is set in `config.php`.

**Unsafe `unserialize()` in cache layer**

`cacheGet()` called `unserialize()` without `allowed_classes`, which permits PHP object injection if an attacker can write to the cache directory. Fixed by passing `['allowed_classes' => false]` and asserting the result is an array.

### Bug Fixes

**AJAX bypass via broad POST key patterns**

`isAllowedModuleRequest()` matched POST keys starting with `'field'`, `'page'`, `'Inputfield'`, and `'process'`. Any attacker could craft a POST AJAX request with a key like `field_x` to bypass all WireWall checks. Narrowed to only specific unambiguous prefixes: `ProcessWire`, `InputfieldPage`, `bookmarks`.

**Datacenter detection false positives**

`isDatacenter()` matched standalone words `'cloud'`, `'server'`, `'hosting'`, `'cdn'`, `'google'`, and `'microsoft'` in ASN org names, causing false positives for legitimate ISPs. Removed the broad single-word keywords; retained only specific compound phrases and named providers.

---

## 1.3.5 — February 23, 2026

### Bug Fix

**False positive blocks on localhost / private networks**

Browsers on `http://localhost` or local networks do not send `Sec-CH-UA` or `Sec-Fetch-*` headers. The fake browser detection was flagging real Chrome browsers on localhost as headless automation.

Fixed by detecting loopback and RFC-1918 addresses and skipping Client Hints and Sec-Fetch checks for those requests. All other fake browser checks remain active.

---

## 1.3.4 — February 23, 2026

### Bug Fixes

**Logged-in users blocked by rate limiting**
Authenticated ProcessWire users are now bypassed unconditionally at priority 3, before rate limiting. Previously the code did not enforce this despite the documentation stating it.

**Eternal ban after rate limit expiry**
When a ban expired, the first subsequent request would immediately re-trigger a new ban because the rate limit counter file outlived the ban file. The counter is now deleted when the ban is created.

**Silent 404 was not stealthy**
The stealth mode returned a full styled HTML page with WireWall branding. It now returns plain-text `Not Found` with no HTML.

### New Feature

**Disable AJAX Protection Completely**
New checkbox option that bypasses WireWall entirely for all AJAX requests (POST with `X-Requested-With: XMLHttpRequest`). Last-resort option when AJAX issues cannot be resolved via Custom Trusted AJAX Paths.

### Priority System Update

Added priority 3 (Logged-in ProcessWire users). Full order: Admin → Trusted AJAX → Logged-in users → IP whitelist → Allowed bots/IPs/ASNs → Rate limiting → IP blacklist → JS challenge → VPN/Proxy/Tor → Datacenter → ASN → Global rules → Country → City → Subdivision → Country-specific rules.

---

## 1.3.3 — January 11, 2026

### New Features

- City-level blocking (requires GeoLite2-City)
- Subdivision / region blocking (requires GeoLite2-City)
- IPv6 support with CIDR notation
- ASN whitelist (Allowed ASNs field)
- Allowed User-Agents and Allowed IPs exception fields
- Cache management UI with per-type statistics and clear buttons

### Improvements

- GeoIP data moved to `/site/assets/WireWall/` — survives module updates
- Composer dependencies moved to `/site/assets/WireWall/vendor/`
- Automatic migration from old module-directory paths on upgrade
- Improved fake browser detection with expanded headless patterns

---

## 1.3.2 — December 2025

### New Features

- AI bot blocking (GPTBot, ClaudeBot, GrokBot, Perplexity, Google-Extended…)
- Datacenter blocking via ASN keyword matching
- Custom API paths bypass (all HTTP methods)
- Custom trusted AJAX paths

### Bug Fixes

- AJAX responses no longer corrupted by ProcessWire output buffering hook interference
- Rate limit counter uses file locking (LOCK_EX) to prevent race conditions

---

## 1.3.0 — November 2025

### New Features

- MaxMind GeoLite2 integration (Country + ASN + City databases)
- HTTP API fallback (ip-api.com) when MaxMind not installed
- JS Challenge page for suspicious requests
- VPN / Proxy / Tor detection via multi-API chain
- ASN blocking
- Country-specific rules (block path / UA / referer per country)
- File-based cache — scales to 1M+ IPs
- 15-level priority system

### Breaking Changes

- Minimum PHP raised to 8.1
- Minimum ProcessWire raised to 3.0.200

---

## 1.2.0 — October 2025

### New Features

- Country blocking (blacklist and whitelist modes)
- Rate limiting with configurable ban duration
- IP whitelist and blacklist with CIDR support
- Bad bot blocking
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
