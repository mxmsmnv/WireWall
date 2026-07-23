# WireWall — Advanced Security & Firewall Module for ProcessWire

**Author:** Maxim Semenov  
**Website:** [smnv.org](https://smnv.org)  
**Email:** [maxim@smnv.org](mailto:maxim@smnv.org)

![WireWall](assets/WireWall.png)

If this project helps your work, consider supporting future development: [GitHub Sponsors](https://github.com/sponsors/mxmsmnv) or [smnv.org/sponsor](https://smnv.org/sponsor/).

**Version:** 1.8.1 | **Requires:** ProcessWire 3.0.200+, PHP 8.1+

Enterprise-grade firewall for ProcessWire CMS with geo-blocking, bot protection, rate limiting, VPN/Proxy/Tor detection, JS challenge, and a real-time admin dashboard.

---

## Features

### Geographic Control
- **Country blocking** — blacklist or whitelist entire countries (200+)
- **City blocking** — block specific cities (requires GeoLite2-City)
- **Subdivision / region blocking** — block states, provinces, oblasts (requires GeoLite2-City)
- **MaxMind GeoLite2** — fast local geolocation (Country, ASN, City databases)
- **HTTP API fallback** — automatic fallback to ip-api.com when MaxMind unavailable
- **IPv4 / IPv6** — full support with CIDR notation

### Bot Protection
- **Bad bot blocking** — scrapers, scanners, vulnerability tools (wget, curl, sqlmap, nikto…)
- **AI bot blocking** — GPTBot, ClaudeBot, GrokBot, Perplexity, Google-Extended…
- **Search engine control** — block or allow Googlebot, Bingbot, Yandex, Baidu
- **Custom bot patterns** — define your own User-Agent block list
- **Fake browser detection** — advanced UA analysis, missing header checks, Chrome version heuristics
- **Headless browser detection** — Puppeteer, Playwright, Selenium, PhantomJS

### Security
- **Rate limiting** — requests per minute per IP, configurable ban duration
- **VPN / Proxy / Tor detection** — multi-API chain (ip-api.com → ipinfo.io → ipapi.co)
- **Datacenter blocking** — AWS, Google Cloud, DigitalOcean, Azure, OVH, Hetzner, Akamai…
- **ASN blocking** — block entire networks by autonomous system number
- **JavaScript challenge** — transparent challenge for suspicious requests
- **URL / User-Agent trigger rules** — add strikes or immediately ban IPs when request URLs, query strings, or User-Agents match suspicious patterns
- **Scanner trigger preset** — optional immediate bans for obvious `.env`, `.git`, `wp-config`, backup, and phpinfo probes
- **Bare block responses** — minimal 404/410 responses that cannot execute site analytics
- **Scoped exceptions** — known bots and browser compatibility rules no longer bypass unrelated protections
- **Verified search crawlers** — configured Googlebot/Bingbot identities use cached forward-confirmed reverse DNS before network heuristics are relaxed
- **IP whitelist / blacklist** — exact, wildcard, and CIDR support
- **IP spoofing protection** — proxy headers (CF-Connecting-IP, Incap, Sucuri) only trusted when REMOTE_ADDR belongs to the CDN's published IP ranges

### Dashboard
- **Real-time statistics** — blocked/allowed counts, block rate, unique IPs, active bans, cache size
- **Traffic history for AI analysis** — daily JSONL files with allowed/blocked requests, URL, referer, UA, country, ASN, and decision reason
- **Protected report downloads** — individual JSONL files, date-range ZIPs, last-24-hours export, and AI incident bundles from the dashboard
- **Redacted settings export** — download active settings for AI-assisted review without exposing secret-like values
- **Hourly chart** — blocked requests over last 24 hours (Chart.js)
- **Top reasons, countries, IPs** — bar charts with counts
- **Active bans** — live list with TTL countdown
- **Recent events** — last 50 log entries, sticky header, newest first
- **Light / dark theme** — reads PW CSS variables, adapts automatically
- **Installed as separate Process module** — `Admin → Setup → WireWall`

### Management
- **16-level priority system** — precise rule ordering
- **File-based cache** — scales to 1M+ IPs, no database overhead
- **Cache management UI** — per-type stats, clear buttons
- **Dedicated settings storage** — canonical `wirewall_settings` table with automatic migration and ProcessWire config fallback
- **Detailed logging** — country, city, region, ASN, UA in every log entry

---

## Requirements

| | |
|---|---|
| ProcessWire | 3.0.200 or higher |
| PHP | 8.1 or higher |
| MaxMind GeoLite2 | Optional but strongly recommended |
| Composer | Optional (required for MaxMind) |

---

## Installation

```bash
# 1. Clone into site/modules/
git clone https://github.com/mxmsmnv/WireWall.git /path/to/site/modules/WireWall

# 2. Install in admin
Admin → Modules → Refresh → WireWall → Install

# 3. Install dashboard module
Admin → Modules → Refresh → WireWall Dashboard → Install

# 4. Configure
Admin → Modules → WireWall → Configure
```

See [INSTALL.md](INSTALL.md) for full installation instructions including MaxMind setup.

---

## Quick Configuration

```
✅ Enable WireWall
✅ Enable Logging
Block Action: Bare 404 (recommended for bot/scanner protection)

Rate Limiting: 10 req/min, 60 min ban
✅ Block Bad Bots
✅ Block AI Bots
✅ Block VPN/Proxy/Tor

Exceptions → Known Bot User-Agents: Googlebot, Bingbot (default)
Exceptions → Known Bot ASNs: 15169 (Google), 8075 (Microsoft)
Custom Block Rules → Scanner Trigger Preset: Standard
IP Control → Whitelist: only explicitly trusted office/home/service IPs
```

---

## Priority System

| Level | Check |
|---|---|
| 0 | Admin area — always allowed |
| 0.5 | Trusted ProcessWire AJAX |
| 0.7 | Logged-in users — always allowed |
| 1 | IP whitelist |
| 2 | Active temporary ban |
| 2.5 | URL / User-Agent trigger rules |
| 3 | Rate limiting (fixed 60-second window) |
| 4 | IP blacklist |
| 4.5 | Verify and classify scoped known-bot / compatibility exceptions |
| 5 | JS challenge (except scoped compatibility clients) |
| 6 | VPN / Proxy / Tor |
| 7 | Datacenter |
| 8 | ASN blocking |
| 9 | Global rules (known bots skip bot heuristics, not explicit rules) |
| 10 | Country blocking |
| 10.5 | City blocking |
| 10.6 | Subdivision blocking |
| 11 | Country-specific rules |

---

## MaxMind GeoLite2

WireWall works without MaxMind via HTTP API fallback, but MaxMind is strongly recommended for production.

| | With MaxMind | Without MaxMind |
|---|---|---|
| Speed | 0.5–2ms | 100–500ms |
| Rate limits | None | Applies |
| City/region blocking | ✅ | ❌ |
| Offline operation | ✅ | ❌ |

```bash
# Download from maxmind.com (free account)
mkdir -p /path/to/site/assets/WireWall/geoip/
cp GeoLite2-Country.mmdb GeoLite2-ASN.mmdb /path/to/site/assets/WireWall/geoip/

cd /path/to/site/assets/WireWall/
composer require geoip2/geoip2
```

---

## File Structure

```
/site/modules/WireWall/
├── WireWall.module.php          Main firewall module
├── ProcessWireWall.module.php   Dashboard module
├── README.md
├── INSTALL.md
├── CONFIGURATIONS.md
└── CHANGELOG.md

/site/assets/WireWall/           Public-root data — GeoIP/vendor only
├── geoip/
│   ├── GeoLite2-Country.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb       optional
├── vendor/                      Composer dependencies
├── composer.json
└── composer.lock

../SITE-DIRECTORY-wirewall-private/  Private data outside document root
└── traffic/
    └── traffic-YYYY-MM-DD.jsonl    AI-friendly request history
```

## Traffic History

Enable **Save Traffic History** in `Admin → Modules → WireWall → Configure`.

WireWall writes one JSON object per request to daily files:

```text
../SITE-DIRECTORY-wirewall-private/traffic/traffic-YYYY-MM-DD.jsonl
```

This is separate from the ProcessWire log and is designed for later traffic analysis. Each row includes time, allow/block status, reason, IP, country, city/region when available, ASN, method, URL path/query, referer, User-Agent, and selected browser headers. Admin pages, logged-in users, CLI requests, and trusted module/API bypasses are not recorded.

Authorized users can open `Admin → Setup → WireWall` to:

- download today, yesterday, the last 24 hours, or any individual daily JSONL file;
- create a ZIP for a selected date range;
- create an AI incident bundle containing redacted settings, traffic, a summary, and handling notes.

The traffic directory is outside the document root and its files use private
filesystem permissions. Report routes require the `wirewall-dashboard`
permission. Set `$config->wireWallPrivateDataPath` to an absolute path when the
default sibling directory is not suitable for the host.

## Settings Storage and Export

WireWall stores its canonical configuration in the `wirewall_settings` database
table. Existing ProcessWire module configuration is imported automatically and
kept synchronized as a fallback. The firewall runtime and dashboard both read
through `WireWall::getWireWallSettings()`.

Use **Download settings for AI** from the settings screen or dashboard for a
redacted JSON snapshot. Keys that look like tokens, passwords, credentials,
private keys, secrets, or API keys are replaced automatically.

---

## Troubleshooting

**Admin area blocked** — WireWall never blocks the admin by design. If you cannot access admin, check server-level firewall rules, not WireWall.

**Legitimate traffic blocked** — use IP Whitelist only for a tightly controlled full bypass. For bots, add the UA/IP/ASN to the scoped Known Bot fields. For browser-header quirks, use Browser / Client Compatibility Exceptions. Review `Admin → Setup → Logs → wirewall`.

**Search engines blocked** — add `Googlebot` / `Bingbot` to Known Bot User-Agents and AS15169 / AS8075 to Known Bot ASNs. These rules do not bypass rate limits, triggers, network checks, geo policy, or explicit blocks.

**MaxMind not detected** — verify `.mmdb` files are in `/site/assets/WireWall/geoip/` and composer autoload exists at `/site/assets/WireWall/vendor/autoload.php`.

**AJAX broken** — add the path to Custom Trusted AJAX Paths, or use Custom API Paths for REST endpoints. Last resort: enable "Disable AJAX Protection Completely".

**Behind Cloudflare / CDN** — set `$config->wireWallTrustProxy = true` and `$config->wireWallProxyHeader = 'HTTP_CF_CONNECTING_IP'` in `config.php`.

---

## Security Notes

WireWall is one layer of a defence-in-depth strategy. It does not replace:
- ProcessWire / PHP updates
- HTTPS / SSL
- Server hardening (SSH, OS firewall)
- Application-level protections (SQL injection, XSS)
- DDoS mitigation at network level

---

## License

MIT License. See [LICENSE](LICENSE) for details.

See [CHANGELOG.md](CHANGELOG.md) for version history.
