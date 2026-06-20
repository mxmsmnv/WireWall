# WireWall — Advanced Security & Firewall Module for ProcessWire

**Author:** Maxim Semenov  
**Website:** [smnv.org](https://smnv.org)  
**Email:** [maxim@smnv.org](mailto:maxim@smnv.org)

![WireWall](assets/WireWall.png)

If this project helps your work, consider supporting future development: [GitHub Sponsors](https://github.com/sponsors/mxmsmnv) or [smnv.org/sponsor](https://smnv.org/sponsor/).  
**Version:** 1.5.0 | **Requires:** ProcessWire 3.0.200+, PHP 8.1+

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
- **IP whitelist / blacklist** — exact, wildcard, and CIDR support
- **IP spoofing protection** — proxy headers (CF-Connecting-IP, Incap, Sucuri) only trusted when REMOTE_ADDR belongs to the CDN's published IP ranges

### Dashboard
- **Real-time statistics** — blocked/allowed counts, block rate, unique IPs, active bans, cache size
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
Block Action: Show block page

Rate Limiting: 10 req/min, 60 min ban
✅ Block Bad Bots
✅ Block AI Bots
✅ Block VPN/Proxy/Tor

Exceptions → Allowed User-Agents: Googlebot, Bingbot (default)
Exceptions → Allowed ASNs: 15169 (Google), 8075 (Microsoft)
IP Control → Whitelist: your office/home IP
```

---

## Priority System

| Level | Check |
|---|---|
| 0 | Admin area — always allowed |
| 0.5 | Trusted ProcessWire AJAX |
| 0.7 | Logged-in users — always allowed |
| 1 | IP whitelist |
| 1.5 | Allowed bots / IPs / ASNs |
| 2 | Rate limiting |
| 3 | IP blacklist |
| 4 | JS challenge |
| 5 | VPN / Proxy / Tor |
| 6 | Datacenter |
| 7 | ASN blocking |
| 8 | Global rules (bots, paths, UA, referer) |
| 9 | Country blocking |
| 9.5 | City blocking |
| 9.6 | Subdivision blocking |
| 10 | Country-specific rules |

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

/site/assets/WireWall/           Persistent data — survives module updates
├── geoip/
│   ├── GeoLite2-Country.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb       optional
├── vendor/                      Composer dependencies
├── composer.json
└── composer.lock
```

---

## Troubleshooting

**Admin area blocked** — WireWall never blocks the admin by design. If you cannot access admin, check server-level firewall rules, not WireWall.

**Legitimate traffic blocked** — add the IP to Whitelist, or the UA to Allowed User-Agents, or the ASN to Allowed ASNs. Review `Admin → Setup → Logs → wirewall`.

**Search engines blocked** — add `Googlebot` / `Bingbot` to Allowed User-Agents and AS15169 / AS8075 to Allowed ASNs.

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
