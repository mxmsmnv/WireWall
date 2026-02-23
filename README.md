# WireWall - Advanced Security & Firewall Module for ProcessWire

**Author:** Maxim Alex | **GitHub:** [mxmsmnv](https://github.com/mxmsmnv) | **Website:** [wirewall.org](https://wirewall.org)

Enterprise-grade security and firewall module for ProcessWire CMS with comprehensive geo-blocking, bot protection, rate limiting, VPN/Proxy detection, and city-level access control.

---

## Overview

WireWall is a powerful, production-ready security module that transforms ProcessWire into a fortress. With MaxMind GeoLite2 integration, multi-API threat detection, and file-based caching that scales to millions of IPs, WireWall provides enterprise-level protection without the enterprise complexity.

**Key Benefits:**
-  **Fast** - File-based cache, 0.5-2ms GeoIP lookups with MaxMind
-  **Precise** - 12+ priority levels, city/subdivision blocking
-  **Smart** - AI bot detection, fake browser analysis, datacenter blocking
-  **Insightful** - Comprehensive logging with city/region data
-  **Scalable** - Handles 1M+ IPs without database overhead
-  **Flexible** - Extensive whitelist/exception system for legitimate traffic

---

## Core Features

### Geographic Control
- **Country Blocking** - Block or whitelist entire countries (200+ countries)
- **City-Level Blocking** - Block specific cities (e.g., Philadelphia, Beijing, Lagos)
- **Subdivision/Region Blocking** - Block states, provinces, oblasts (e.g., Pennsylvania, California, Krasnodar)
- **MaxMind GeoLite2** - Fast, accurate local geolocation (Country, ASN, City databases)
- **HTTP API Fallback** - Automatic fallback to ip-api.com when MaxMind unavailable
- **IPv4/IPv6 Support** - Full support with CIDR notation (e.g., 192.168.0.0/16, 2601:41:c780:6740::/64)

### Bot Protection
- **Bad Bot Blocking** - Block scrapers, scanners, and malicious bots (wget, curl, scrapy, nikto, sqlmap)
- **Search Engine Control** - Block/allow search crawlers (Googlebot, Bingbot, DuckDuckBot, Baidu)
- **AI Bot Blocking** - Block AI training bots (GPTBot, ClaudeBot, GrokBot, Perplexity, Google-Extended)
- **Custom Bot Lists** - Define your own bot patterns to block
- **Fake Browser Detection** - Advanced User-Agent analysis to detect spoofed browsers
- **Headless Browser Detection** - Detect Puppeteer, Playwright, Selenium, PhantomJS

### Security Features
- **Rate Limiting** - Configurable requests per minute with automatic temporary bans
- **VPN/Proxy/Tor Detection** - Multi-API detection with fallback (ip-api.com, ipinfo.io, ipapi.co)
- **Datacenter Blocking** - Block AWS, Google Cloud, DigitalOcean, Azure, and other hosting providers
- **ASN Blocking** - Block specific networks by Autonomous System Number
- **JavaScript Challenge** - Anti-bot challenge page for suspicious requests
- **IP Whitelist/Blacklist** - Manual override for specific IPs, ranges, and CIDR blocks
- **ASN Whitelist** - Allow specific networks (Google, Microsoft, Facebook, etc.)

### Management & Monitoring
- **File-Based Cache** - Scales to millions of IPs without database overhead
- **Cache Management UI** - View statistics and clear cache by type
- **Priority System** - 12+ priority levels for precise rule control
- **Admin Protection** - Triple-layer admin area protection (never blocks admin)
- **Detailed Logging** - City/region/ASN included in all logs

### User Experience
- **Beautiful Block Page** - Modern design with location display and wave pattern
- **Silent 404 Mode** - Alternative stealth blocking mode
- **Custom Redirect** - Redirect blocked users to custom URL
- **Custom Messages** - Personalise block messages

### Exception System
- **Allowed User-Agents** - Whitelist legitimate bots (Googlebot, Bingbot, Slackbot, etc.)
- **Allowed IPs** - Whitelist specific IPs or CIDR ranges for bot verification
- **Allowed ASNs** - Whitelist entire networks by ASN (Google, Microsoft, Facebook, CDNs)
- **Trusted Modules** - Automatic AJAX bypass for ProcessWire modules (RockFrontend, AppApi)
- **Custom API Paths** - Configure custom API endpoints that bypass all checks

---

## Requirements

- **ProcessWire:** 3.0.200 or higher
- **PHP:** 8.1 or higher
- **Optional:** MaxMind GeoLite2 databases (Country, ASN, City)
- **Optional:** Composer (for MaxMind GeoIP2 library)

---

## Quick Start

### Installation

```bash
# 1. Download module
git clone https://github.com/mxmsmnv/WireWall.git

# 2. Install to ProcessWire
cp -r WireWall /path/to/processwire/site/modules/

# 3. Activate in admin
Admin → Modules → Site → WireWall → Install

# 4. Configure
Admin → Modules → WireWall → Configure
```

### Basic Configuration

```
 Enable WireWall
 Country Blocking: [select based on your threat profile]
 VPN/Proxy Detection: Enabled
 Rate Limiting: 10 requests/min, 60 min ban
 Block Bad Bots: Enabled
 Enable Stats Logging: Enabled
 Allowed User-Agents: Googlebot, Bingbot (default)
 Allowed ASNs: 15169 (Google), 8075 (Microsoft)
```

See [INSTALL.md](INSTALL.md) for detailed installation and [CONFIGURATIONS.md](CONFIGURATIONS.md) for advanced setups.

---

## Common Use Cases

### 1. Attack Protection (Recommended)
```
Country Blocking: [select based on your threat profile]
City Blocking: Philadelphia, Beijing (blacklist - adjust for your threat profile)
VPN/Proxy Detection: Enabled
Datacenter Blocking: Enabled
Rate Limiting: 10 req/min, 60 min ban
Bot Blocking: Bad bots + AI bots enabled
Fake Browser Detection: Enabled
Allowed Bots: Googlebot, Bingbot (for SEO)
Allowed ASNs: 15169 (Google), 8075 (Microsoft)
```

### 2. E-commerce Security
```
Country Blocking: Blacklist fraud-prone countries
VPN/Proxy Detection: Enabled
Datacenter Blocking: Enabled
Rate Limiting: 15 req/min, 30 min ban
Bot Blocking: Bad bots enabled (keep search bots for SEO)
IP Whitelist: Payment gateway IPs
Allowed Bots: Googlebot, Bingbot (SEO)
Allowed IPs: 66.249.64.0/19 (Google Bot verified IPs)
```

### 3. Local Business (Australia Example)
```
Country Blocking: AU (whitelist - allow only)
Subdivision Blocking: New South Wales, Victoria, Queensland (whitelist)
City Blocking: Sydney, Melbourne, Brisbane (whitelist)
IP Whitelist: Office IP, staff IPs
Rate Limiting: 20 req/min
Allowed Bots: Googlebot, Bing (for local SEO)
```

### 4. API Protection
```
IP Whitelist: Known API consumers
Rate Limiting: 100 req/min, 10 min ban
Datacenter Blocking: Disabled (if API clients use cloud)
Bot Blocking: Custom bot list for API abuse
Allowed IPs: Trusted API client IPs
Allowed ASNs: 16509 (AWS), 13335 (Cloudflare) if using cloud
```

### 5. Content Protection (Block AI Scrapers)
```
Block AI Bots: Enabled (GPTBot, ClaudeBot, Perplexity, etc.)
Block Bad Bots: Enabled
Fake Browser Detection: Enabled
Rate Limiting: 5 req/min for suspicious UAs
Datacenter Blocking: Enabled
Allowed Bots: Googlebot, Bingbot ONLY (for SEO, not AI)
```

---

## MaxMind GeoLite2 Setup

WireWall works with or without MaxMind, but MaxMind is **strongly recommended** for production use.

### Comparison

| Feature | With MaxMind | Without MaxMind |
|---------|-------------|-----------------|
| **Speed** |  0.5-2ms | ️ 100-500ms (HTTP API) |
| **Reliability** |  No rate limits | ️ Rate limited |
| **City/Region** |  Full support |  Not available |
| **Subdivision Blocking** |  Supported |  Not available |
| **Offline Operation** |  Works offline |  Requires internet |
| **Accuracy** | 5/5 | 3/5 |

### Installation (Recommended)

```bash
# 1. Register for free MaxMind account
https://www.maxmind.com/en/geolite2/signup

# 2. Download databases
- GeoLite2-Country.mmdb (required for country blocking)
- GeoLite2-ASN.mmdb (required for ASN detection)
- GeoLite2-City.mmdb (optional for city/subdivision blocking)

# 3. Create directory and copy databases
mkdir -p /path/to/site/assets/WireWall/geoip/
cp *.mmdb /path/to/site/assets/WireWall/geoip/

# 4. Install PHP library (in data directory)
cd /path/to/site/assets/WireWall
composer require geoip2/geoip2

# 5. Verify in admin
Admin → Modules → WireWall → Configure
 MaxMind GeoLite2 Status: Active
```

### Database Update Schedule

MaxMind releases updated databases every **Tuesday and Friday**. For best accuracy:

```bash
# Download latest databases weekly
# Set up cron job to auto-update (optional)
0 2 * * 2,5 cd /path/to/site/assets/WireWall/geoip/ && ./update-maxmind.sh
```

---

## Exception System

WireWall includes a comprehensive exception system for whitelisting legitimate traffic.

### Allowed User-Agents (Bot Whitelist)

Whitelist legitimate bots to bypass ALL WireWall checks:

**Default Allowed Bots:**
```
Googlebot
Bingbot
facebookexternalhit
Slackbot
LinkedInBot
Twitterbot
WhatsApp
Applebot
```

**Location:** `Admin → Modules → WireWall → Exceptions/Whitelist`

**Use Cases:**
- SEO: Keep search engines for indexing
- Social: Allow social media preview crawlers
- Monitoring: Whitelist uptime monitors
- Custom: Add your own trusted bots

### Allowed IPs (IP Whitelist)

Whitelist specific IPs or CIDR ranges:

**Examples:**
```
# Google Bot verified IPs
66.249.64.0/19

# Bing Bot IPs
157.55.39.0/24

# Single IP
192.168.1.100

# Private network
10.0.0.0/8
```

**Verification Resources:**
- Google Bot: https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
- Bing Bot: https://www.bing.com/webmasters/help/verifying-bingbot-2195b2e2

### Allowed ASNs (Network Whitelist)

Whitelist entire networks by ASN - the most powerful exception method:

**Major Services ASNs:**
```
# Search Engines
AS15169 or 15169 - Google
AS8075 or 8075 - Microsoft (Bing)
# Social Networks
AS32934 or 32934 - Facebook/Meta

# Cloud/CDN
AS16509 or 16509 - Amazon AWS
AS13335 or 13335 - Cloudflare
AS54113 or 54113 - Fastly CDN

# Services
AS46489 or 46489 - Twilio
```

**Format Options:**
- ASN number: `15169`
- AS prefix: `AS15169`
- Organization name: `Google`

**Requires:** MaxMind GeoLite2 ASN database

### Trusted ProcessWire Modules

Automatic AJAX bypass for ProcessWire modules:

```
Feature: allowTrustedModules (enabled by default)
Bypasses: ProcessWire module AJAX requests (RockFrontend, AppApi, etc.)
Benefits: No module conflicts, seamless operation
Supports: POST AJAX + all HTTP methods on /api/, /rest/ paths
```

Trusted modules automatically bypass WireWall checks, ensuring smooth ProcessWire operation.

**Disable AJAX Protection Completely:**

For cases where AJAX issues persist and cannot be resolved via trusted paths, there is a separate option "Disable AJAX Protection Completely" — it bypasses WireWall for **all** AJAX requests (POST with `X-Requested-With` header), regardless of origin. Use with caution.

### Custom API Paths

Configure custom API endpoints that bypass all WireWall checks:

```
Feature: Custom API Paths
Location: Admin → Modules → WireWall → Exceptions
Format: One path per line (e.g., /api/webhook, /graphql)
Supports: All HTTP methods (GET, POST, PUT, DELETE, etc.)
Use Cases: External webhooks, API endpoints, third-party integrations
```

**Example Configuration:**
```
/api/webhook
/api/stripe
/graphql
/rest/v1
```

**Benefits:**
- Complete bypass for API endpoints
- Supports all HTTP methods
- No rate limiting on API paths
- Ideal for webhooks and integrations

---

## Logging & Monitoring

### Log Format

WireWall creates a single log file with all security events.

**With City Database:**
```
BLOCKED | US (Chicago, Illinois) | 174.198.11.141 | AS6167 CELLCO-PART | UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64)... | subdivision-blocked
ALLOWED | US (Philadelphia, Pennsylvania) | 1.2.3.4 | AS7922 Comcast Cable | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
BLOCKED | AU (Sydney, New South Wales) | 203.0.113.5 | AS1221 Telstra | UA: curl/7.68.0 | city-blocked
ALLOWED | US | 66.249.66.1 | AS15169 Google | UA: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) | allowed-bot
BLOCKED | DE | 185.220.101.1 | AS24940 Hetzner | UA: python-requests/2.28.0 | rate-limit
```

**Without City Database:**
```
BLOCKED | DE | 185.220.101.1 | AS24940 Hetzner | UA: python-requests/2.28.0 | country-blocked
ALLOWED | AU | 1.1.1.1 | AS13335 Cloudflare | UA: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
ALLOWED | US | 66.249.66.1 | AS15169 Google | UA: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) | allowed-bot
BLOCKED | Unknown | 10.20.30.40 | UA: curl/7.68.0 | global
```

**Log field order:** `STATUS | country [+(city, region)] | ip | [asn] | UA: user-agent | [reason]`

ASN field is omitted if not available. Reason field is omitted for allowed requests (except `allowed-bot`). UA is truncated to 100 characters.

### Log File Location

```
Admin → Setup → Logs → wirewall
```

**Log includes:**
- Access status (ALLOWED/BLOCKED)
- Country code with city/region (if City database available)
- IP address
- ASN (Autonomous System Number) with organization name
- User-Agent (first 100 characters)
- Block reason (if blocked)

**Common block reasons:**
- `country-blocked` - Blocked by country rules
- `city-blocked` - Blocked by city rules
- `subdivision-blocked` - Blocked by subdivision/region rules
- `rate-limit` - Rate limit exceeded
- `proxy-vpn-tor` - VPN/Proxy/Tor detected
- `datacenter` - Datacenter IP detected
- `asn-blocked` - ASN blocked
- `ip` - IP blacklist match
- `global` - Global rule match (bot/path/UA/referer)
- `allowed-bot` - Legitimate bot allowed by exception system
- `js-challenge` - JavaScript challenge issued

---

## Cache Management

Built-in cache management UI with real-time statistics:

**Cache Statistics:**
- Total cached files
- Rate limit entries
- Active bans
- Proxy/VPN cache
- Geo data cache

**Cache Actions:**
- Clear rate limits
- Clear bans
- Clear proxy cache
- Clear geo cache
- Clear all cache

**Location:**
```
Admin → Modules → WireWall → Configure → Cache Management
```

**Performance:**
- File-based cache in `/site/assets/cache/WireWall/`
- Automatically removes expired entries
- Scales to 1M+ entries without performance degradation

---

## Priority System

WireWall evaluates requests in this order (higher priority = checked first):

1. **Admin Area Protection** → ALLOW (always, never blocked)
2. **Trusted ProcessWire Modules** → ALLOW (AJAX requests bypass all checks)
3. **Logged-in Users** → ALLOW (authenticated ProcessWire users always bypass all checks)
4. **IP Whitelist** → ALLOW (bypasses all rules)
5. **Allowed Bots/IPs/ASNs** → ALLOW (exceptions bypass all checks)
6. **Rate Limiting** → BLOCK if exceeded
7. **IP Blacklist** → BLOCK (always)
8. **JS Challenge** → CHALLENGE if suspicious
9. **VPN/Proxy/Tor Detection** → BLOCK if detected
10. **Datacenter Detection** → BLOCK if datacenter
11. **ASN Blocking** → BLOCK if ASN matched
12. **Global Rules** → BLOCK if bot/path/UA/referer matched
13. **Country Blocking** → BLOCK/ALLOW based on blacklist/whitelist
14. **City Blocking** → BLOCK/ALLOW based on blacklist/whitelist
15. **Subdivision Blocking** → BLOCK/ALLOW based on blacklist/whitelist
16. **Country Rules** → BLOCK if country-specific rule matched

**Access ALLOWED** if none of the above rules trigger.

---

## Bot Detection Categories

### Bad Bots (Malicious)
```
wget, curl, python-requests, scrapy, nmap, nikto, sqlmap
semrush, ahrefs, majestic, dotbot, mj12bot, ahrefsbot
```

### Search Engine Bots (SEO)
```
Googlebot, Bingbot, Slurp (Yahoo), DuckDuckBot
Baidu, Sogou, Exabot
```
️ **Warning:** Blocking search bots prevents indexing! Use exception system to allow them.

### AI Training Bots (Content Protection)
```
GPTBot (OpenAI), ClaudeBot (Anthropic), GrokBot (xAI)
PerplexityBot, Google-Extended, Applebot-Extended
ChatGPT-User, Claude-Web, Omgilibot, FacebookBot
```

### Headless Browsers (Automation)
```
Puppeteer, Playwright, Selenium, PhantomJS
HeadlessChrome, Chrome-Lighthouse, WebDriver
```

### Custom Bot Patterns
Define your own patterns:
```
Admin → Modules → WireWall → Bot Detection → Custom Bot Patterns

BadSpider
MyCustomBot/1.0
AnnoyingCrawler
```

---

## Block Page Customization

### Default Block Page
- Modern, professional design
- Shows visitor's location (City, Region, Country)
- Displays IP address
- Custom message
- Wave pattern background (CSS animation)
- Fully responsive

### Alternative Block Actions

**1. Silent 404 Mode (Stealth)**
```
Block Action: Return 404 silently
- Returns plain text "Not Found", no HTML
- No WireWall branding or fingerprint
- Indistinguishable from a missing page
- Frustrates and confuses attackers
```

**2. Custom Redirect**
```
Block Action: Redirect to URL
Redirect URL: https://example.com/blocked
- Redirects to your custom page
- Full control over message
- Can collect analytics
```

---

## Performance Benchmarks

### With MaxMind GeoLite2
```
GeoIP Lookup:        0.5-2ms
ASN Lookup:          0.5-2ms
Rate Limit Check:    0.1ms
Total Overhead:      1-3ms per request
Memory Usage:        ~70MB (with City DB)
                     ~12MB (without City DB)
```

### Without MaxMind (HTTP API)
```
GeoIP Lookup:        100-500ms (network dependent)
Rate Limit Check:    0.1ms
Total Overhead:      100-500ms per request
API Rate Limits:     Apply (varies by provider)
```

### Cache Performance
```
File Cache:          Scales to 1M+ IPs
Cache Hit:           0.1ms
Cache Miss:          2-5ms (with MaxMind)
Expired Entry:       Automatic cleanup
```

### Exception System Performance
```
IP Whitelist Check:  0.1ms
ASN Whitelist Check: 0.5ms (with cached ASN)
Bot Whitelist Check: 0.1ms
Total Exception:     <1ms (complete bypass)
```

---

## Troubleshooting

### Issue: Admin Area Blocked
```
WireWall NEVER blocks admin area by design.
If you can't access admin:
1. Check server configuration
2. Verify admin path in config.php
3. Check firewall rules outside WireWall
4. Check if IP is in blacklist (shouldn't affect admin)
```

### Issue: Legitimate Traffic Blocked
```
1. Add to IP Whitelist: Specific trusted IPs
2. Add to Allowed User-Agents: Legitimate bot patterns
3. Add to Allowed ASNs: Entire trusted networks
4. Adjust Rate Limiting: Increase limits
5. Review Logs: Admin → Setup → Logs → wirewall
6. Disable specific rules temporarily
7. Check subdivision/city blocking (might be too broad)
```

### Issue: Search Engines Blocked
```
1. Add to Allowed User-Agents: Googlebot, Bingbot
2. Add to Allowed ASNs: 15169 (Google), 8075 (Microsoft)
3. Add to Allowed IPs: Verified search engine IPs
4. Verify with: /admin/setup/logs → wirewall
5. Check if country blocking affects crawlers
```

### Issue: Bots Still Getting Through
```
1. Enable Fake Browser Detection
2. Enable Datacenter Blocking
3. Reduce Rate Limiting threshold
4. Check custom bot patterns
5. Enable JS Challenge for suspicious requests
6. Review logs for bot signatures
7. Add specific ASNs to blocked list
```

### Issue: MaxMind Not Working
```
1. Verify databases in /site/assets/WireWall/geoip/
2. Check composer installation: cd /site/assets/WireWall && composer require geoip2/geoip2
3. Verify file permissions (readable by PHP)
4. Check module config: MaxMind Status indicator
5. Ensure correct file names (case-sensitive)
```

### Issue: High Memory Usage
```
1. City DB is large (~70MB) - optional, can be removed
2. Consider using Country + ASN only (~12MB)
3. Clear cache regularly if millions of IPs
4. Reduce cache TTL in code if needed
5. Monitor with Admin → Modules → WireWall → Cache Management
```

### Issue: CDN/Proxy Conflicts
```
1. Whitelist CDN ASNs: 13335 (Cloudflare), 54113 (Fastly)
2. Add CDN IPs to Allowed IPs
3. Disable Datacenter Blocking if using CDN
4. Ensure X-Forwarded-For header is configured
5. Check getRealClientIP() configuration
```

---

## Security Best Practices

### Recommended Configuration
```
 Enable Rate Limiting (10-15 req/min)
 Enable VPN/Proxy Detection
 Enable Datacenter Blocking (unless you need CDNs)
 Block Bad Bots + AI Bots
 Enable Fake Browser Detection
 Enable Stats Logging
 Whitelist your office/home IP
 Whitelist legitimate bots (Googlebot, Bingbot)
 Whitelist trusted ASNs (Google, Microsoft for SEO)
 Regular log review
```

### Exception System Best Practices
```
 Always whitelist search engines: Googlebot, Bingbot
 Use ASN whitelisting for major services: Google (15169), Microsoft (8075)
 Verify bot IPs: Use official verification methods
 Monitor exceptions: Check logs for allowed bot activity
 Keep trusted modules enabled: Prevents ProcessWire conflicts
 Document exceptions: Note why each exception exists
 Review periodically: Remove unnecessary exceptions
```

### What WireWall Does NOT Replace
-  Regular ProcessWire/PHP updates
-  Strong passwords and 2FA
-  HTTPS/SSL certificates
-  Server hardening (firewall, SSH, etc.)
-  Regular backups
-  DDoS protection at network level
-  Application-level security (SQL injection, XSS)

**Use WireWall as part of a comprehensive security strategy.**

---

## File Structure

```
/site/modules/WireWall/
├── WireWall.module.php          # Main module
├── README.md                    # This file
├── INSTALL.md                   # Installation guide
├── CONFIGURATIONS.md            # Configuration examples
└── LICENSE                      # License

/site/assets/WireWall/           # Persistent data (survives module updates)
├── geoip/                       # MaxMind databases
│   ├── GeoLite2-Country.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb       # optional
├── vendor/                      # Composer dependencies
│   └── geoip2/                  # MaxMind GeoIP2 library
└── composer.json                # Composer config
```

---

## Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## License

This module is provided as-is under the MIT License. See [LICENSE](LICENSE) file for details.

---

## Tips & Tricks

### Whitelist Your Development IPs
```
Always add your office/home IP to whitelist during setup:
Admin → Modules → WireWall → Exceptions → Allowed IPs
Your IP: 1.2.3.4 (automatically detected and shown in config)
```

### Verify Search Engine Bots
```
Use official verification methods:
1. Google: https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
2. Bing: https://www.bing.com/webmasters/help/verifying-bingbot-2195b2e2
3. Add verified IPs to Allowed IPs
4. Add ASNs (Google: 15169, Microsoft: 8075) to Allowed ASNs
```

### Test Before Going Live
```
1. Configure rules
2. Test with VPN from blocked country
3. Verify logs show blocks
4. Ensure admin access always works
5. Test from mobile (different network)
6. Verify search engines can still crawl (check Search Console)
7. Test rate limiting with repeated requests
```

### Monitor Attack Patterns
```
Regular log review reveals patterns:
- Common attack countries
- Bot signatures
- Peak attack times
- Repeated IPs (add to blacklist)
- Legitimate bots being blocked (add to exceptions)
- ASN patterns (datacenters, VPNs)
```

### Optimize for Your Traffic
```
High Traffic Sites:
- Use MaxMind (not HTTP API)
- Increase rate limits
- Enable cache aggressively
- Use ASN whitelisting for CDNs

Low Traffic Sites:
- Can use HTTP API
- Stricter rate limits OK
- More aggressive blocking
- Fewer exceptions needed

E-commerce Sites:
- Moderate rate limits
- Whitelist payment processors
- Enable VPN/Proxy detection
- Whitelist search engines (SEO)
```

### Exception Hierarchy
```
Most Efficient → Least Efficient:
1. Admin Area (automatic)
2. Logged-in Users (automatic, session-based)
3. IP Whitelist (instant)
4. ASN Whitelist (fast, covers entire networks)
5. User-Agent Whitelist (fast, covers bot families)
6. Country Whitelist (covers entire countries)

Best Practice: Use ASN whitelisting for legitimate services
Example: AS15169 whitelists ALL Google services at once
```
