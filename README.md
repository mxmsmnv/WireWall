# WireWall - Advanced Security & Firewall Module for ProcessWire

**Version 1.1.9** | **Author:** Maxim Alex | **GitHub:** [mxmsmnv](https://github.com/mxmsmnv)

Enterprise-grade security and firewall module for ProcessWire CMS with comprehensive geo-blocking, bot protection, rate limiting, VPN/Proxy detection, and city-level access control.

---

## 🛡️ Overview

WireWall is a powerful, production-ready security module that transforms ProcessWire into a fortress. With MaxMind GeoLite2 integration, multi-API threat detection, and file-based caching that scales to millions of IPs, WireWall provides enterprise-level protection without the enterprise complexity.

**Key Benefits:**
- ⚡ **Fast** - File-based cache, 0.5-2ms GeoIP lookups with MaxMind
- 🎯 **Precise** - 12+ priority levels, city/subdivision blocking
- 🤖 **Smart** - AI bot detection, fake browser analysis, datacenter blocking
- 📊 **Insightful** - Comprehensive logging with city/region data
- 🌐 **Scalable** - Handles 1M+ IPs without database overhead

---

## 🔥 Core Features

### 🌍 Geographic Control
- **Country Blocking** - Block or whitelist entire countries (200+ countries)
- **City-Level Blocking** - Block specific cities (e.g., Philadelphia, Beijing, Moscow)
- **Subdivision/Region Blocking** - Block states, provinces, oblasts (e.g., Pennsylvania, California, Krasnodar)
- **MaxMind GeoLite2** - Fast, accurate local geolocation (Country, ASN, City databases)
- **HTTP API Fallback** - Automatic fallback to ip-api.com when MaxMind unavailable
- **IPv4/IPv6 Support** - Full support with CIDR notation

### 🤖 Bot Protection
- **Bad Bot Blocking** - Block scrapers, scanners, and malicious bots (wget, curl, scrapy, nikto, sqlmap)
- **Search Engine Control** - Block/allow search crawlers (Googlebot, Bingbot, Yandex, Baidu)
- **AI Bot Blocking** - Block AI training bots (GPTBot, ClaudeBot, GrokBot, Perplexity, Google-Extended)
- **Custom Bot Lists** - Define your own bot patterns to block
- **Fake Browser Detection** - Advanced User-Agent analysis to detect spoofed browsers

### 🛡️ Security Features
- **Rate Limiting** - Configurable requests per minute with automatic temporary bans
- **VPN/Proxy/Tor Detection** - Multi-API detection with fallback (ip-api.com, ipinfo.io, ipapi.co)
- **Datacenter Blocking** - Block AWS, Google Cloud, DigitalOcean, Azure, and other hosting providers
- **ASN Blocking** - Block specific networks by Autonomous System Number
- **JavaScript Challenge** - Anti-bot challenge page for suspicious requests
- **IP Whitelist/Blacklist** - Manual override for specific IPs, ranges, and CIDR blocks

### 📊 Management & Monitoring
- **File-Based Cache** - Scales to millions of IPs without database overhead
- **Cache Management UI** - View statistics and clear cache by type
- **Priority System** - 12+ priority levels for precise rule control
- **Admin Protection** - Triple-layer admin area protection (never blocks admin)
- **Detailed Logging** - City/region included in all logs
- **Debug Mode** - Comprehensive debug logging for troubleshooting

### 🎨 User Experience
- **Beautiful Block Page** - Modern design with location display and wave pattern
- **Silent 404 Mode** - Alternative stealth blocking mode
- **Custom Redirect** - Redirect blocked users to custom URL
- **Custom Messages** - Personalise block messages

---

## 📋 Requirements

- **ProcessWire:** 3.0.200 or higher
- **PHP:** 8.1 or higher
- **Optional:** MaxMind GeoLite2 databases (Country, ASN, City)
- **Optional:** Composer (for MaxMind GeoIP2 library)

---

## 🚀 Quick Start

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
✓ Enable WireWall
✓ Country Blocking: RU, CN, KP (blacklist)
✓ VPN/Proxy Detection: Enabled
✓ Rate Limiting: 10 requests/min, 60 min ban
✓ Block Bad Bots: Enabled
✓ Enable Stats Logging: Enabled
```

See [INSTALL.md](INSTALL.md) for detailed installation and [CONFIGURATIONS.md](CONFIGURATIONS.md) for advanced setups.

---

## 🎯 Common Use Cases

### 1. Attack Protection (Recommended)
```
Country Blocking: RU, CN, KP, IR, BY (blacklist)
City Blocking: Philadelphia, Beijing (blacklist - adjust for your threat profile)
VPN/Proxy Detection: Enabled
Datacenter Blocking: Enabled
Rate Limiting: 10 req/min, 60 min ban
Bot Blocking: Bad bots + AI bots enabled
Fake Browser Detection: Enabled
```

### 2. E-commerce Security
```
Country Blocking: Blacklist fraud-prone countries
VPN/Proxy Detection: Enabled
Datacenter Blocking: Enabled
Rate Limiting: 15 req/min, 30 min ban
Bot Blocking: Bad bots enabled (keep search bots for SEO)
IP Whitelist: Payment gateway IPs
```

### 3. Local Business (Australia Example)
```
Country Blocking: AU (whitelist - allow only)
Subdivision Blocking: New South Wales, Victoria, Queensland (whitelist)
City Blocking: Sydney, Melbourne, Brisbane (whitelist)
IP Whitelist: Office IP, staff IPs
Rate Limiting: 20 req/min
```

### 4. API Protection
```
IP Whitelist: Known API consumers
Rate Limiting: 100 req/min, 10 min ban
Datacenter Blocking: Disabled (if API clients use cloud)
Bot Blocking: Custom bot list for API abuse
```

### 5. Content Protection (Block AI Scrapers)
```
Block AI Bots: Enabled (GPTBot, ClaudeBot, Perplexity, etc.)
Block Bad Bots: Enabled
Fake Browser Detection: Enabled
Rate Limiting: 5 req/min for suspicious UAs
Datacenter Blocking: Enabled
```

---

## 🌐 MaxMind GeoLite2 Setup

WireWall works with or without MaxMind, but MaxMind is **strongly recommended** for production use.

### Comparison

| Feature | With MaxMind | Without MaxMind |
|---------|-------------|-----------------|
| **Speed** | ⚡ 0.5-2ms | ⏱️ 100-500ms (HTTP API) |
| **Reliability** | ✅ No rate limits | ⚠️ Rate limited |
| **City/Region** | ✅ Full support | ❌ Not available |
| **Subdivision Blocking** | ✅ Supported | ❌ Not available |
| **Offline Operation** | ✅ Works offline | ❌ Requires internet |
| **Accuracy** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

### Installation (Recommended)

```bash
# 1. Register for free MaxMind account
https://www.maxmind.com/en/geolite2/signup

# 2. Download databases
- GeoLite2-Country.mmdb (required for country blocking)
- GeoLite2-ASN.mmdb (required for ASN detection)
- GeoLite2-City.mmdb (required for city/subdivision blocking)

# 3. Create directory and copy databases
mkdir -p /path/to/site/modules/WireWall/geoip/
cp *.mmdb /path/to/site/modules/WireWall/geoip/

# 4. Install PHP library (in module directory)
cd /path/to/site/modules/WireWall
composer require geoip2/geoip2

# 5. Verify in admin
Admin → Modules → WireWall → Configure
✅ MaxMind GeoLite2 Status: Active
```

### Database Update Schedule

MaxMind releases updated databases every **Tuesday and Friday**. For best accuracy:

```bash
# Download latest databases weekly
# Set up cron job to auto-update (optional)
0 2 * * 2,5 cd /path/to/site/modules/WireWall/geoip/ && ./update-maxmind.sh
```

---

## 📊 Logging & Monitoring

### Log Format

**With City Database:**
```
BLOCKED | US (Chicago, Illinois) | 174.198.11.141 | AS6167 CELLCO-PART | subdivision-blocked
ALLOWED | US (Philadelphia, Pennsylvania) | 1.2.3.4 | AS7922 Comcast Cable
BLOCKED | AU (Sydney, New South Wales) | 1.1.1.1 | AS13335 Cloudflare | city-blocked
BLOCKED | RU (Moscow, Moscow) | 5.18.123.45 | AS12389 Rostelecom | country-blocked
```

**Without City Database:**
```
BLOCKED | DE | 185.220.101.1 | AS13335 Cloudflare | country-blocked
ALLOWED | AU | 1.1.1.1 | AS13335 Cloudflare
BLOCKED | CN | 119.23.45.67 | AS4134 Chinanet | vpn-detected
```

### Debug Logging

Enable for troubleshooting (wirewall-debug.txt):
```
getCityData(174.198.11.141): city=Chicago, region=Illinois, country=US
Subdivision check: Illinois, US | Mode: blacklist | Matched: Illinois | Will block: YES
VPN/Proxy check: 1.2.3.4 | API: ip-api.com | Result: proxy detected
Rate limit: 1.2.3.4 | Count: 15/10 | Ban expires: 2025-12-19 14:30:00
```

### Log Files Location

```
Admin → Setup → Logs
- wirewall.txt (main log)
- wirewall-debug.txt (debug log)
```

---

## 🔧 Cache Management

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

## 🔒 Priority System

WireWall evaluates requests in this order (higher priority = checked first):

1. **Admin Area Protection** → ALLOW (always, never blocked)
2. **IP Whitelist** → ALLOW (bypasses all rules)
3. **Rate Limiting** → BLOCK if exceeded
4. **IP Blacklist** → BLOCK (always)
5. **JS Challenge** → CHALLENGE if suspicious
6. **VPN/Proxy/Tor Detection** → BLOCK if detected
7. **Datacenter Detection** → BLOCK if detected
8. **ASN Blocking** → BLOCK if in ASN blacklist
9. **Bot Blocking** → BLOCK if matched (bad/search/AI bots)
10. **Global Rules** → BLOCK if matched (paths/UA/referers)
11. **Country Blocking** → BLOCK if matched
12. **City Blocking** → BLOCK if matched
13. **Subdivision Blocking** → BLOCK if matched
14. **Country-Specific Rules** → BLOCK if matched
15. **Default** → ALLOW ✅

---

## 🤖 Bot Detection Details

### Bad Bots (Malicious)
```
wget, curl, python-requests, scrapy, nmap, nikto, sqlmap
semrush, ahrefs, majestic, dotbot, mj12bot, ahrefsbot
```

### Search Engine Bots
```
Googlebot, Bingbot, Slurp (Yahoo), Yandex, Baidu
DuckDuckBot, Sogou, Exabot
```
⚠️ **Warning:** Blocking search bots prevents indexing!

### AI Training Bots
```
GPTBot (OpenAI), ClaudeBot (Anthropic), GrokBot (xAI)
PerplexityBot, Google-Extended, Applebot-Extended
ChatGPT-User, Claude-Web, Omgilibot, FacebookBot
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

## 🎨 Block Page Customization

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
- No block page shown
- Looks like page doesn't exist
- Frustrates attackers
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

## ⚡ Performance Benchmarks

### With MaxMind GeoLite2
```
GeoIP Lookup:        0.5-2ms
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

---

## 🔍 Troubleshooting

### Issue: Admin Area Blocked
```
WireWall NEVER blocks admin area by design.
If you can't access admin:
1. Check server configuration
2. Verify admin path in config.php
3. Check firewall rules outside WireWall
```

### Issue: Legitimate Traffic Blocked
```
1. Check IP Whitelist: Add trusted IPs
2. Adjust Rate Limiting: Increase limits
3. Review Logs: Admin → Setup → Logs → wirewall
4. Disable specific rules temporarily
5. Check subdivision/city blocking (might be too broad)
```

### Issue: Bots Still Getting Through
```
1. Enable Fake Browser Detection
2. Enable Datacenter Blocking
3. Reduce Rate Limiting threshold
4. Check custom bot patterns
5. Enable JS Challenge for suspicious requests
```

### Issue: MaxMind Not Working
```
1. Verify databases in /site/modules/WireWall/geoip/
2. Check composer installation: composer require geoip2/geoip2
3. Verify file permissions (readable by PHP)
4. Check module config: MaxMind Status indicator
```

### Issue: High Memory Usage
```
1. City DB is large (~70MB) - optional, can be removed
2. Consider using Country + ASN only (~12MB)
3. Clear cache regularly if millions of IPs
4. Reduce cache TTL in code if needed
```

---

## 🔐 Security Best Practices

### Recommended Configuration
```
✓ Enable Rate Limiting (10-15 req/min)
✓ Enable VPN/Proxy Detection
✓ Enable Datacenter Blocking (unless you need CDNs)
✓ Block Bad Bots + AI Bots
✓ Enable Fake Browser Detection
✓ Enable Stats Logging
✓ Whitelist your office/home IP
✓ Regular log review
```

### What WireWall Does NOT Replace
- ✗ Regular ProcessWire/PHP updates
- ✗ Strong passwords and 2FA
- ✗ HTTPS/SSL certificates
- ✗ Server hardening (firewall, SSH, etc.)
- ✗ Regular backups
- ✗ DDoS protection at network level
- ✗ Application-level security (SQL injection, XSS)

**Use WireWall as part of a comprehensive security strategy.**

---

## 📁 File Structure

```
WireWall/
├── WireWall.module.php          # Main module
├── README.md                    # This file
├── INSTALL.md                   # Installation guide
├── CONFIGURATIONS.md            # Configuration examples
├── LICENSE                      # License
├── geoip/                       # MaxMind databases (create this)
│   ├── GeoLite2-Country.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb
├── vendor/                      # Composer dependencies
│   └── geoip2/                  # MaxMind GeoIP2 library
└── composer.json                # Composer config
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This module is provided as-is under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🙏 Credits & Acknowledgements

- **MaxMind** - GeoLite2 free databases ([MaxMind.com](https://www.maxmind.com))
- **ProcessWire** - Exceptional CMS platform ([ProcessWire.com](https://processwire.com))
- **Community** - Testing, feedback, and support
- **ip-api.com** - Free GeoIP API fallback
- **ipinfo.io** - VPN/Proxy detection API
- **ipapi.co** - Alternative detection API

---

## 📞 Support & Resources

- **GitHub Issues:** [Report bugs/features](https://github.com/mxmsmnv/WireWall/issues)
- **Documentation:** [Wiki](https://github.com/mxmsmnv/WireWall/wiki)
- **ProcessWire Forum:** [Support thread](https://processwire.com/talk/topic/31581-wirewall-advanced-security-firewall-module/)
- **Author:** Maxim Alex [@mxmsmnv](https://github.com/mxmsmnv)

---

## 🗺️ Roadmap

**Planned Features:**
- ⏰ Scheduled rule activation (time-based rules)
- 📧 Email alerts for attack patterns
- 📈 Analytics dashboard
- 🔄 Automatic MaxMind database updates
- 🌐 IPv6 geo-blocking improvements
- 🤖 Machine learning bot detection
- 📱 Mobile app for monitoring

---

## 💡 Tips & Tricks

### Whitelist Your Development IPs
```
Always add your office/home IP to whitelist during setup:
Admin → Modules → WireWall → IP Whitelist
Your IP: 1.2.3.4 (automatically detected and shown in config)
```

### Test Before Going Live
```
1. Configure rules
2. Test with VPN from blocked country
3. Verify logs show blocks
4. Ensure admin access always works
5. Test from mobile (different network)
```

### Monitor Attack Patterns
```
Regular log review reveals patterns:
- Common attack countries
- Bot signatures
- Peak attack times
- Repeated IPs (add to blacklist)
```

### Optimise for Your Traffic
```
High Traffic Sites:
- Use MaxMind (not HTTP API)
- Increase rate limits
- Enable cache aggressively

Low Traffic Sites:
- Can use HTTP API
- Stricter rate limits OK
- More aggressive blocking
```

---

**Version:** 1.1.9  
**Last Updated:** December 19, 2025  
**Author:** Maxim Alex  
**License:** MIT
