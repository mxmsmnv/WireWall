# WireWall - ProcessWire Security & Firewall Module

**Version 1.0.8** | **Author:** Maxim Alex | **GitHub:** [mxmsmnv](https://github.com/mxmsmnv)

Advanced security and firewall module for ProcessWire CMS with comprehensive geo-blocking, rate limiting, VPN/Proxy detection, and city-level access control with subdivision/region blocking.

---

## 🔥 Key Features

### 🌍 Geographic Control
- **Country Blocking** - Block or whitelist entire countries
- **City-Level Blocking** - Block specific cities (e.g., Philadelphia, Beijing)
- **Subdivision/Region Blocking** - Block states, provinces, oblasts (e.g., Pennsylvania, California, Delaware)
- **MaxMind GeoLite2** - Fast, accurate geolocation with local databases
- **HTTP API Fallback** - Automatic fallback to ip-api.com when MaxMind unavailable

### 🛡️ Security Features
- **Rate Limiting** - Configurable requests per minute with automatic bans
- **VPN/Proxy/Tor Detection** - Multi-API detection with fallback
- **Datacenter Blocking** - Block AWS, Google Cloud, DigitalOcean, etc.
- **ASN Blocking** - Block specific networks by ASN
- **JavaScript Challenge** - Anti-bot challenge for suspicious requests
- **Fake Browser Detection** - Advanced User-Agent analysis

### 📊 Smart Management
- **File-Based Cache** - Scales to millions of IPs (no database overhead)
- **Cache Management UI** - View statistics and clear cache by type
- **Priority System** - 12+ priority levels for precise control
- **Admin Protection** - Triple-layer admin area protection
- **Detailed Logging** - City/region included in logs with debug support

### 🎨 User Experience
- **Beautiful Block Page** - Modern design with location display
- **Silent 404 Mode** - Alternative blocking mode
- **Custom Redirect** - Redirect blocked users to custom URL
- **IP Whitelist/Blacklist** - Manual override for specific IPs

---

## 📦 Requirements

- **ProcessWire:** 3.0.200+
- **PHP:** 7.4+ (8.0+ recommended)
- **Optional:** MaxMind GeoLite2 databases (Country, ASN, City)
- **Optional:** Composer (for MaxMind GeoIP2 library)

---

## 🚀 Quick Start

```bash
# 1. Download module
git clone https://github.com/mxmsmnv/WireWall.git

# 2. Install
cp -r WireWall /path/to/site/modules/

# 3. Activate
Admin → Modules → Site → WireWall → Install

# 4. Configure
Admin → Modules → WireWall → Configure
```

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

---

## 🎯 Common Use Cases

### Block Attack Sources
```
Country Blocking: RU, CN, KP
City Blocking: Philadelphia, Beijing (blacklist)
Subdivision Blocking: Pennsylvania (blacklist)
VPN/Proxy Detection: Enabled
Rate Limiting: 10 req/min, 60 min ban
```

### Allow Only Local Traffic
```
Country Blocking: AU (whitelist)
Subdivision Blocking: New South Wales, AU (whitelist)
City Blocking: Sydney, Melbourne, Brisbane (whitelist)
IP Whitelist: Your office IP
```

### E-commerce Protection
```
Country Blocking: Blacklist known fraud countries
VPN/Proxy Detection: Enabled
Datacenter Blocking: Enabled
Rate Limiting: 15 req/min
Subdivision Blocking: Block problem regions
```

See [CONFIGURATIONS.md](CONFIGURATIONS.md) for more examples.

---

## 📊 Log Format

With City Database:
```
BLOCKED | US (Chicago, Illinois) | 174.198.11.141 |  AS6167 CELLCO-PART | subdivision-blocked
ALLOWED | US (Philadelphia, Pennsylvania) | 1.2.3.4 | AS7922 Comcast
BLOCKED | AU (Sydney, New South Wales) | 1.1.1.1 | AS13335 Cloudflare | city-blocked
```

Without City Database:
```
BLOCKED | DE | 185.220.101.1 | AS13335 Cloudflare | country-blocked
ALLOWED | AU | 1.1.1.1 | AS13335 Cloudflare
```

Debug Log (wirewall-debug.txt):
```
getCityData(174.198.11.141): city= Chicago, region= Illinois, country=US
Subdivision check: Illinois, US | Mode: blacklist | Matched: Illinois | Will block: YES
```

---

## 🌐 MaxMind GeoLite2

WireWall works with or without MaxMind databases:

**WITH MaxMind (Recommended):**
- ✅ Fast local lookups (~0.5-2ms)
- ✅ No rate limits
- ✅ City/Region support
- ✅ Subdivision blocking
- ✅ Offline operation

**WITHOUT MaxMind:**
- ⚠️ Uses HTTP API (slower)
- ⚠️ Rate limits apply
- ⚠️ No city/region support
- ⚠️ No subdivision blocking
- ⚠️ Requires internet

### Install MaxMind (Optional)

```bash
# 1. Register (free)
https://www.maxmind.com/en/geolite2/signup

# 2. Download databases
- GeoLite2-Country.mmdb (required for country blocking)
- GeoLite2-ASN.mmdb (required for ASN detection)
- GeoLite2-City.mmdb (optional - for city/subdivision blocking)

# 3. Place in module
cp *.mmdb /path/to/site/modules/WireWall/geoip/

# 4. Install PHP library
cd /path/to/site/modules/WireWall
composer require geoip2/geoip2

# 5. Verify in admin
Admin → Modules → WireWall → Configure
✅ MaxMind GeoLite2 Status: Active
```

---

## 🎨 Block Page

Modern, professional block page with:
- Location display (City, Region, Country)
- IP address
- Custom message
- Responsive design
- Wave pattern background

---

## 🔧 Cache Management

Built-in cache management UI:
- **View Statistics** - Total files, rate limits, bans, proxies, geo data
- **Clear by Type** - Rate limits, bans, proxy cache, geo cache
- **Clear All** - Full cache reset

Location: `Admin → Modules → WireWall → Configure → Cache Management`

---

## 📝 Priority System

WireWall checks rules in this order:

1. **Admin Area** → ALLOW (always)
2. **IP Whitelist** → ALLOW
3. **Rate Limiting** → BLOCK if exceeded
4. **IP Blacklist** → BLOCK
5. **JS Challenge** → CHALLENGE if suspicious
6. **VPN/Proxy/Tor** → BLOCK if detected
7. **Datacenter** → BLOCK if detected
8. **ASN Blocking** → BLOCK if in list
9. **Global Rules** → BLOCK if matched
10. **Country Blocking** → BLOCK if matched
11. **City Blocking** → BLOCK if matched
12. **Subdivision Blocking** → BLOCK if matched
13. **Country Rules** → BLOCK if matched
14. **ALLOW** ✅

---

## 🔍 Debug Features

WireWall includes comprehensive debug logging:

**Main Log (wirewall.txt):**
- All access attempts
- Block/allow decisions
- Reason codes
- City/region information

**Debug Log (wirewall-debug.txt):**
- getCityData() results
- Subdivision matching
- API errors
- Detailed diagnostics

Enable debug logging:
```
Admin → Modules → WireWall → Configure
☑ Enable Stats Logging
```

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Submit pull request

---

## 🙏 Credits

- **MaxMind** - GeoLite2 databases
- **ProcessWire** - Amazing CMS platform
- **Community** - Testing and feedback

---

## ⚡ Performance

- **File Cache:** Scales to 1M+ IPs
- **GeoIP Lookup:** 0.5-2ms with MaxMind
- **Rate Limiting:** Fast file-based counters
- **Memory:** ~70MB with City DB, ~12MB without

---

## 🔐 Security Notice

WireWall enhances security but doesn't replace:
- Regular updates
- Strong passwords
- HTTPS/SSL
- Server hardening
- Regular backups

Use WireWall as part of comprehensive security strategy.
