# WireWall Configuration Examples

Ready-to-use configurations for common security scenarios.

---

## Basic Configurations

### Recommended privacy/proxy baseline

```text
Per-class proxy/privacy policy: enabled
IP intelligence mode: local_only
iCloud / privacy relay: allow
Consumer VPN: allow
Residential proxy suspected: allow
Unknown proxy: challenge
Datacenter proxy: block
Tor: block
Sensitive paths: /login, /checkout, /forms, /api
Sensitive minimum action: challenge
```

This keeps ordinary privacy-focused users behind normal rate, trigger, and
abuse controls without treating them as trusted bypasses. During an incident,
use dashboard TTL rules or the **Under Attack** profile, preview its diff, and
restore the automatically created snapshot afterward.

### 1. Blog / News Site

**Goal:** Protect from comment spam and DDoS

```
Enable WireWall: ✅
Enable Logging:  ✅

Rate Limiting:
  Requests: 20 / min
  Ban: 30 min

Bot Protection:
  ✅ Block Bad Bots

VPN / Proxy:
  ✅ Block VPN/Proxy/Tor

Block Action: Show block page
```

---

### 2. E-commerce Store

**Goal:** Prevent fraud, bot scraping, and carding attacks

```
Enable WireWall: ✅

Country Blocking:
  Mode: Blacklist
  Countries: [high-fraud countries based on your logs]

Rate Limiting:
  Requests: 15 / min
  Ban: 60 min

VPN / Proxy / Datacenter:
  ✅ Block VPN/Proxy/Tor
  ✅ Block Datacenters

Bot Protection:
  ✅ Block Bad Bots
  ✅ JS Challenge

Exceptions:
  Known Bot ASNs: 15169 (Google), 8075 (Microsoft)
```

---

### 3. Corporate Website — Geo-Restricted

**Goal:** Allow only specific countries

```
Country Blocking:
  Mode: Whitelist
  Countries: US, CA, GB, AU

Rate Limiting:
  Requests: 10 / min
  Ban: 60 min

Block Action: Show block page
Custom Message: "This website is only accessible from authorized regions."
```

---

## Security-Focused Configurations

### 4. Maximum Security

**Goal:** Lockdown against all automated threats

```
IP Whitelist:
  YOUR.OFFICE.IP
  YOUR.HOME.IP

Rate Limiting:
  Requests: 5 / min
  Ban: 120 min

VPN / Proxy / Datacenter:
  ✅ Block VPN/Proxy/Tor
  ✅ Block Datacenters

ASN Blocking:
  AS16509  (Amazon AWS)
  AS15169  (Google Cloud)
  AS14061  (DigitalOcean)

Bot Protection:
  ✅ Block Bad Bots
  ✅ Block AI Bots
  ✅ JS Challenge

Custom Block Rules → Paths:
  /wp-admin/*
  /administrator/*
  /.env
  /xmlrpc.php

Block Action: Silent 404

Note: Logged-in users bypass all checks automatically.
```

---

### 5. Development / Staging Server

**Goal:** Allow only team members

```
IP Whitelist:
  OFFICE.IP.1
  OFFICE.IP.2
  DEVELOPER.HOME.IP

Country Blocking:
  Mode: Blacklist
  Countries: [all except your country]

Rate Limiting:
  Requests: 50 / min

Block Action: Show block page
Custom Message: "Development environment — access restricted."
```

---

### 6. Content Protection — Block AI Scrapers

**Goal:** Prevent AI training bots from harvesting content

```
Bot Protection:
  ✅ Block AI Bots  (GPTBot, ClaudeBot, GrokBot, Perplexity…)
  ✅ Block Bad Bots

VPN / Proxy / Datacenter:
  ✅ Block Datacenters

Exceptions:
  Known Bot User-Agents: Googlebot, Bingbot  (keep for SEO)
  Known Bot ASNs: 15169, 8075
```

---

## Geographic Configurations

### 7. Block Specific Regions (Subdivisions)

**Goal:** Block entire states or provinces without blocking the whole country

```
Geo Blocking → Subdivision Blocking:
  ✅ Enable Subdivision Blocking
  Mode: Blacklist
  Subdivisions:
    California, US
    Texas, US
    New South Wales, AU

VPN / Proxy:
  ✅ Block VPN/Proxy/Tor
```

Result: California → BLOCKED, New York → ALLOWED, Sydney → BLOCKED.

---

### 8. Allow Only Local States

**Goal:** Restrict to specific US states

```
Country Blocking:
  Mode: Whitelist
  Countries: US

Geo Blocking → Subdivision Blocking:
  ✅ Enable Subdivision Blocking
  Mode: Whitelist
  Subdivisions:
    Pennsylvania, US
    New Jersey, US
    Delaware, US
```

---

## Performance Configurations

### 9. High-Traffic Site

**Goal:** Protect without impacting performance

```
Enable WireWall: ✅

Rate Limiting:
  Requests: 30 / min
  Ban: 30 min

VPN / Proxy:
  ❌ Block VPN/Proxy/Tor  (skip — adds latency)

JS Challenge:
  ❌  (skip — adds latency)

Block Action: Silent 404
Enable Logging: ❌  (skip for performance)
```

---

### 10. Behind Cloudflare / CDN

**Goal:** Correct IP detection behind a CDN

Add to `config.php`:
```php
$config->wireWallTrustProxy = true;
$config->wireWallProxyHeader = 'HTTP_CF_CONNECTING_IP';
```

```
Rate Limiting:
  Requests: 20 / min

Country Blocking:
  Mode: Blacklist
  Countries: [as needed]

VPN / Proxy / Datacenter:
  ❌ Block Datacenters  (Cloudflare IPs are datacenter IPs)
```

---

## Emergency Configurations

### Under DDoS Attack

**Immediate actions:**

```
1. Enable WireWall (if not already)

2. Set aggressive rate limiting:
   Requests: 3 / min
   Ban: 120 min

3. Enable:
   ✅ Block VPN/Proxy/Tor
   ✅ Block Datacenters

4. Country Blocking:
   Mode: Whitelist
   Countries: [your main markets only]

5. Add attacking IPs to IP Blacklist

6. Add attacking ASNs to Blocked ASNs

7. Monitor:
   Admin → Setup → WireWall  (live dashboard)
   Admin → Setup → Logs → wirewall

8. Clear cache if overwhelmed:
   Admin → Modules → WireWall → Cache Management → Clear All Cache
```

---

## AJAX Troubleshooting

If third-party modules break after enabling WireWall, try in order:

```
1. Add path to Custom Trusted AJAX Paths:
   /my-module-path/

2. Add to Custom API Paths (all HTTP methods):
   /my-api/

3. Last resort — enable Disable AJAX Protection Completely
   (bypasses WireWall for all POST AJAX requests)
```

Note: Logged-in ProcessWire users are exempt from all checks automatically.

---

## Rate Limiting Reference

| Site Type | Req/Min | Ban (min) |
|---|---|---|
| Blog / News | 20 | 30 |
| E-commerce | 15 | 60 |
| Corporate | 10 | 60 |
| API | 30 | 15 |
| High-traffic | 30 | 30 |
| Landing Page | 5 | 120 |

---

## Exception Scopes

Use the narrowest scope that solves the problem:

| Setting | Scope |
|---|---|
| IP Whitelist | Full-firewall bypass for tightly controlled trusted IPs only |
| Known Bot IPs / ASNs / User-Agents | Skip bot-category and fake-browser heuristics; all other protections continue |
| Browser / Client Compatibility Exceptions | Skip only fake-browser and JavaScript-challenge heuristics |
| Country Whitelist mode | Geo policy; not an exception to bans, triggers, rate limits, or explicit blocks |

User-Agent text is spoofable. Known bot rules should not be treated as proof of
identity, and broad browser-family names belong only in compatibility exceptions.
Prefer known bot IP/CIDR data where it is maintained and reliable.

Configured Googlebot and Bingbot User-Agent rules use cached forward-confirmed
reverse DNS. A UA-only match that fails verification receives no exception.
Verified configured crawlers may skip proxy/datacenter/ASN heuristics, but they
still obey bans, triggers, rate limits, explicit blocks, and geo policy.

```
Known Bot ASNs:
  15169  — Google (Googlebot, GSC, Analytics)
  8075   — Microsoft (Bingbot)
  32934  — Facebook (Social preview crawler)
  13238  — Yandex
  13335  — Cloudflare
```
