# WireWall Configuration Examples

Practical configuration examples for common security scenarios. 19 ready-to-use configurations!

---

## 🎯 Basic Configurations

### 1. Blog/News Site

**Goal:** Protect from comment spam and DDoS

```
Enable WireWall: ☑

Rate Limiting:
  ☑ Enable Rate Limiting
  Requests: 20
  Minutes: 60
  Ban Minutes: 30

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor
  
Block Action: Beautiful Block Page
Enable Stats Logging: ☑
```

**Result:** Legitimate readers unaffected, bots blocked.

---

### 2. E-commerce Store

**Goal:** Prevent fraud and bot scraping

```
Enable WireWall: ☑

Country Blocking:
  Mode: Blacklist
  Countries: [known fraud countries]

Rate Limiting:
  Requests: 15
  Minutes: 60
  Ban Minutes: 60

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor
  ☑ Block Datacenters

JavaScript Challenge:
  ☑ Enable JS Challenge

Block Action: Beautiful Block Page
Enable Stats Logging: ☑
```

**Result:** High security, minimal impact on customers.

---

### 3. Corporate Website

**Goal:** Geo-restrict to specific countries

```
Enable WireWall: ☑

Country Blocking:
  Mode: Whitelist
  Countries: US, CA, GB, AU

Rate Limiting:
  Requests: 10
  Minutes: 60
  Ban Minutes: 60

Block Action: Beautiful Block Page
Custom Message: "This website is only accessible from authorized regions."
```

**Result:** Access limited to specified countries only.

---

## 🌍 Geographic Configurations

### 4. Block Attack Sources

**Goal:** Block countries with high attack rates

```
Country Blocking:
  Mode: Blacklist
  Countries: [select based on your logs]
  
City Blocking:
  ☑ Enable City Blocking
  Mode: Blacklist
  Cities:
    Philadelphia
    Beijing
    Shanghai
    Lagos
    Mumbai

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor
```

**Result:** Targeted blocking of known attack sources.

---

### 5. Allow Only Local Traffic

**Goal:** Restrict to specific geographic region

```
Country Blocking:
  Mode: Whitelist
  Countries: US

City Blocking:
  ☑ Enable City Blocking
  Mode: Whitelist
  Cities:
    Philadelphia, US
    New York, US
    Boston, US
    Washington, US

Subdivision Blocking:
  ☑ Enable Subdivision Blocking
  Mode: Whitelist
  Subdivisions:
    Pennsylvania, US
    New York, US
    Massachusetts, US
```

**Result:** Only specified US cities/states can access.

---

### 6. Block Specific Regions

**Goal:** Block specific states/provinces

```
Subdivision Blocking:
  ☑ Enable Subdivision Blocking
  Mode: Blacklist
  Subdivisions:
    California, US
    Texas, US
    New South Wales, AU
    Bavaria, DE

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor
```

**Result:** Block entire regions without blocking whole countries.

**Examples:**
- California, US → BLOCKED
- Texas, US → BLOCKED  
- New York, US → ALLOWED
- Sydney, AU → ALLOWED
- New South Wales, AU → BLOCKED

---

### 7. Allow Only Specific States

**Goal:** Restrict to local states only

```
Subdivision Blocking:
  ☑ Enable Subdivision Blocking
  Mode: Whitelist
  Subdivisions:
    Pennsylvania, US
    New Jersey, US
    Delaware, US

Country Blocking:
  Mode: Whitelist
  Countries: US
```

**Result:** Only these 3 US states can access.

---

## 🛡️ Security-Focused Configurations

### 8. Maximum Security

**Goal:** Lockdown against all automated threats

```
Enable WireWall: ☑

IP Whitelist:
  YOUR.OFFICE.IP.ADDRESS
  YOUR.HOME.IP.ADDRESS

Rate Limiting:
  Requests: 5
  Minutes: 60
  Ban Minutes: 120

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor
  ☑ Block Datacenters

ASN Blocking:
  AS16509  (Amazon AWS)
  AS15169  (Google Cloud)
  AS14061  (DigitalOcean)

JavaScript Challenge:
  ☑ Enable JS Challenge

Global Rules:
  User-Agent: bot, crawler, scraper, scanner
  Path: /wp-admin, /administrator, /.env

Block Action: Silent 404
```

**Result:** Maximum protection, legitimate users unaffected.

---

### 9. Development/Staging Protection

**Goal:** Allow only team members

```
Enable WireWall: ☑

IP Whitelist:
  OFFICE.IP.1
  OFFICE.IP.2
  DEVELOPER.HOME.IP.1
  DEVELOPER.HOME.IP.2

Country Blocking:
  Mode: Blacklist
  Countries: [all except your country]

Rate Limiting:
  Requests: 50
  Minutes: 60

Block Action: Beautiful Block Page
Custom Message: "This is a development environment. Access is restricted to authorized personnel only."
```

**Result:** Only whitelisted IPs can access.

---

### 10. API Endpoint Protection

**Goal:** Protect API from abuse

```
Country-Specific Rules:
  Country: All
  Paths: /api/*, /graphql
  Rules:
    - User-Agent must contain "YourApp/"
    - No curl, wget, python

Rate Limiting:
  Requests: 30
  Minutes: 60
  Ban Minutes: 15

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor
  ☑ Block Datacenters
```

**Result:** API protected from automated abuse.

---

## ⚡ Performance-Optimized Configurations

### 11. High-Traffic Site

**Goal:** Protect without impacting performance

```
Enable WireWall: ☑

Rate Limiting:
  Requests: 30
  Minutes: 60
  Ban Minutes: 30

VPN/Proxy Detection:
  ☐ Block VPN/Proxy/Tor  (disabled for performance)

JavaScript Challenge:
  ☐ Enable JS Challenge  (disabled for performance)

Block Action: Silent 404
Enable Stats Logging: ☐  (disabled for performance)
```

**Result:** Minimal overhead, rate limiting only.

---

### 12. CDN-Friendly

**Goal:** Work with CloudFlare/CDN

```
Enable WireWall: ☑

(Add in config.php:)
$config->wireWallTrustProxy = true;
$config->wireWallProxyHeader = 'HTTP_CF_CONNECTING_IP';

Rate Limiting:
  Requests: 20
  Minutes: 60

Country Blocking:
  Mode: Blacklist
  Countries: [as needed]
```

**Result:** Correct IP detection behind CDN.

---

## 🎨 User Experience Configurations

### 13. Friendly Block Page

**Goal:** Professional, helpful block message

```
Block Action: Beautiful Block Page

Custom Block Message:
"We've detected unusual activity from your location. 
If you believe this is an error, please contact 
support@yoursite.com with your IP address."

Enable Stats Logging: ☑
```

**Result:** Users know how to get help.

---

### 14. Silent Blocking

**Goal:** Hide from attackers

```
Block Action: Silent 404

Country Blocking:
  Mode: Blacklist
  Countries: [attack sources]

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor

Enable Stats Logging: ☑
```

**Result:** Attackers see 404, not block page.

---

### 15. Custom Redirect

**Goal:** Send blocked users elsewhere

```
Block Action: Redirect

Redirect URL: https://yoursite.com/access-restricted

(Create custom page at /access-restricted/ with explanation)
```

**Result:** Full control over block page.

---

## 🧪 Testing Configurations

### 16. Safe Testing

**Goal:** Test WireWall without breaking site

```
Enable WireWall: ☑

IP Whitelist:
  YOUR.IP.ADDRESS  (CRITICAL!)

Rate Limiting:
  Requests: 3
  Minutes: 1
  Ban Minutes: 2

Block Action: Beautiful Block Page
Enable Stats Logging: ☑
```

**Testing Steps:**
1. Add your IP to whitelist FIRST
2. Enable module
3. Use VPN or mobile to test
4. Check logs constantly
5. Remove your IP from whitelist last

---

## 🔧 Advanced Configurations

### 17. Multi-Layer Defense

**Goal:** Comprehensive protection

```
Priority Layers:

1. IP Whitelist:
   OFFICE.IP
   
2. Rate Limiting:
   10 req/min, 60 min ban
   
3. IP Blacklist:
   KNOWN.ATTACKER.IP
   
4. VPN/Proxy Detection:
   ☑ Enabled
   
5. Country Blocking:
   Blacklist: [attack sources]
   
6. City Blocking:
   Blacklist: [attack cities]
   
7. Subdivision Blocking:
   Blacklist: [attack regions]
   
8. ASN Blocking:
   Block datacenter ASNs
   
9. Global Rules:
   Block bots, bad UAs, suspicious paths
```

**Result:** 9 layers of protection!

---

### 18. Temporary Event Protection

**Goal:** Extra protection during special events

```
(Before Event)

Enable WireWall: ☑

Rate Limiting:
  Requests: 5
  Minutes: 60
  Ban Minutes: 120

VPN/Proxy Detection:
  ☑ Block VPN/Proxy/Tor
  ☑ Block Datacenters

Country Blocking:
  Mode: Whitelist
  Countries: [your target countries only]

(After Event - Relax Settings)

Rate Limiting:
  Requests: 20
  Minutes: 60

Country Blocking:
  Mode: Disabled or Blacklist only
```

---

## 📊 Monitoring Configurations

### 19. Detailed Logging

**Goal:** Maximum visibility

```
Enable WireWall: ☑
Enable Stats Logging: ☑

(Install GeoLite2-City for detailed logs)

Logs will show:
BLOCKED | US (Philadelphia, Pennsylvania) | 1.2.3.4 | AS7922 Comcast | rate-limit

Monitor logs:
tail -f /site/assets/logs/wirewall.txt

Analyze with:
grep BLOCKED /site/assets/logs/wirewall.txt | wc -l
grep "Philadelphia" /site/assets/logs/wirewall.txt
```

---

## 💡 Pro Tips

### IP Whitelist Best Practices

```
IP Whitelist:
  # Your IPs (always whitelist yourself!)
  YOUR.OFFICE.IP
  YOUR.HOME.IP
  
  # Trusted services
  MONITORING.SERVICE.IP
  BACKUP.SERVICE.IP
  
  # Important customers (if needed)
  VIP.CUSTOMER.IP
  
  # Comments for organization
  # Support ranges in CIDR: 192.168.1.0/24
```

### Country Blocking Strategy

```
Start Conservative:
1. Enable logging only (no blocking)
2. Monitor for 1 week
3. Analyze top blocked countries
4. Add to blacklist gradually
5. Monitor for false positives

Avoid:
- Blocking too many countries at once
- Blocking your own country
- Blocking without monitoring
```

### Rate Limiting Tuning

```
Site Type         | Req/Min | Ban Min
------------------+---------+---------
Blog/News         | 20      | 30
E-commerce        | 15      | 60
Corporate         | 10      | 60
API               | 30      | 15
High-traffic      | 30      | 30
Landing Page      | 5       | 120
```

---

## 🚨 Emergency Configurations

### Under DDoS Attack

```
IMMEDIATE ACTIONS:

1. Enable WireWall if not enabled
2. Set aggressive rate limiting:
   Requests: 3
   Minutes: 1
   Ban Minutes: 120

3. Block proxy/VPN:
   ☑ Block VPN/Proxy/Tor
   ☑ Block Datacenters

4. Country whitelist:
   Mode: Whitelist
   Countries: [your main countries only]

5. Clear cache if overwhelmed:
   Admin → Modules → WireWall → Clear All Cache

6. Monitor logs:
   tail -f /site/assets/logs/wirewall.txt

7. Add attacking IPs to blacklist
8. Add attacking ASNs to ASN blocking
```
