# WireWall Installation Guide

---

## Requirements

**Required**
- ProcessWire 3.0.200 or higher
- PHP 8.1 or higher
- Write permissions on `/site/modules/` and `/site/assets/cache/`

**Optional (for MaxMind)**
- Composer
- Free MaxMind account
- ~82 MB disk space for all three databases

---

## Step 1 — Install the module files

```bash
cd /path/to/processwire/site/modules/
git clone https://github.com/mxmsmnv/WireWall.git
```

Or download ZIP:
```bash
wget https://github.com/mxmsmnv/WireWall/archive/master.zip
unzip master.zip
mv WireWall-master WireWall
```

---

## Step 2 — Install in ProcessWire

1. Login to the admin
2. Go to **Modules → Refresh**
3. Find **WireWall** in the list, click **Install**
4. Find **WireWall Dashboard** in the list, click **Install**

The dashboard is a separate `Process` module that creates **Admin → Setup → WireWall** automatically.

WireWall also creates a dedicated `wirewall_settings` table. On upgrades, the
existing ProcessWire module configuration is imported automatically and retained
as a synchronized fallback.

---

## Step 3 — Initial configuration

1. Go to **Modules → Configure → WireWall**
2. Check **Enable WireWall**
3. Check **Enable Logging**
4. Set Rate Limiting: 10 requests / 60 min ban
5. Add your IP to the whitelist (IP Control → IP Whitelist)
6. Click **Save**

---

## Step 4 — MaxMind GeoLite2 (recommended)

MaxMind provides fast, accurate geolocation without external API calls.
Required for city and subdivision blocking.

### 4.1 Register

1. Go to https://www.maxmind.com/en/geolite2/signup
2. Create a free account and verify email

### 4.2 Download databases

From https://www.maxmind.com/en/accounts/current/geoip/downloads download:

| File | Size | Required for |
|---|---|---|
| GeoLite2-Country.mmdb | ~7 MB | Country blocking |
| GeoLite2-ASN.mmdb | ~5 MB | ASN detection, datacenter blocking |
| GeoLite2-City.mmdb | ~70 MB | City and subdivision blocking |

### 4.3 Place databases

```bash
mkdir -p /path/to/site/assets/WireWall/geoip/

# Extract and copy .mmdb files
tar -xzf GeoLite2-Country_*.tar.gz
tar -xzf GeoLite2-ASN_*.tar.gz
tar -xzf GeoLite2-City_*.tar.gz   # optional

cp GeoLite2-Country_*/GeoLite2-Country.mmdb /path/to/site/assets/WireWall/geoip/
cp GeoLite2-ASN_*/GeoLite2-ASN.mmdb         /path/to/site/assets/WireWall/geoip/
cp GeoLite2-City_*/GeoLite2-City.mmdb        /path/to/site/assets/WireWall/geoip/
```

### 4.4 Install PHP library

```bash
cd /path/to/site/assets/WireWall/
composer require geoip2/geoip2
```

### 4.5 Verify

Go to **Modules → WireWall → Configure** — the Geo Blocking section shows MaxMind status.

---

## Directory structure after installation

```
/site/modules/WireWall/
├── WireWall.module.php          Main firewall module
├── ProcessWireWall.module.php   Dashboard module
├── README.md
├── INSTALL.md
├── CONFIGURATIONS.md
└── CHANGELOG.md

/site/assets/WireWall/           Persistent — NOT deleted on module updates
├── geoip/
│   ├── GeoLite2-Country.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb       optional
├── vendor/                      Composer dependencies
├── composer.json
└── composer.lock

/site/assets/cache/WireWall/     Auto-created cache directory
├── ratelimit_*.cache            Rate limit counters
├── ban_*.cache                  Active bans
├── proxy_*.cache                VPN/Proxy detection results
└── geo_*.cache                  GeoIP lookup results
```

---

## Behind a CDN or reverse proxy

If your server is behind Cloudflare, Incapsula, or Sucuri, add to `config.php`:

```php
// Cloudflare
$config->wireWallTrustProxy = true;
$config->wireWallProxyHeader = 'HTTP_CF_CONNECTING_IP';

// Incapsula
$config->wireWallTrustProxy = true;
$config->wireWallProxyHeader = 'HTTP_INCAP_CLIENT_IP';

// Generic (X-Forwarded-For)
$config->wireWallTrustProxy = true;
// omit wireWallProxyHeader to use X-Forwarded-For
```

WireWall validates that `REMOTE_ADDR` belongs to the CDN's published IP ranges before trusting proxy headers, so these settings are safe.

---

## Testing

### Test 1 — Basic block

1. Add your IP to the **IP Blacklist** temporarily
2. Open the site in a private/incognito window
3. You should see the block page
4. Remove your IP from the blacklist

### Test 2 — Rate limiting

1. Set rate limit to 3 requests / 1 minute
2. Refresh the page 4 times quickly
3. On the 4th request you should be blocked
4. Reset rate limit to normal values

### Test 3 — MaxMind (if installed)

1. Open `Admin → Setup → Logs → wirewall`
2. Entries should show country codes: `BLOCKED | US (Philadelphia, Pennsylvania) | ...`

### Test 4 — Dashboard

1. Go to `Admin → Setup → WireWall`
2. Stat cards should show request counts
3. The chart shows the last 24 hours

---

## Updating

### Module files

```bash
cd /path/to/site/modules/WireWall/
git pull origin main
```

Then go to **Modules → Refresh** in the admin. MaxMind databases and Composer dependencies in `/site/assets/WireWall/` are preserved.

### MaxMind databases

MaxMind updates databases every Tuesday and Friday. To update:

```bash
cd /path/to/site/assets/WireWall/geoip/
# Download new .mmdb files and replace the old ones
# File names remain the same — no config change needed
```

---

## Troubleshooting

**Module does not appear after upload**
```bash
chmod 755 /path/to/site/modules/WireWall
chmod 644 /path/to/site/modules/WireWall/*.php
# Then: Modules → Refresh
```

**MaxMind shows "not detected"**
```bash
ls -lh /path/to/site/assets/WireWall/geoip/
# Should list GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb

ls /path/to/site/assets/WireWall/vendor/autoload.php
# If missing: cd /path/to/site/assets/WireWall && composer require geoip2/geoip2
```

**Cache directory errors**
```bash
mkdir -p /path/to/site/assets/cache/WireWall
chmod 755 /path/to/site/assets/cache/WireWall
```

**AJAX stopped working**
Add the affected path to **Custom Trusted AJAX Paths** in module settings. If that does not help, enable **Disable AJAX Protection Completely** as a last resort.

**Dashboard shows no data**
Enable **Enable Logging** in WireWall settings and wait for traffic to accumulate.

---

## Next steps

- Read [CONFIGURATIONS.md](CONFIGURATIONS.md) for ready-to-use configuration examples
- Check [CHANGELOG.md](CHANGELOG.md) for version history
