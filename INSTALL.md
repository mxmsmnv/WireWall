# WireWall Installation Guide

Complete installation instructions for WireWall security module.

---

## 📋 Prerequisites

### Required
- ProcessWire 3.0.200 or higher
- PHP 7.4+ (8.0+ recommended)
- Write permissions on `/site/modules/` directory
- Write permissions on `/site/assets/cache/` directory

### Optional (for MaxMind)
- Composer (for GeoIP2 library)
- MaxMind account (free)
- ~82MB disk space for all databases

---

## 🚀 Method 1: Standard Installation

### Step 1: Download Module

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

### Step 2: Set Permissions

```bash
chmod 755 WireWall
chmod 644 WireWall/WireWall.module.php
```

### Step 3: Install in ProcessWire

1. Login to ProcessWire admin
2. Navigate to: `Modules → Site`
3. Click "Refresh" to detect new module
4. Find "WireWall" in the list
5. Click "Install"

### Step 4: Initial Configuration

1. Navigate to: `Modules → Configure → WireWall`
2. Enable module: ☑ **Enable WireWall**
3. Set basic options:
   - Rate Limiting: `10 requests / 60 minutes`
   - Block Action: `Beautiful Block Page`
   - Enable Stats Logging: ☑
4. Click "Save"

---

## 🌍 Method 2: Installation with MaxMind (Recommended)

MaxMind provides fast, accurate geolocation without external API calls.

### Step 1: Register for MaxMind (Free)

1. Go to: https://www.maxmind.com/en/geolite2/signup
2. Create free account
3. Verify email
4. Login to account

### Step 2: Download Databases

1. Go to: https://www.maxmind.com/en/accounts/current/geoip/downloads
2. Download these databases:
   - **GeoLite2-Country.mmdb** (~7 MB) - Required
   - **GeoLite2-ASN.mmdb** (~5 MB) - Required
   - **GeoLite2-City.mmdb** (~70 MB) - Optional

### Step 3: Create geoip Directory

```bash
cd /path/to/processwire/site/modules/WireWall/
mkdir geoip
chmod 755 geoip
```

### Step 4: Place Databases

```bash
# Extract downloaded GZ files
gunzip GeoLite2-Country.tar.gz
gunzip GeoLite2-ASN.tar.gz
gunzip GeoLite2-City.tar.gz  # if using

# Extract tar archives
tar -xvf GeoLite2-Country.tar
tar -xvf GeoLite2-ASN.tar
tar -xvf GeoLite2-City.tar  # if using

# Copy .mmdb files to module
cd /path/to/processwire/site/modules/WireWall/geoip/
cp /path/to/downloads/GeoLite2-Country_*/GeoLite2-Country.mmdb .
cp /path/to/downloads/GeoLite2-ASN_*/GeoLite2-ASN.mmdb .
cp /path/to/downloads/GeoLite2-City_*/GeoLite2-City.mmdb .  # if using
```

### Step 5: Install PHP Library

```bash
cd /path/to/processwire/site/modules/WireWall/
composer require geoip2/geoip2
```

If composer not installed:
```bash
# Install composer
curl -sS https://getcomposer.org/installer | php
php composer.phar require geoip2/geoip2
```

### Step 6: Verify Installation

1. Go to: `Admin → Modules → WireWall → Configure`
2. Look for "MaxMind GeoLite2 Status" section
3. Should show:
   ```
   ✅ MaxMind GeoLite2 databases are installed and active
   
   Country Database: GeoLite2-Country.mmdb (6.84 MB) ✅
   ASN Database: GeoLite2-ASN.mmdb (5.21 MB) ✅
   City Database: GeoLite2-City.mmdb (70.5 MB) ✅
   Status: Active - Using MaxMind for all GeoIP lookups
   ```

---

## 🔧 Directory Structure

After installation, your directory should look like:

```
/site/modules/WireWall/
├── WireWall.module.php          (Main module file)
├── README.md                    (Documentation)
├── INSTALL.md                   (This file)
├── CONFIGURATIONS.md            (Configuration examples)
├── geoip/                       (MaxMind databases)
│   ├── GeoLite2-Country.mmdb
│   ├── GeoLite2-ASN.mmdb
│   └── GeoLite2-City.mmdb       (optional)
└── vendor/                      (Composer dependencies)
    └── geoip2/                  (MaxMind library)
```

---

## 📊 Cache Directory

WireWall will automatically create cache directory:

```
/site/assets/cache/WireWall/
├── ratelimit_IP.cache           (Rate limit counters)
├── ban_IP.cache                 (Banned IPs)
├── proxy_IP.cache               (VPN/Proxy detection results)
└── geo_IP.cache                 (GeoIP lookup results)
```

Permissions: `755` (directory), `644` (files)

---

## ✅ Verification Checklist

After installation, verify:

- [ ] Module appears in `Modules → Site`
- [ ] Module can be installed without errors
- [ ] Configuration page loads
- [ ] Cache directory created: `/site/assets/cache/WireWall/`
- [ ] MaxMind status shows (if installed)
- [ ] Test blocking works (temporarily block your IP)
- [ ] Logs appear in `/site/assets/logs/wirewall.txt`

---

## 🧪 Testing Installation

### Test 1: Basic Functionality

1. Enable WireWall
2. Add your IP to blacklist temporarily
3. Open site in incognito/private window
4. Should see block page
5. Remove your IP from blacklist

### Test 2: Rate Limiting

1. Set rate limit: `5 requests / 1 minute`
2. Refresh page 6 times quickly
3. Should see block page on 6th request
4. Wait 1 minute, access restored
5. Reset rate limit to normal

### Test 3: MaxMind (if installed)

1. Check logs: `/site/assets/logs/wirewall.txt`
2. Should see country codes: `ALLOWED | US | ...`
3. If City DB installed, should see: `ALLOWED | US (Philadelphia, Pennsylvania) | ...`

---

## 🔄 Updating

### Update Module Files

```bash
cd /path/to/processwire/site/modules/WireWall/
git pull origin main
```

Or download new version and replace files.

### Update MaxMind Databases (Monthly)

MaxMind updates databases monthly. To update:

```bash
# 1. Download new databases from MaxMind
# 2. Replace old files
cd /path/to/processwire/site/modules/WireWall/geoip/
rm -f *.mmdb
cp /path/to/new/GeoLite2-Country.mmdb .
cp /path/to/new/GeoLite2-ASN.mmdb .
cp /path/to/new/GeoLite2-City.mmdb .  # if using

# 3. Verify in admin
Admin → Modules → WireWall → Configure
# Check "Last Updated" dates
```

---

## 🐛 Troubleshooting

### Problem: Module doesn't appear in Modules list

**Solution:**
```bash
# Check file permissions
chmod 755 /path/to/site/modules/WireWall
chmod 644 /path/to/site/modules/WireWall/WireWall.module.php

# Refresh modules
Admin → Modules → Refresh
```

### Problem: MaxMind shows "Not Installed"

**Solution:**
```bash
# Check databases exist
ls -lh /path/to/site/modules/WireWall/geoip/
# Should show: GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb

# Check composer dependencies
ls -lh /path/to/site/modules/WireWall/vendor/
# Should show: geoip2/

# If missing, install:
cd /path/to/site/modules/WireWall/
composer require geoip2/geoip2
```

### Problem: Cache directory errors

**Solution:**
```bash
# Create cache directory manually
mkdir -p /path/to/site/assets/cache/WireWall
chmod 755 /path/to/site/assets/cache/WireWall

# Check ProcessWire can write
touch /path/to/site/assets/cache/WireWall/test.txt
# If error, fix permissions on parent directory
chmod 755 /path/to/site/assets/cache
```

### Problem: Rate limiting not working

**Solution:**
1. Check cache directory is writable
2. Test with low limit (e.g., 3 req/min)
3. Use incognito/private window (avoid cookie caching)
4. Check logs for rate-limit blocks

### Problem: Country blocking not working

**Solution:**
1. Verify MaxMind installed (or HTTP fallback working)
2. Check country codes are correct (US, AU, GB)
3. Verify blocking mode (blacklist vs whitelist)
4. Check logs show correct country detection

---

## 🔐 Security Recommendations

After installation:

1. **Test thoroughly** - Use incognito mode for testing
2. **Whitelist your IP** - Prevent self-blocking
3. **Monitor logs** - Watch for false positives
4. **Start conservative** - Enable features gradually
5. **Backup configuration** - Export settings regularly

---

## 📚 Next Steps

After installation:

1. Read [CONFIGURATIONS.md](CONFIGURATIONS.md) for configuration examples
2. Configure country blocking (if needed)
3. Set up rate limiting
4. Enable VPN/Proxy detection
5. Test with different scenarios
6. Monitor logs for first 24 hours

---

**Installation complete! 🎉**

Proceed to [CONFIGURATIONS.md](CONFIGURATIONS.md) for configuration examples.
