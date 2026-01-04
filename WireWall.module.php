<?php namespace ProcessWire;

/**
 * WireWall 1.3.2 - Advanced Traffic Firewall
 * 
 * Maximum security firewall with:
 * - MaxMind GeoLite2 support with HTTP fallback
 * - VPN/Proxy/Tor detection (multi-API)
 * - Rate limiting
 * - JS Challenge for suspicious requests
 * - ASN blocking
 * - Datacenter detection
 * - Enhanced fake browser detection
 * - IPv4/IPv6 support with CIDR
 *
 * @version 1.3.2
 * @author Maxim Alex
 * @date January 3, 2026
 * @requires ProcessWire 3.0.200+, PHP 8.1+
 */

class WireWall extends WireData implements Module, ConfigurableModule {

    public static function getModuleInfo() {
        return [
            'title' => 'WireWall',
            'summary' => 'Advanced traffic firewall with VPN/Proxy/Tor detection, rate limiting, and JS challenge',
            'version' => 132,
            'autoload' => true,
            'singular' => true,
            'icon' => 'shield',
            'requires' => 'ProcessWire>=3.0.200,PHP>=8.1',
            'author' => 'Maxim Alex'
        ];
    }

    // Cache for parsed rules (performance optimization)
    protected $parsedCache = [];
    
    // Current request data
    protected $currentAS = null;
    protected $currentCountry = null;
    
    // Allow AJAX from trusted ProcessWire modules (default: enabled)
    protected $allowTrustedModules = true;
    
    // Allowed User-Agents and IPs (whitelist/exceptions)
    protected $allowedUserAgents = '';
    protected $allowedIPs = '';
    protected $allowedASNs = '';
    
    // MaxMind GeoIP readers
    protected $geoipReader = null;
    protected $geoipAsnReader = null;
    protected $geoipCityReader = null;

    /**
     * Get WireWall data directory path (persistent across updates)
     * 
     * Data stored in /site/assets/ to prevent deletion during updates
     * This directory is NOT deleted when module is updated via git or admin
     */
    protected function getDataPath() {
        return $this->wire('config')->paths->assets . 'WireWall/';
    }
    
    /**
     * Get GeoIP directory path (persistent across updates)
     */
    protected function getGeoIPPath() {
        return $this->getDataPath() . 'geoip/';
    }
    
    /**
     * Get vendor directory path (persistent across updates)
     */
    protected function getVendorPath() {
        return $this->getDataPath() . 'vendor/';
    }
    
    /**
     * Get composer autoload path (persistent across updates)
     */
    protected function getComposerAutoloadPath() {
        return $this->getVendorPath() . 'autoload.php';
    }

    /**
     * Get cache file path for a key
     */
    protected function getCachePath($key) {
        $cachePath = $this->wire('config')->paths->cache . 'WireWall/';
        if (!is_dir($cachePath)) {
            @mkdir($cachePath, 0755, true);
        }
        // Sanitize key for filename
        $safeKey = preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $key);
        return $cachePath . $safeKey . '.cache';
    }
    
    /**
     * Save to file cache
     */
    protected function cacheSet($key, $value, $expire) {
        $filepath = $this->getCachePath($key);
        $data = [
            'value' => $value,
            'expire' => time() + $expire
        ];
        return @file_put_contents($filepath, serialize($data), LOCK_EX) !== false;
    }
    
    /**
     * Get from file cache
     */
    protected function cacheGet($key) {
        $filepath = $this->getCachePath($key);
        if (!file_exists($filepath)) {
            return null;
        }
        
        $content = @file_get_contents($filepath);
        if ($content === false) {
            return null;
        }
        
        $data = @unserialize($content);
        if (!$data || !isset($data['expire'])) {
            return null;
        }
        
        // Check if expired
        if ($data['expire'] < time()) {
            @unlink($filepath);
            return null;
        }
        
        return $data['value'];
    }

    /**
     * Initialize module - early hook for maximum performance
     */
    public function init() {
        // Load module settings explicitly (fixes ProcessWire not loading new fields)
        $data = $this->wire('modules')->getModuleConfigData($this);
        
        // Normalize checkbox values: convert empty strings to 0, keep 1 as is
        // This supports old configs with "" and new configs with 0/1
        $checkboxFields = [
            'enabled', 'allowTrustedModules', 'city_blocking_enabled', 
            'subdivision_blocking_enabled', 'block_proxy_vpn_tor', 
            'block_datacenters', 'js_challenge_enabled', 'rate_limit_enabled',
            'block_bad_bots', 'block_search_bots', 'block_ai_bots', 
            'block_other_bots', 'enable_stats_logging'
        ];
        
        foreach ($checkboxFields as $field) {
            if (isset($data[$field])) {
                // Convert: "" → 0, "1" → 1, 1 → 1, anything else → 0
                $this->$field = ($data[$field] == 1 || $data[$field] === '1') ? 1 : 0;
            }
        }
        
        if (isset($data['allowedASNs'])) {
            $this->allowedASNs = $data['allowedASNs'];
        }
        if (isset($data['allowedUserAgents'])) {
            $this->allowedUserAgents = $data['allowedUserAgents'];
        }
        if (isset($data['allowedIPs'])) {
            $this->allowedIPs = $data['allowedIPs'];
        }
        if (isset($data['allowTrustedModules'])) {
            $this->allowTrustedModules = $data['allowTrustedModules'];
        }
        
        // Create cache directory if it doesn't exist
        $cachePath = $this->wire('config')->paths->cache . 'WireWall/';
        if (!is_dir($cachePath)) {
            if (!@mkdir($cachePath, 0755, true)) {
                $this->wire('log')->save('wirewall', "Failed to create cache directory: {$cachePath}");
            }
        }
        
        // Hook to normalize config before saving
        $this->addHookBefore('Modules::saveModuleConfigData', $this, 'normalizeConfigBeforeSave');
        
        // Early hook BEFORE page rendering for speed
        $this->addHookBefore('ProcessPageView::execute', $this, 'checkAccess');
        
        // Initialize MaxMind GeoIP readers if available
        $this->initializeGeoIP();
    }
    
    /**
     * Normalize config data before saving
     * Converts empty strings to 0 for checkbox fields
     * Adds version number to config
     */
    protected function normalizeConfigBeforeSave(HookEvent $event) {
        // Only process WireWall module
        $module = $event->arguments(0);
        if ($module !== $this && $module !== 'WireWall') return;
        
        $data = $event->arguments(1);
        
        // Normalize all checkbox fields: "" → 0, "1" → 1, 1 → 1
        $checkboxFields = [
            'enabled', 'allowTrustedModules', 'city_blocking_enabled', 
            'subdivision_blocking_enabled', 'block_proxy_vpn_tor', 
            'block_datacenters', 'js_challenge_enabled', 'rate_limit_enabled',
            'block_bad_bots', 'block_search_bots', 'block_ai_bots', 
            'block_other_bots', 'enable_stats_logging'
        ];
        
        foreach ($checkboxFields as $field) {
            if (isset($data[$field])) {
                // Convert to integer: 0 or 1
                $data[$field] = ($data[$field] == 1 || $data[$field] === '1') ? 1 : 0;
            }
        }
        
        // Add version number to config
        $moduleInfo = self::getModuleInfo();
        $data['version'] = $moduleInfo['version'];
        
        // Update event arguments
        $event->arguments(1, $data);
    }

    /**
     * Initialize MaxMind GeoIP readers
     * 
     * Uses /site/assets/WireWall/ instead of module directory
     * This prevents data loss during module updates
     * 
     * To setup MaxMind:
     * 1. Register on maxmind.com
     * 2. Download GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb
     * 3. Place in /site/assets/WireWall/geoip/
     * 4. Run: composer require geoip2/geoip2:^2.0 (in /site/assets/WireWall/)
     */
    protected function initializeGeoIP() {
        $geoipDir = $this->getGeoIPPath();
        $autoload = $this->getComposerAutoloadPath();
        
        // Check if composer autoload exists
        if (!file_exists($autoload)) {
            return; // MaxMind not installed - fallback to HTTP APIs
        }
        
        require_once $autoload;
        
        // Load Country database
        $countryDb = $geoipDir . 'GeoLite2-Country.mmdb';
        if (file_exists($countryDb)) {
            try {
                $this->geoipReader = new \GeoIp2\Database\Reader($countryDb);
            } catch (\Exception $e) {
                // Silent fail - will use HTTP fallback
            }
        }
        
        // Load ASN database
        $asnDb = $geoipDir . 'GeoLite2-ASN.mmdb';
        if (file_exists($asnDb)) {
            try {
                $this->geoipAsnReader = new \GeoIp2\Database\Reader($asnDb);
            } catch (\Exception $e) {
                // Silent fail - ASN detection will be limited
            }
        }
        
        // Load City database (optional - for detailed logging)
        $cityDb = $geoipDir . 'GeoLite2-City.mmdb';
        if (file_exists($cityDb)) {
            try {
                $this->geoipCityReader = new \GeoIp2\Database\Reader($cityDb);
            } catch (\Exception $e) {
                // Silent fail - will only log country
            }
        }
    }

    /**
     * Main access check - fires before page execution
     */
    public function checkAccess(HookEvent $event) {
        // === ABSOLUTE PRIORITY 0: NEVER BLOCK ADMIN AREA ===
        // Get actual admin path from config
        $config = $this->wire('config');
        $adminPath = $config->urls->admin;
        
        // Normalize admin path (ensure leading slash)
        if (substr($adminPath, 0, 1) !== '/') {
            $adminPath = '/' . $adminPath;
        }
        
        // Check URL FIRST before any other checks
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Admin check: starts with admin path OR is admin template
        if (strpos($requestUri, $adminPath) === 0 ||
            strpos($requestUri, '/wire/') === 0) {
            return; // ALWAYS allow admin access - NO LOGGING
        }
        
        // Check page template - multiple checks for bulletproof protection
        $page = $this->wire('page');
        if ($page) {
            // Check if page template is admin
            if ($page->template && $page->template == 'admin') {
                return; // ALWAYS allow admin pages - NO LOGGING
            }
            // Check if page rootParent is admin (for any page under admin tree)
            if ($page->rootParent && $page->rootParent->template == 'admin') {
                return; // ALWAYS allow admin area pages - NO LOGGING
            }
        }
        
        // Skip if module not enabled
        if (!$this->enabled) return;
        
        // Skip for CLI
        if ($config->cli) return;
        
        // === PRIORITY 0.5: ALLOW TRUSTED PROCESSWIRE MODULE AJAX REQUESTS ===
        // Check before any other security checks
        if ($this->allowTrustedModules && $this->isAllowedModuleRequest()) {
            return; // Allow trusted module AJAX - no logging, no blocking
        }
        
        $ip = $this->getRealClientIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $path = $page ? $page->url : parse_url($requestUri, PHP_URL_PATH);
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        
        // === PRIORITY 1: IP WHITELIST (ALWAYS ALLOW) ===
        if ($this->isIPWhitelisted($ip)) {
            $this->logAccess($ip, null, null, true, '', $userAgent);
            return;
        }
        
        // Get GeoIP data early (country + ASN) for whitelist checks
        $geoData = $this->getGeoData($ip);
        $country = $geoData['country'] ?? null;
        $asn = $geoData['asn'] ?? null;
        $this->currentAS = $asn;
        $this->currentCountry = $country;
        
        // === PRIORITY 1.5: ALLOWED BOTS/IPs/ASNs (EXCEPTIONS) ===
        // Allow legitimate bots (Google, Bing, Yandex, etc.)
        if ($this->isAllowedBot($userAgent, $ip, $asn)) {
            $this->logAccess($ip, $country, $asn, true, 'allowed-bot', $userAgent);
            return;
        }
        
        // === PRIORITY 2: RATE LIMITING ===
        if ($this->rate_limit_enabled && $this->isRateLimited($ip)) {
            $this->blockAccess('rate-limit', $ip, null, null, $userAgent);
            return;
        }
        
        // === PRIORITY 3: IP BLACKLIST (ALWAYS BLOCK) ===
        if ($this->isIPBlacklisted($ip)) {
            $this->blockAccess('ip', $ip, null, null, $userAgent);
            return;
        }
        
        // === PRIORITY 4: JS CHALLENGE CHECK ===
        if ($this->js_challenge_enabled) {
            // Check if suspicious AND no valid cookie
            if ($this->isSuspiciousRequest($userAgent) && !$this->verifyChallengeCookie()) {
                $this->showJSChallenge($ip, $userAgent);
                return;
            }
        }
        
        // === PRIORITY 5: VPN/PROXY/TOR DETECTION ===
        if ($this->block_proxy_vpn_tor && $this->isProxyVPNTor($ip)) {
            $this->blockAccess('proxy-vpn-tor', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 6: DATACENTER DETECTION ===
        if ($this->block_datacenters && $this->isDatacenter($ip, $asn)) {
            $this->blockAccess('datacenter', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 7: ASN BLOCKING ===
        if ($asn && $this->isBlockedASN($asn)) {
            $this->blockAccess('asn-blocked', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 8: GLOBAL RULES (bots, paths, UA, referer) ===
        if ($this->checkGlobalRules($ip, $userAgent, $path, $referer)) {
            $this->blockAccess('global', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 9: COUNTRY BLOCKING (blacklist/whitelist) ===
        if ($country && $this->checkCountryBlocking($country)) {
            $this->blockAccess('country', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 9.5: CITY BLOCKING (blacklist/whitelist) ===
        if ($this->city_blocking_enabled && $this->geoipCityReader) {
            $cityData = $this->getCityData($ip);
            if ($cityData && $this->checkCityBlocking($cityData)) {
                $this->blockAccess('city-blocked', $ip, $country, $asn, $userAgent);
                return;
            }
        }
        
        // === PRIORITY 9.6: SUBDIVISION/REGION BLOCKING (blacklist/whitelist) ===
        if ($this->subdivision_blocking_enabled && $this->geoipCityReader) {
            $cityData = $this->getCityData($ip);
            if ($cityData && $this->checkSubdivisionBlocking($cityData)) {
                $this->blockAccess('subdivision-blocked', $ip, $country, $asn, $userAgent);
                return;
            }
        }
        
        // === PRIORITY 10: COUNTRY-SPECIFIC RULES ===
        if ($country && $this->checkCountryRules($country, $userAgent, $path, $referer)) {
            $this->blockAccess('country-rule', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === ACCESS ALLOWED ===
        if ($this->enable_stats_logging) {
            $this->logAccess($ip, $country, $asn, true, '', $userAgent);
        }
    }

    /**
     * Check if request is rate limited
     */
    protected function isRateLimited($ip) {
        $cacheKey = "ratelimit_{$ip}";
        $banKey = "ban_{$ip}";
        
        // Check if IP is currently banned
        if ($this->cacheGet($banKey)) {
            return true;
        }
        
        // Get current request count (60 seconds window)
        $count = (int)$this->cacheGet($cacheKey);
        $count++;
        
        // Save incremented count with 60 second expiration
        $this->cacheSet($cacheKey, $count, 60);
        
        // Check if exceeded limit
        if ($count > $this->rate_limit_requests) {
            // Ban for specified minutes
            $banTime = $this->rate_limit_minutes * 60;
            $this->cacheSet($banKey, true, $banTime);
            return true;
        }
        
        return false;
    }

    /**
     * Check if request is suspicious (triggers JS challenge)
     */
    protected function isSuspiciousRequest($userAgent) {
        // Headless browser detection
        $headlessPatterns = [
            'headlesschrome', 'headless', 'puppeteer', 'playwright',
            'selenium', 'webdriver', 'phantomjs', 'chrome-lighthouse'
        ];
        
        foreach ($headlessPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                return true;
            }
        }
        
        // Empty or very short UA
        if (empty($userAgent) || strlen($userAgent) < 10) {
            return true;
        }
        
        // Too long UA (likely spoofed)
        if (strlen($userAgent) > 500) {
            return true;
        }
        
        return false;
    }

    /**
     * Verify JS challenge cookie
     */
    protected function verifyChallengeCookie() {
        if (!isset($_COOKIE['ww_challenge'])) {
            return false;
        }
        
        $cookie = $_COOKIE['ww_challenge'];
        $parts = explode(':', $cookie);
        
        if (count($parts) !== 2) {
            return false;
        }
        
        list($token, $timestamp) = $parts;
        
        // Check if token expired (1 hour validity)
        if (time() - $timestamp > 3600) {
            return false;
        }
        
        // Verify token matches expected hash
        $expected = md5($timestamp . $this->wire('config')->userAuthSalt);
        return hash_equals($expected, $token);
    }

    /**
     * Show JS Challenge page
     */
    protected function showJSChallenge($ip, $userAgent = '') {
        if ($this->enable_stats_logging) {
            $this->logAccess($ip, null, null, false, 'js-challenge', $userAgent);
        }
        
        http_response_code(403);
        
        $timestamp = time();
        $token = md5($timestamp . $this->wire('config')->userAuthSalt);
        $domain = $this->wire('config')->httpHost;
        
        echo "<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>Security Check - WireWall</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #000000;
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .wave-pattern {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.03;
            pointer-events: none;
        }
        
        .wave-line {
            position: absolute;
            left: 0;
            right: 0;
            height: 2px;
            background: white;
            transform-origin: center;
        }
        
        .wave-line:nth-child(1) { top: 10%; transform: scaleX(0.8); }
        .wave-line:nth-child(2) { top: 15%; transform: scaleX(0.85); }
        .wave-line:nth-child(3) { top: 20%; transform: scaleX(0.9); }
        .wave-line:nth-child(4) { top: 25%; transform: scaleX(0.95); }
        .wave-line:nth-child(5) { top: 30%; transform: scaleX(1); }
        .wave-line:nth-child(6) { top: 35%; transform: scaleX(0.95); }
        .wave-line:nth-child(7) { top: 40%; transform: scaleX(0.9); }
        .wave-line:nth-child(8) { top: 45%; transform: scaleX(0.85); }
        .wave-line:nth-child(9) { top: 50%; transform: scaleX(0.8); }
        .wave-line:nth-child(10) { top: 55%; transform: scaleX(0.85); }
        .wave-line:nth-child(11) { top: 60%; transform: scaleX(0.9); }
        .wave-line:nth-child(12) { top: 65%; transform: scaleX(0.95); }
        .wave-line:nth-child(13) { top: 70%; transform: scaleX(1); }
        .wave-line:nth-child(14) { top: 75%; transform: scaleX(0.95); }
        .wave-line:nth-child(15) { top: 80%; transform: scaleX(0.9); }
        
        .container {
            position: relative;
            max-width: 500px;
            width: 100%;
            z-index: 10;
            text-align: center;
        }
        
        .accent-line {
            width: 60px;
            height: 4px;
            background: #DC2626;
            margin: 0 auto 40px;
        }
        
        .spinner-container {
            margin: 0 auto 40px;
            position: relative;
            width: 80px;
            height: 80px;
        }
        
        .spinner {
            position: absolute;
            width: 100%;
            height: 100%;
            border: 3px solid rgba(255, 255, 255, 0.1);
            border-top: 3px solid #DC2626;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        h1 {
            font-size: 36px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 16px;
            letter-spacing: -0.02em;
        }
        
        .subtitle {
            font-size: 16px;
            color: rgba(255, 255, 255, 0.6);
            line-height: 1.6;
            margin-bottom: 32px;
        }
        
        .status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 24px;
            background: rgba(220, 38, 38, 0.1);
            border: 1px solid rgba(220, 38, 38, 0.2);
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            color: rgba(255, 255, 255, 0.8);
            letter-spacing: 0.05em;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            background: #DC2626;
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }
        
        .footer {
            margin-top: 48px;
            padding-top: 32px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .footer-logo {
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: rgba(255, 255, 255, 0.3);
            margin-bottom: 6px;
        }
        
        .footer-text {
            font-size: 11px;
            color: rgba(255, 255, 255, 0.25);
            letter-spacing: 0.05em;
        }
        
        @media (max-width: 600px) {
            h1 {
                font-size: 28px;
            }
            
            .container {
                padding: 0 20px;
            }
        }
    </style>
</head>
<body>
    <div class='wave-pattern'>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
    </div>

    <div class='container'>
        <div class='accent-line'></div>
        
        <div class='spinner-container'>
            <div class='spinner'></div>
        </div>
        
        <h1>Security Check</h1>
        
        <p class='subtitle'>
            Verifying your browser security credentials.<br>
            This process will complete momentarily.
        </p>
        
        <div class='status'>
            <span class='status-dot'></span>
            VERIFICATION IN PROGRESS
        </div>
        
        <div class='footer'>
            <div class='footer-logo'>WIREWALL</div>
            <div class='footer-text'>SECURE ACCESS CONTROL SYSTEM</div>
        </div>
    </div>
    
    <script>
        // Set challenge cookie
        var token = '$token';
        var timestamp = '$timestamp';
        var cookieValue = token + ':' + timestamp;
        var expiryDate = new Date();
        expiryDate.setTime(expiryDate.getTime() + (3600 * 1000)); // 1 hour
        
        document.cookie = 'ww_challenge=' + cookieValue + 
                         '; expires=' + expiryDate.toUTCString() +
                         '; path=/' +
                         '; domain=$domain' +
                         '; SameSite=Lax';
        
        // Redirect after 2 seconds
        setTimeout(function() {
            window.location.reload();
        }, 2000);
    </script>
</body>
</html>";
        exit;
    }

    /**
     * Check VPN/Proxy/Tor (multi-API fallback)
     */
    protected function isProxyVPNTor($ip) {
        $cacheKey = "proxy_{$ip}";
        
        // Check cache first (7 days)
        $cached = $this->cacheGet($cacheKey);
        if ($cached !== null) {
            return $cached === 'blocked';
        }
        
        $http = new WireHttp();
        $http->setTimeout(2);
        $isProxy = false;
        
        // API 1: ip-api.com (free, no key needed)
        if (!$isProxy) {
            try {
                $response = $http->get("http://ip-api.com/json/{$ip}?fields=proxy,hosting");
                if ($response) {
                    $data = json_decode($response, true);
                    if (!empty($data['proxy']) || !empty($data['hosting'])) {
                        $isProxy = true;
                    }
                }
            } catch (\Exception $e) {
                // Continue to next API
            }
        }
        
        // API 2: ipinfo.io (fallback)
        if (!$isProxy) {
            try {
                $response = $http->get("https://ipinfo.io/{$ip}/json");
                if ($response) {
                    $data = json_decode($response, true);
                    // Check company/org for hosting keywords
                    if (isset($data['org'])) {
                        $org = strtolower($data['org']);
                        if (strpos($org, 'hosting') !== false ||
                            strpos($org, 'vpn') !== false ||
                            strpos($org, 'proxy') !== false ||
                            strpos($org, 'datacenter') !== false) {
                            $isProxy = true;
                        }
                    }
                }
            } catch (\Exception $e) {
                // Continue
            }
        }
        
        // API 3: ipapi.co (fallback)
        if (!$isProxy) {
            try {
                $response = $http->get("https://ipapi.co/{$ip}/json/");
                if ($response) {
                    $data = json_decode($response, true);
                    // Check org for hosting/vpn keywords
                    if (isset($data['org'])) {
                        $org = strtolower($data['org']);
                        if (strpos($org, 'hosting') !== false ||
                            strpos($org, 'vpn') !== false ||
                            strpos($org, 'cloud') !== false) {
                            $isProxy = true;
                        }
                    }
                }
            } catch (\Exception $e) {
                // Continue
            }
        }
        
        // Cache result for 7 days
        $this->cacheSet($cacheKey, $isProxy ? 'blocked' : 'allowed', 604800);
        
        return $isProxy;
    }

    /**
     * Check if IP is from datacenter
     */
    protected function isDatacenter($ip, $asn) {
        if (!$asn) return false;
        
        // Known datacenter ASN keywords
        $datacenterKeywords = [
            'amazon', 'aws', 'google', 'cloud', 'azure', 'microsoft',
            'digitalocean', 'ovh', 'hetzner', 'linode', 'vultr',
            'choopa', 'hosting', 'datacenter', 'data center',
            'cloudflare', 'akamai', 'fastly', 'cdn', 'server',
            'colocation', 'colo'
        ];
        
        $asnLower = strtolower($asn);
        
        foreach ($datacenterKeywords as $keyword) {
            if (strpos($asnLower, $keyword) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if ASN is in blocked list
     */
    protected function isBlockedASN($asn) {
        if (!$this->block_asns) return false;
        
        $blockedASNs = $this->parseRules($this->block_asns);
        if (empty($blockedASNs)) return false;
        
        // Extract ASN number only (e.g., "AS16509 Amazon" -> "16509")
        preg_match('/AS(\d+)/', $asn, $matches);
        $asnNumber = $matches[1] ?? '';
        
        foreach ($blockedASNs as $blocked) {
            $blocked = trim($blocked);
            
            // Match by ASN number
            if ($asnNumber && stripos($blocked, $asnNumber) !== false) {
                return true;
            }
            
            // Match by organization name
            if (stripos($asn, $blocked) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Get geo data (country + ASN) with MaxMind priority, HTTP fallback
     */
    protected function getGeoData($ip) {
        $cacheKey = "geo_{$ip}";
        
        // Check cache first (30 days)
        $cached = $this->cacheGet($cacheKey);
        if ($cached) {
            return $cached;
        }
        
        $data = ['country' => null, 'asn' => null];
        
        // === TRY MAXMIND FIRST (FASTEST) ===
        if ($this->geoipReader) {
            try {
                $record = $this->geoipReader->country($ip);
                $data['country'] = $record->country->isoCode;
            } catch (\Exception $e) {
                // IP not found or error, fall through
            }
        }
        
        if ($this->geoipAsnReader) {
            try {
                $record = $this->geoipAsnReader->asn($ip);
                $data['asn'] = 'AS' . $record->autonomousSystemNumber . ' ' . 
                              ($record->autonomousSystemOrganization ?? '');
            } catch (\Exception $e) {
                // IP not found or error, fall through
            }
        }
        
        // === FALLBACK TO HTTP API IF NEEDED ===
        if (!$data['country'] || !$data['asn']) {
            $http = new WireHttp();
            $http->setTimeout(2);
            
            try {
                $response = $http->get("http://ip-api.com/json/{$ip}?fields=countryCode,as");
                
                if ($response) {
                    $apiData = json_decode($response, true);
                    
                    if (!$data['country'] && !empty($apiData['countryCode'])) {
                        $data['country'] = $apiData['countryCode'];
                    }
                    
                    if (!$data['asn'] && !empty($apiData['as'])) {
                        $data['asn'] = $apiData['as'];
                    }
                }
            } catch (\Exception $e) {
                $this->wire('log')->save('wirewall', "WireWall: Error fetching geo data for {$ip}: " . $e->getMessage());
            }
        }
        
        // Cache for 30 days
        $this->cacheSet($cacheKey, $data, 2592000);
        
        return $data;
    }

    /**
     * Get city data from MaxMind GeoLite2-City (optional, for detailed logging)
     */
    protected function getCityData($ip) {
        // Only works if City database is loaded
        if (!$this->geoipCityReader) {
            return null;
        }
        
        try {
            $record = $this->geoipCityReader->city($ip);
            
            // Get region name with multiple fallbacks
            $regionName = null;
            
            // Try subdivisions first (subdivisions is an array-like object)
            if (!empty($record->subdivisions) && count($record->subdivisions) > 0) {
                $subdivision = $record->subdivisions[0]; // First subdivision (most specific)
                // Priority: name > isoCode
                $regionName = $subdivision->name ?? $subdivision->isoCode ?? null;
            }
            
            $cityData = [
                'city' => $record->city->name ?? null,
                'region' => $regionName,
                'region_code' => !empty($record->subdivisions) && isset($record->subdivisions[0]) ? 
                                ($record->subdivisions[0]->isoCode ?? null) : null,
                'country' => $record->country->isoCode ?? null,
                'latitude' => $record->location->latitude ?? null,
                'longitude' => $record->location->longitude ?? null,
                'timezone' => $record->location->timeZone ?? null
            ];
            
            return $cityData;
            
        } catch (\Exception $e) {
            // IP not found or error - log it
            if ($this->enable_stats_logging) {
                $this->wire('log')->save('wirewall', "getCityData error for {$ip}: " . $e->getMessage());
            }
            return null;
        }
    }

    /**
     * Enhanced fake browser detection
     */
    protected function detectFakeBrowser($userAgent) {
        // Empty or too short/long User-Agent
        if (empty($userAgent) || strlen($userAgent) < 10 || strlen($userAgent) > 500) {
            return true;
        }
        
        // Headless browser patterns
        $headlessPatterns = [
            'headlesschrome', 'headless', 'puppeteer', 'playwright',
            'selenium', 'webdriver', 'phantomjs', 'chrome-lighthouse'
        ];
        
        foreach ($headlessPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                return true;
            }
        }
        
        // Check if looks like a browser
        $looksLikeBrowser = (
            stripos($userAgent, 'Mozilla') !== false ||
            stripos($userAgent, 'Chrome') !== false ||
            stripos($userAgent, 'Safari') !== false ||
            stripos($userAgent, 'Firefox') !== false ||
            stripos($userAgent, 'Edge') !== false
        );
        
        if ($looksLikeBrowser) {
            // Real browsers ALWAYS send these headers
            $hasAcceptLanguage = !empty($_SERVER['HTTP_ACCEPT_LANGUAGE']);
            $hasAcceptEncoding = !empty($_SERVER['HTTP_ACCEPT_ENCODING']);
            $hasAccept = !empty($_SERVER['HTTP_ACCEPT']);
            
            // Missing critical browser headers = FAKE
            if (!$hasAcceptLanguage || !$hasAcceptEncoding || !$hasAccept) {
                return true;
            }
            
            // Suspicious Accept header (wget/curl send only */*)
            if ($hasAccept && $_SERVER['HTTP_ACCEPT'] === '*/*') {
                return true;
            }
            
            // Check Chrome version for outdated/automation detection
            if (preg_match('/Chrome\/(\d+)\.(\d+)/', $userAgent, $matches)) {
                $chromeVersion = (int)$matches[1];
                $chromeMinor = (int)$matches[2];
                
                // Chrome 90+ should have Sec-CH-UA header
                if ($chromeVersion >= 90 && empty($_SERVER['HTTP_SEC_CH_UA'])) {
                    return true; // Likely automation/fake
                }
                
                // Detect very outdated Chrome (older than 100 = likely automation)
                // Current Chrome is 130+ (2025), anything below 100 is 3+ years old
                if ($chromeVersion < 100) {
                    // Could be automation masking as old Chrome
                    // Check if has modern headers - if yes, it's fake
                    if (!empty($_SERVER['HTTP_SEC_FETCH_SITE']) || 
                        !empty($_SERVER['HTTP_SEC_FETCH_MODE']) ||
                        !empty($_SERVER['HTTP_SEC_CH_UA'])) {
                        return true; // Old UA + modern headers = fake
                    }
                }
                
                // Additional check: Very old Chrome version + perfect headers = suspicious
                if ($chromeVersion < 95) {
                    // Chrome 91-94 is from 2021, likely Puppeteer/Selenium default
                    // Real users don't run browsers 4+ years old
                    if ($hasAcceptLanguage && $hasAcceptEncoding && $hasAccept) {
                        // Too perfect for an old browser, likely automation
                        return true;
                    }
                }
            }
            
            // Check for missing Sec-Fetch headers (modern browsers send them)
            $hasSecFetchSite = !empty($_SERVER['HTTP_SEC_FETCH_SITE']);
            $hasSecFetchMode = !empty($_SERVER['HTTP_SEC_FETCH_MODE']);
            
            // Modern Chrome should send Sec-Fetch headers
            // NOTE: Firefox doesn't always send Sec-Fetch, so check only for Chrome
            if (preg_match('/Chrome\/(\d+)/', $userAgent, $matches)) {
                // Skip check if also contains Firefox/Edge (they may contain Chrome/ in UA)
                $isRealChrome = !preg_match('/Firefox|Edg/', $userAgent);
                
                if ($isRealChrome && (int)$matches[1] >= 76 && (!$hasSecFetchSite || !$hasSecFetchMode)) {
                    // Chrome 76+ without Sec-Fetch = likely headless
                    return true;
                }
            }
        }
        
        // Detect command line tools
        $cliTools = [
            'libwww-perl', 'python-urllib', 'java/', 'go-http-client',
            'okhttp', 'apache-httpclient', 'httpclient', 'http_request',
            'node-fetch', 'axios'
        ];
        
        foreach ($cliTools as $tool) {
            if (stripos($userAgent, $tool) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check global rules with categorized bots
     */
    protected function checkGlobalRules($ip, $userAgent, $path, $referer) {
        // 1. Block bad bots (scrapers, scanners)
        if ($this->block_bad_bots) {
            $badBots = $this->getBadBotPatterns();
            foreach ($badBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 2. Block search engine bots
        if ($this->block_search_bots) {
            $searchBots = $this->getSearchBotPatterns();
            foreach ($searchBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 3. Block AI bots
        if ($this->block_ai_bots) {
            $aiBots = $this->getAIBotPatterns();
            foreach ($aiBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 4. Block other bots (custom list)
        if ($this->block_other_bots && $this->other_bots_list) {
            $otherBots = $this->parseRules($this->other_bots_list);
            foreach ($otherBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 5. Detect fake browser
        if ($this->detectFakeBrowser($userAgent)) {
            return true;
        }
        
        // 6. Block specific paths
        if ($this->blocked_paths) {
            $blockedPaths = $this->parseRules($this->blocked_paths);
            foreach ($blockedPaths as $blockedPath) {
                if ($this->matchPattern($path, $blockedPath)) {
                    return true;
                }
            }
        }
        
        // 7. Block by user agent pattern
        if ($this->blocked_user_agents) {
            $blockedAgents = $this->parseRules($this->blocked_user_agents);
            foreach ($blockedAgents as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 8. Block by referer
        if ($this->blocked_referers) {
            $blockedReferers = $this->parseRules($this->blocked_referers);
            foreach ($blockedReferers as $pattern) {
                if (stripos($referer, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Get bad bot patterns (scrapers, scanners, malicious)
     */
    protected function getBadBotPatterns() {
        return [
            'scrapy', 'curl', 'wget', 'python-requests',
            'masscan', 'nmap', 'nikto', 'sqlmap',
            'dirbuster', 'acunetix', 'netsparker',
            'semrush', 'ahrefs', 'mj12bot', 'dotbot',
            'petalbot', 'aspiegelbot', 'mail.ru',
            'zgrab', 'go-http-client', 'jorgee',
            'nessus', 'openvas', 'metasploit'
        ];
    }

    /**
     * Get search bot patterns
     */
    protected function getSearchBotPatterns() {
        return [
            'googlebot', 'bingbot', 'yandex', 'baiduspider',
            'duckduckbot', 'slurp', 'teoma', 'ia_archiver',
            'msnbot', 'exabot', 'facebookexternalhit',
            'twitterbot', 'linkedinbot', 'applebot'
        ];
    }

    /**
     * Get AI bot patterns
     */
    protected function getAIBotPatterns() {
        return [
            'gptbot', 'chatgpt', 'claudebot', 'claude-web',
            'anthropic-ai', 'google-extended', 'grokbot',
            'cohere-ai', 'perplexitybot', 'you-ai',
            'bytespider', 'meta-externalagent'
        ];
    }

    /**
     * Check if request is from a trusted ProcessWire module or API endpoint
     * Returns true if this is an allowed module request that should bypass WireWall
     * 
     * Supports:
     * - Core ProcessWire modules (POST AJAX)
     * - RockFrontend AJAX endpoints (/ajax/)
     * - API endpoints (/api/, /api2/, etc.) - ALL HTTP methods
     * - Custom trusted paths (configurable)
     */
    protected function isAllowedModuleRequest() {
        $input = $this->wire('input');
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        
        // === API ENDPOINTS CHECK (all HTTP methods) ===
        // API endpoints don't require POST or AJAX headers
        $apiPaths = [
            '/api/',    // AppApi and custom APIs
            '/api2/',   // AppApi v2
            '/rest/',   // REST API
        ];
        
        // Add custom API paths from module config
        $customApiPaths = $this->get('custom_api_paths');
        if (!empty($customApiPaths)) {
            $customApiPathsList = array_filter(array_map('trim', explode("\n", $customApiPaths)));
            $apiPaths = array_merge($apiPaths, $customApiPathsList);
        }
        
        // Check if request is to an API endpoint
        foreach ($apiPaths as $apiPath) {
            if (stripos($requestUri, $apiPath) !== false) {
                return true; // Allow all HTTP methods to API endpoints
            }
        }
        
        // === AJAX REQUESTS CHECK (POST only) ===
        // Only check POST AJAX requests for modules
        if (!$input->requestMethod('POST')) {
            return false;
        }
        
        // Check for AJAX header
        $isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) 
            && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
        
        if (!$isAjax) {
            return false;
        }
        
        // List of trusted ProcessWire module patterns
        $trustedPatterns = [
            'bookmarks',       // FieldtypeBookmarks
            'ProcessWire',     // Core ProcessWire modules
            'InputfieldPage',  // Page autocomplete
            'Inputfield',      // Other inputfields
            'process',         // Process modules
            'field',           // Field-related requests
            'page',            // Page-related AJAX
        ];
        
        // Check POST parameters for trusted patterns
        foreach ($input->post as $key => $value) {
            foreach ($trustedPatterns as $pattern) {
                // Case-insensitive check if key starts with pattern
                if (stripos($key, $pattern) === 0) {
                    return true;
                }
            }
        }
        
        // Default trusted AJAX paths
        $trustedPaths = [
            '/processwire/',  // Admin area
            '/admin/',        // Custom admin path
            '/ajax/',         // RockFrontend and custom AJAX endpoints
        ];
        
        // Add custom trusted paths from module config
        $customPaths = $this->get('custom_trusted_paths');
        if (!empty($customPaths)) {
            $customPathsList = array_filter(array_map('trim', explode("\n", $customPaths)));
            $trustedPaths = array_merge($trustedPaths, $customPathsList);
        }
        
        // Check URL against all trusted AJAX paths
        foreach ($trustedPaths as $trustedPath) {
            if (stripos($requestUri, $trustedPath) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if request is from an allowed bot or IP (whitelist/exceptions)
     * Returns true if this request should bypass WireWall completely
     */
    protected function isAllowedBot($userAgent, $ip, $asn = null) {
        // Check allowed User-Agents
        if ($this->allowedUserAgents) {
            $allowedAgents = $this->parseRules($this->allowedUserAgents);
            foreach ($allowedAgents as $pattern) {
                $pattern = trim($pattern);
                if (empty($pattern)) continue;
                
                // Case-insensitive match
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // Check allowed IPs (supports CIDR)
        if ($this->allowedIPs) {
            $allowedIPs = $this->parseRules($this->allowedIPs);
            foreach ($allowedIPs as $allowedIP) {
                $allowedIP = trim($allowedIP);
                if (empty($allowedIP)) continue;
                
                // Check if IP matches (exact or CIDR)
                if ($this->matchIP($ip, $allowedIP)) {
                    return true;
                }
            }
        }
        
        // Check allowed ASNs (Autonomous System Numbers)
        if ($this->allowedASNs && $asn) {
            $allowedASNs = $this->parseRules($this->allowedASNs);
            
            foreach ($allowedASNs as $allowedASN) {
                $allowedASN = trim($allowedASN);
                if (empty($allowedASN)) continue;
                
                // Extract ASN number from both strings
                // Supports: "AS15169 Google", "15169", "AS15169"
                preg_match('/(?:AS)?(\d+)/i', $asn, $matches1);
                preg_match('/(?:AS)?(\d+)/i', $allowedASN, $matches2);
                
                $asnNumber = $matches1[1] ?? '';
                $allowedNumber = $matches2[1] ?? '';
                
                // Match by ASN number
                if ($asnNumber && $allowedNumber && $asnNumber === $allowedNumber) {
                    return true;
                }
                
                // Match by organization name (case-insensitive)
                // This allows: "Google", "GOOGLE", "google"
                if (strlen($allowedASN) > 2 && !is_numeric($allowedASN) && stripos($allowedASN, 'AS') !== 0) {
                    // It's a name, not a number
                    if (stripos($asn, $allowedASN) !== false) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }

    /**
     * Check country-specific rules
     */
    protected function checkCountryRules($country, $userAgent, $path, $referer) {
        if (!$this->country_rules) return false;
        
        $countryRules = $this->parseRules($this->country_rules);
        if (empty($countryRules)) return false;
        
        foreach ($countryRules as $rule) {
            $rule = trim($rule);
            if (empty($rule)) continue;
            
            // Parse rule: COUNTRY:action:pattern
            $parts = explode(':', $rule, 3);
            if (count($parts) !== 3) continue;
            
            list($ruleCountry, $action, $pattern) = $parts;
            
            // Check if rule applies to this country
            if (strtoupper($ruleCountry) !== strtoupper($country)) continue;
            
            // Check pattern match
            if ($action === 'block_path' && $this->matchPattern($path, $pattern)) {
                return true;
            }
            
            if ($action === 'block_agent' && stripos($userAgent, $pattern) !== false) {
                return true;
            }
            
            if ($action === 'block_referer' && stripos($referer, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check country blocking (blacklist/whitelist mode)
     */
    protected function checkCountryBlocking($country) {
        if (!$this->blocked_countries) return false;
        
        $countries = is_array($this->blocked_countries) ? 
                     $this->blocked_countries : 
                     $this->parseRules($this->blocked_countries);
        
        $countryBlocked = in_array(strtoupper($country), array_map('strtoupper', $countries));
        
        // Blacklist mode: block if in list
        if ($this->country_mode === 'blacklist') {
            return $countryBlocked;
        }
        
        // Whitelist mode: block if NOT in list
        if ($this->country_mode === 'whitelist') {
            return !$countryBlocked;
        }
        
        return false;
    }

    /**
     * Check if city should be blocked (requires GeoLite2-City)
     */
    protected function checkCityBlocking($cityData) {
        // Check if city blocking is enabled (must be exactly 1)
        if ($this->city_blocking_enabled !== 1) return false;
        
        if (!$this->blocked_cities) return false;
        if (!$cityData || !isset($cityData['city'])) return false;
        
        $cities = $this->parseRules($this->blocked_cities);
        
        $cityName = $cityData['city'] ?? '';
        $countryCode = $cityData['country'] ?? '';
        
        $cityBlocked = false;
        
        // Check each rule
        foreach ($cities as $rule) {
            $rule = trim($rule);
            if (empty($rule)) continue;
            
            // Format: "City, Country" or "City"
            if (strpos($rule, ',') !== false) {
                // Has country code
                list($ruleCity, $ruleCountry) = array_map('trim', explode(',', $rule, 2));
                
                // Match both city and country
                if (strcasecmp($cityName, $ruleCity) === 0 && 
                    strcasecmp($countryCode, $ruleCountry) === 0) {
                    $cityBlocked = true;
                    break;
                }
            } else {
                // City name only - match any country
                if (strcasecmp($cityName, $rule) === 0) {
                    $cityBlocked = true;
                    break;
                }
            }
        }
        
        // Blacklist mode: block if in list
        if ($this->city_mode === 'blacklist') {
            return $cityBlocked;
        }
        
        // Whitelist mode: block if NOT in list
        if ($this->city_mode === 'whitelist') {
            return !$cityBlocked;
        }
        
        return false;
    }

    /**
     * Check if subdivision/region should be blocked (requires GeoLite2-City)
     */
    protected function checkSubdivisionBlocking($cityData) {
        // Check if subdivision blocking is enabled (must be exactly 1)
        if ($this->subdivision_blocking_enabled !== 1) return false;
        
        if (!$this->blocked_subdivisions) return false;
        if (!$cityData || !isset($cityData['region'])) return false;
        
        $subdivisions = $this->parseRules($this->blocked_subdivisions);
        
        $regionName = $cityData['region'] ?? '';
        $countryCode = $cityData['country'] ?? '';
        
        if (empty($regionName)) return false; // No region data
        
        $subdivisionBlocked = false;
        $matchedRule = '';
        
        // Check each rule
        foreach ($subdivisions as $rule) {
            $rule = trim($rule);
            if (empty($rule)) continue;
            
            // Format: "Subdivision, Country" or "Subdivision"
            if (strpos($rule, ',') !== false) {
                // Has country code - match both subdivision and country
                list($ruleSubdivision, $ruleCountry) = array_map('trim', explode(',', $rule, 2));
                
                if (strcasecmp($regionName, $ruleSubdivision) === 0 && 
                    strcasecmp($countryCode, $ruleCountry) === 0) {
                    $subdivisionBlocked = true;
                    $matchedRule = $rule;
                    break;
                }
            } else {
                // No country code - match subdivision only (any country)
                if (strcasecmp($regionName, $rule) === 0) {
                    $subdivisionBlocked = true;
                    $matchedRule = $rule;
                    break;
                }
            }
        }
        
        // Log for debugging (can be removed in production)
        if ($this->enable_stats_logging) {
            $mode = $this->subdivision_mode ?? 'blacklist';
            $willBlock = ($mode === 'blacklist' && $subdivisionBlocked) || ($mode === 'whitelist' && !$subdivisionBlocked);
            
            if ($willBlock) {
                $this->wire('log')->save('wirewall', 
                    "Subdivision check: {$regionName}, {$countryCode} | Mode: {$mode} | Matched: {$matchedRule} | Will block: YES");
            }
        }
        
        // Blacklist mode: block if in list
        if ($this->subdivision_mode === 'blacklist') {
            return $subdivisionBlocked;
        }
        
        // Whitelist mode: block if NOT in list
        if ($this->subdivision_mode === 'whitelist') {
            return !$subdivisionBlocked;
        }
        
        return false;
    }

    /**
     * Check if IP is whitelisted
     */
    protected function isIPWhitelisted($ip) {
        if (!$this->ip_whitelist) return false;
        
        $whitelist = $this->parseRules($this->ip_whitelist);
        foreach ($whitelist as $allowedIP) {
            if ($this->matchIP($ip, $allowedIP)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if IP is blacklisted
     */
    protected function isIPBlacklisted($ip) {
        if (!$this->ip_blacklist) return false;
        
        $blacklist = $this->parseRules($this->ip_blacklist);
        foreach ($blacklist as $blockedIP) {
            if ($this->matchIP($ip, $blockedIP)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Match IP (supports exact, wildcard *, and CIDR notation)
     */
    protected function matchIP($ip, $pattern) {
        $pattern = trim($pattern);
        
        // Exact match
        if ($ip === $pattern) return true;
        
        // CIDR notation (e.g., 192.168.0.0/16)
        if (strpos($pattern, '/') !== false) {
            return $this->matchCIDR($ip, $pattern);
        }
        
        // Wildcard (e.g., 192.168.*.* or 192.168.1.*)
        if (strpos($pattern, '*') !== false) {
            $regex = '/^' . str_replace(['.', '*'], ['\.', '.*'], $pattern) . '$/';
            return preg_match($regex, $ip) === 1;
        }
        
        return false;
    }

    /**
     * Match CIDR notation (supports both IPv4 and IPv6)
     * 
     * Examples:
     * IPv4: 192.168.0.0/16, 10.0.0.0/8
     * IPv6: 2601:41:c780:6740::/64, 2001:db8::/32
     */
    protected function matchCIDR($ip, $cidr) {
        // Split CIDR into subnet and prefix length
        if (strpos($cidr, '/') === false) {
            return false;
        }
        
        list($subnet, $bits) = explode('/', $cidr);
        $bits = (int)$bits;
        
        // Detect IP version
        $isIPv6 = strpos($ip, ':') !== false;
        $isSubnetIPv6 = strpos($subnet, ':') !== false;
        
        // IP and subnet must be same version
        if ($isIPv6 !== $isSubnetIPv6) {
            return false;
        }
        
        if ($isIPv6) {
            // IPv6 CIDR matching
            return $this->matchIPv6CIDR($ip, $subnet, $bits);
        } else {
            // IPv4 CIDR matching (original logic)
            return $this->matchIPv4CIDR($ip, $subnet, $bits);
        }
    }
    
    /**
     * Match IPv4 CIDR
     */
    protected function matchIPv4CIDR($ip, $subnet, $bits) {
        // Convert to long integers
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        
        if ($ip_long === false || $subnet_long === false) {
            return false;
        }
        
        // Validate prefix length (0-32 for IPv4)
        if ($bits < 0 || $bits > 32) {
            return false;
        }
        
        // Create mask
        $mask = -1 << (32 - $bits);
        $subnet_long &= $mask;
        
        return ($ip_long & $mask) == $subnet_long;
    }
    
    /**
     * Match IPv6 CIDR
     * 
     * Example: 2601:41:c780:6740::/64
     */
    protected function matchIPv6CIDR($ip, $subnet, $bits) {
        // Convert IP addresses to binary format
        $ip_bin = @inet_pton($ip);
        $subnet_bin = @inet_pton($subnet);
        
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        
        // Validate prefix length (0-128 for IPv6)
        if ($bits < 0 || $bits > 128) {
            return false;
        }
        
        // Convert binary to bit string
        $ip_bits = '';
        $subnet_bits = '';
        
        for ($i = 0; $i < strlen($ip_bin); $i++) {
            $ip_bits .= str_pad(decbin(ord($ip_bin[$i])), 8, '0', STR_PAD_LEFT);
            $subnet_bits .= str_pad(decbin(ord($subnet_bin[$i])), 8, '0', STR_PAD_LEFT);
        }
        
        // Compare only the prefix bits
        $ip_prefix = substr($ip_bits, 0, $bits);
        $subnet_prefix = substr($subnet_bits, 0, $bits);
        
        return $ip_prefix === $subnet_prefix;
    }

    /**
     * Parse rules with caching (performance optimization)
     */
    protected function parseRules($text) {
        if (empty($text)) return [];
        
        // Check cache
        $cacheKey = md5($text);
        if (isset($this->parsedCache[$cacheKey])) {
            return $this->parsedCache[$cacheKey];
        }
        
        $lines = explode("\n", $text);
        $rules = [];
        
        foreach ($lines as $line) {
            $line = trim($line);
            // Skip comments and empty lines
            if ($line && !str_starts_with($line, '#')) {
                $rules[] = $line;
            }
        }
        
        // Cache parsed rules in memory
        $this->parsedCache[$cacheKey] = $rules;
        
        return $rules;
    }

    /**
     * Match pattern with wildcard support
     */
    protected function matchPattern($text, $pattern) {
        if ($text === $pattern) return true;
        
        if (strpos($pattern, '*') !== false) {
            $regex = '/^' . str_replace(['/', '*'], ['\/', '.*'], $pattern) . '$/i';
            return preg_match($regex, $text) === 1;
        }
        
        return false;
    }

    /**
     * Get real client IP (Cloudflare/Incapsula/Sucuri compatible)
     */
    protected function getRealClientIP() {
        // Cloudflare
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        
        // Incapsula
        if (!empty($_SERVER['HTTP_INCAP_CLIENT_IP'])) {
            return $_SERVER['HTTP_INCAP_CLIENT_IP'];
        }
        
        // Sucuri
        if (!empty($_SERVER['HTTP_X_SUCURI_CLIENTIP'])) {
            return $_SERVER['HTTP_X_SUCURI_CLIENTIP'];
        }
        
        // Standard X-Forwarded-For
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($ips[0]);
        }
        
        // X-Real-IP
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            return $_SERVER['HTTP_X_REAL_IP'];
        }
        
        // Direct connection
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Block access and show block page/redirect/404
     */
    protected function blockAccess($reason, $ip, $country, $asn, $userAgent = '') {
        if ($this->enable_stats_logging) {
            $this->logAccess($ip, $country, $asn, false, $reason, $userAgent);
        }
        
        // Get city data if City database is available
        $cityData = null;
        if ($this->geoipCityReader) {
            $cityData = $this->getCityData($ip);
        }
        
        // Redirect mode
        if ($this->block_action === 'redirect' && $this->redirect_url) {
            header('Location: ' . $this->redirect_url);
            exit;
        }
        
        // Silent 404 mode
        if ($this->block_action === 'silent_404') {
            http_response_code(404);
            echo "<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>404 Not Found - WireWall</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #000000;
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .wave-pattern {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.03;
            pointer-events: none;
        }
        
        .wave-line {
            position: absolute;
            left: 0;
            right: 0;
            height: 2px;
            background: white;
            transform-origin: center;
        }
        
        .wave-line:nth-child(1) { top: 10%; transform: scaleX(0.8); }
        .wave-line:nth-child(2) { top: 15%; transform: scaleX(0.85); }
        .wave-line:nth-child(3) { top: 20%; transform: scaleX(0.9); }
        .wave-line:nth-child(4) { top: 25%; transform: scaleX(0.95); }
        .wave-line:nth-child(5) { top: 30%; transform: scaleX(1); }
        .wave-line:nth-child(6) { top: 35%; transform: scaleX(0.95); }
        .wave-line:nth-child(7) { top: 40%; transform: scaleX(0.9); }
        .wave-line:nth-child(8) { top: 45%; transform: scaleX(0.85); }
        .wave-line:nth-child(9) { top: 50%; transform: scaleX(0.8); }
        .wave-line:nth-child(10) { top: 55%; transform: scaleX(0.85); }
        .wave-line:nth-child(11) { top: 60%; transform: scaleX(0.9); }
        .wave-line:nth-child(12) { top: 65%; transform: scaleX(0.95); }
        .wave-line:nth-child(13) { top: 70%; transform: scaleX(1); }
        .wave-line:nth-child(14) { top: 75%; transform: scaleX(0.95); }
        .wave-line:nth-child(15) { top: 80%; transform: scaleX(0.9); }
        
        .container {
            position: relative;
            max-width: 600px;
            width: 100%;
            z-index: 10;
            text-align: center;
        }
        
        .accent-line {
            width: 60px;
            height: 4px;
            background: #DC2626;
            margin: 0 auto 40px;
        }
        
        .error-code {
            font-size: 120px;
            font-weight: 700;
            line-height: 1;
            color: #ffffff;
            letter-spacing: -0.02em;
            margin-bottom: 24px;
        }
        
        h1 {
            font-size: 32px;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 16px;
            letter-spacing: -0.01em;
        }
        
        .subtitle {
            font-size: 16px;
            color: rgba(255, 255, 255, 0.6);
            line-height: 1.6;
            margin-bottom: 48px;
            max-width: 480px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .footer {
            padding-top: 48px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .footer-logo {
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: rgba(255, 255, 255, 0.3);
            margin-bottom: 6px;
        }
        
        .footer-text {
            font-size: 11px;
            color: rgba(255, 255, 255, 0.25);
            letter-spacing: 0.05em;
        }
        
        @media (max-width: 600px) {
            .error-code {
                font-size: 80px;
            }
            
            h1 {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
    <div class='wave-pattern'>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
    </div>

    <div class='container'>
        <div class='accent-line'></div>
        
        <div class='error-code'>404</div>
        
        <h1>Page Not Found</h1>
        
        <p class='subtitle'>
            The requested resource could not be located on this server. 
            Please verify the URL or return to the homepage.
        </p>
        
        <div class='footer'>
            <div class='footer-logo'>WIREWALL</div>
            <div class='footer-text'>SECURE ACCESS CONTROL SYSTEM</div>
        </div>
    </div>
</body>
</html>";
            exit;
        }
        
        // Show beautiful block page (default)
        $this->showBlockPage($country, $ip, $reason, $asn, $cityData);
    }

    /**
     * Show beautiful block page (WireWall 3.0 design)
     */
    protected function showBlockPage($country, $ip, $reason, $asn = null, $cityData = null) {
        http_response_code(403);
        
        $message = $this->block_message ?: 'Access from your location is currently unavailable.';
        
        // Get country name
        $countryNames = $this->getCountryNames();
        $countryName = $countryNames[$country] ?? $country ?? 'Unknown';
        
        // Build location string with city if available
        $locationStr = $countryName;
        if ($cityData && !empty($cityData['city'])) {
            $cityParts = [];
            if ($cityData['city']) $cityParts[] = $cityData['city'];
            if ($cityData['region']) $cityParts[] = $cityData['region'];
            if (!empty($cityParts)) {
                $locationStr = implode(', ', $cityParts) . ', ' . $countryName;
            }
        }
        
        echo "<!DOCTYPE html>
<html lang='en-AU'>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Access Restricted - WireWall</title>
    <style>
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }
        
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #000000;
            color: #ffffff;
            position: relative;
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .wave-pattern {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.03;
            pointer-events: none;
        }
        
        .wave-line {
            position: absolute;
            left: 0;
            right: 0;
            height: 2px;
            background: white;
            transform-origin: center;
        }
        
        .wave-line:nth-child(1) { top: 10%; transform: scaleX(0.8); }
        .wave-line:nth-child(2) { top: 15%; transform: scaleX(0.85); }
        .wave-line:nth-child(3) { top: 20%; transform: scaleX(0.9); }
        .wave-line:nth-child(4) { top: 25%; transform: scaleX(0.95); }
        .wave-line:nth-child(5) { top: 30%; transform: scaleX(1); }
        .wave-line:nth-child(6) { top: 35%; transform: scaleX(0.95); }
        .wave-line:nth-child(7) { top: 40%; transform: scaleX(0.9); }
        .wave-line:nth-child(8) { top: 45%; transform: scaleX(0.85); }
        .wave-line:nth-child(9) { top: 50%; transform: scaleX(0.8); }
        .wave-line:nth-child(10) { top: 55%; transform: scaleX(0.85); }
        .wave-line:nth-child(11) { top: 60%; transform: scaleX(0.9); }
        .wave-line:nth-child(12) { top: 65%; transform: scaleX(0.95); }
        .wave-line:nth-child(13) { top: 70%; transform: scaleX(1); }
        .wave-line:nth-child(14) { top: 75%; transform: scaleX(0.95); }
        .wave-line:nth-child(15) { top: 80%; transform: scaleX(0.9); }
        
        .container {
            position: relative;
            max-width: 600px;
            width: 100%;
            z-index: 10;
        }
        
        .accent-line {
            width: 60px;
            height: 4px;
            background: #DC2626;
            margin: 0 auto 40px;
        }
        
        h1 {
            font-size: 48px;
            font-weight: 700;
            text-align: center;
            margin-bottom: 24px;
            letter-spacing: -0.02em;
            color: #ffffff;
        }
        
        .subtitle {
            text-align: center;
            font-size: 18px;
            color: rgba(255, 255, 255, 0.6);
            margin-bottom: 48px;
            line-height: 1.6;
            max-width: 500px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .info-section {
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 32px 0;
            margin: 48px 0;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 32px;
        }
        
        .info-item {
            text-align: center;
        }
        
        .info-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: rgba(255, 255, 255, 0.4);
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        .info-value {
            font-size: 16px;
            color: #ffffff;
            font-weight: 500;
        }
        
        .footer {
            text-align: center;
            padding-top: 40px;
        }
        
        .footer-logo {
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: rgba(255, 255, 255, 0.3);
            margin-bottom: 8px;
        }
        
        .footer-text {
            font-size: 11px;
            color: rgba(255, 255, 255, 0.25);
            letter-spacing: 0.05em;
        }
        
        .info-item:hover .info-value {
            color: #DC2626;
            transition: color 0.3s ease;
        }
        
        @media (max-width: 600px) {
            h1 {
                font-size: 36px;
            }
            
            .info-grid {
                grid-template-columns: 1fr;
                gap: 24px;
            }
        }
    </style>
</head>
<body>
    <div class='wave-pattern'>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
        <div class='wave-line'></div>
    </div>

    <div class='container'>
        <div class='accent-line'></div>
        
        <h1>Access Restricted</h1>
        
        <p class='subtitle'>
            $message
        </p>
        
        <div class='info-section'>
            <div class='info-grid'>
                <div class='info-item'>
                    <div class='info-label'>Location</div>
                    <div class='info-value'>$locationStr</div>
                </div>
                <div class='info-item'>
                    <div class='info-label'>IP Address</div>
                    <div class='info-value'>$ip</div>
                </div>
            </div>
        </div>
        
        <div class='footer'>
            <div class='footer-logo'>WIREWALL</div>
            <div class='footer-text'>SECURE ACCESS CONTROL SYSTEM</div>
        </div>
    </div>
</body>
</html>";
        exit;
    }

    /**
     * Log access for statistics
     */
    protected function logAccess($ip, $country, $asn, $allowed, $reason, $userAgent = '') {
        $status = $allowed ? 'ALLOWED' : 'BLOCKED';
        
        // Build country string with city/region if available
        $countryStr = $country ? $country : 'Unknown';
        if ($this->geoipCityReader) {
            $cityData = $this->getCityData($ip);
            
            if ($cityData && ($cityData['city'] || $cityData['region'])) {
                $cityParts = [];
                if ($cityData['city']) $cityParts[] = $cityData['city'];
                if ($cityData['region']) $cityParts[] = $cityData['region'];
                if (!empty($cityParts)) {
                    $countryStr .= ' (' . implode(', ', $cityParts) . ')';
                }
            }
        }
        
        // Build single line log entry
        $parts = [$status, $countryStr, $ip];
        
        if ($asn) {
            $parts[] = $asn;
        }
        
        if ($userAgent) {
            $parts[] = 'UA: ' . substr($userAgent, 0, 100);
        }
        
        if ($reason) {
            $parts[] = $reason;
        }
        
        $message = implode(' | ', $parts);
        $this->wire('log')->save('wirewall', $message);
    }

    /**
     * Get country names mapping
     */
    protected function getCountryNames() {
        return [
            'US' => 'United States', 'GB' => 'United Kingdom', 'CA' => 'Canada',
            'AU' => 'Australia', 'NZ' => 'New Zealand', 'DE' => 'Germany',
            'FR' => 'France', 'IT' => 'Italy', 'ES' => 'Spain', 'RU' => 'Russia',
            'CN' => 'China', 'JP' => 'Japan', 'KR' => 'South Korea', 'BR' => 'Brazil',
            'MX' => 'Mexico', 'IN' => 'India', 'UA' => 'Ukraine', 'PL' => 'Poland',
            'NL' => 'Netherlands', 'SE' => 'Sweden', 'NO' => 'Norway', 'DK' => 'Denmark',
            'FI' => 'Finland', 'BE' => 'Belgium', 'AT' => 'Austria', 'CH' => 'Switzerland',
            'GR' => 'Greece', 'PT' => 'Portugal', 'CZ' => 'Czech Republic', 'RO' => 'Romania',
            'HU' => 'Hungary', 'BG' => 'Bulgaria', 'SK' => 'Slovakia', 'HR' => 'Croatia',
            'IE' => 'Ireland', 'LT' => 'Lithuania', 'LV' => 'Latvia', 'EE' => 'Estonia',
            'SI' => 'Slovenia', 'IS' => 'Iceland', 'MT' => 'Malta', 'CY' => 'Cyprus',
            'LU' => 'Luxembourg', 'TR' => 'Turkey', 'IL' => 'Israel', 'SA' => 'Saudi Arabia',
            'AE' => 'UAE', 'EG' => 'Egypt', 'ZA' => 'South Africa', 'NG' => 'Nigeria',
            'KE' => 'Kenya', 'AR' => 'Argentina', 'CL' => 'Chile', 'CO' => 'Colombia',
            'PE' => 'Peru', 'VE' => 'Venezuela', 'SG' => 'Singapore', 'MY' => 'Malaysia',
            'TH' => 'Thailand', 'VN' => 'Vietnam', 'PH' => 'Philippines', 'ID' => 'Indonesia',
            'PK' => 'Pakistan', 'BD' => 'Bangladesh', 'HK' => 'Hong Kong', 'TW' => 'Taiwan'
        ];
    }

    /**
     * Module configuration fields
     */
    public static function getModuleConfigInputfields(array $data) {
        $inputfields = new InputfieldWrapper();
        $modules = wire('modules');
        
        // Always update version in config
        $moduleInfo = self::getModuleInfo();
        $data['version'] = $moduleInfo['version'];
        
        // Handle cache clearing POST request
        if (wire('input')->post('clear_cache')) {
            $type = wire('input')->post('clear_cache');
            $cachePath = wire('config')->paths->cache . 'WireWall/';
            $cleared = 0;
            
            if (is_dir($cachePath)) {
                $files = scandir($cachePath);
                foreach ($files as $file) {
                    if ($file == '.' || $file == '..') continue;
                    
                    $shouldDelete = false;
                    if ($type === 'all') {
                        $shouldDelete = true;
                    } elseif ($type === 'ratelimit' && strpos($file, 'ratelimit_') === 0) {
                        $shouldDelete = true;
                    } elseif ($type === 'ban' && strpos($file, 'ban_') === 0) {
                        $shouldDelete = true;
                    } elseif ($type === 'proxy' && strpos($file, 'proxy_') === 0) {
                        $shouldDelete = true;
                    } elseif ($type === 'geo' && strpos($file, 'geo_') === 0) {
                        $shouldDelete = true;
                    }
                    
                    if ($shouldDelete && is_file($cachePath . $file)) {
                        @unlink($cachePath . $file);
                        $cleared++;
                    }
                }
            }
            
            wire('session')->message("Cleared {$cleared} cache files ({$type})");
        }
        
        // === ENABLE MODULE ===
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'enabled';
        $f->label = 'Enable WireWall';
        $f->description = 'Turn on the firewall protection';
        $f->checked = isset($data['enabled']) && $data['enabled'] ? 'checked' : '';
        $inputfields->add($f);
        
        // === ALLOW TRUSTED MODULES ===
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'allowTrustedModules';
        $f->label = 'Allow AJAX from trusted modules';
        $f->description = 'Allow AJAX requests from known ProcessWire modules (FieldtypeBookmarks, InputfieldPage, etc.)';
        $f->notes = 'Recommended: Keep this enabled to allow ProcessWire modules to function properly. Disabling this may break AJAX functionality in your modules.';
        $f->icon = 'check-circle';
        $f->checked = (!isset($data['allowTrustedModules']) || $data['allowTrustedModules']) ? 'checked' : '';
        $inputfields->add($f);
        
        // Custom Trusted Paths
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'custom_trusted_paths';
        $f->label = 'Custom Trusted AJAX Paths';
        $f->description = 'Additional URL paths that should bypass WireWall for AJAX requests (one per line)';
        $f->notes = 'Default trusted paths: /processwire/, /admin/, /ajax/
Examples of custom paths:
• /rockfrontend/ - RockFrontend module
• /my-custom-ajax/ - Your custom AJAX directory
• /live-search/ - Live search endpoints

Note: These paths apply only to POST AJAX requests (with X-Requested-With header).
For API endpoints, use "Custom API Paths" field below.';
        $f->rows = 5;
        $f->value = isset($data['custom_trusted_paths']) ? $data['custom_trusted_paths'] : '';
        $f->icon = 'code';
        $f->showIf = 'allowTrustedModules=1';
        $f->collapsed = Inputfield::collapsedBlank;
        $inputfields->add($f);
        
        // Custom API Paths
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'custom_api_paths';
        $f->label = 'Custom API Paths (All HTTP Methods)';
        $f->description = 'URL paths for API endpoints that should bypass WireWall for ALL HTTP methods (one per line)';
        $f->notes = 'Default API paths: /api/, /api2/, /rest/
Examples of custom API paths:
• /graphql/ - GraphQL endpoint
• /webhook/ - Webhook handlers
• /v1/ - Versioned API
• /endpoints/ - Custom API directory

Important: These paths bypass WireWall for ALL HTTP methods (GET, POST, PUT, DELETE, PATCH).
Only add paths that are secured by their own authentication (API keys, OAuth, etc.)';
        $f->rows = 5;
        $f->value = isset($data['custom_api_paths']) ? $data['custom_api_paths'] : '';
        $f->icon = 'exchange';
        $f->showIf = 'allowTrustedModules=1';
        $f->collapsed = Inputfield::collapsedBlank;
        $inputfields->add($f);
        
        // === STATISTICS & LOGGING ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Statistics & Logging';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'bar-chart';
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'enable_stats_logging';
        $f->label = 'Enable Statistics Logging';
        $f->description = 'Log all blocked and allowed requests with detailed information';
        $f->notes = 'View logs: Admin → Setup → Logs → wirewall';
        $f->checked = isset($data['enable_stats_logging']) && $data['enable_stats_logging'] ? 'checked' : '';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === CACHE MANAGEMENT ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Cache Management';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'database';
        
        // Get cache statistics
        $cachePath = wire('config')->paths->cache . 'WireWall/';
        $cacheStats = [
            'total' => 0,
            'ratelimit' => 0,
            'ban' => 0,
            'proxy' => 0,
            'geo' => 0,
            'size' => 0
        ];
        
        if (is_dir($cachePath)) {
            $files = scandir($cachePath);
            foreach ($files as $file) {
                if ($file != '.' && $file != '..' && is_file($cachePath . $file)) {
                    $cacheStats['total']++;
                    $cacheStats['size'] += filesize($cachePath . $file);
                    
                    if (strpos($file, 'ratelimit_') === 0) $cacheStats['ratelimit']++;
                    elseif (strpos($file, 'ban_') === 0) $cacheStats['ban']++;
                    elseif (strpos($file, 'proxy_') === 0) $cacheStats['proxy']++;
                    elseif (strpos($file, 'geo_') === 0) $cacheStats['geo']++;
                }
            }
        }
        
        $sizeFormatted = $cacheStats['size'] > 1024*1024 
            ? round($cacheStats['size']/1024/1024, 2) . ' MB'
            : round($cacheStats['size']/1024, 2) . ' KB';
        
        // Cache statistics display
        $f = $modules->get('InputfieldMarkup');
        $f->label = 'Cache Statistics';
        $f->icon = 'line-chart';
        $f->value = "
        <style>
            .cache-stats { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
                gap: 15px; 
                margin: 15px 0;
            }
            .cache-stat-item {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                border-left: 4px solid #0074d9;
            }
            .cache-stat-label {
                font-size: 11px;
                color: #666;
                text-transform: uppercase;
                font-weight: 600;
                letter-spacing: 0.5px;
            }
            .cache-stat-value {
                font-size: 24px;
                font-weight: bold;
                color: #333;
                margin-top: 5px;
            }
            .cache-buttons {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                margin-top: 20px;
            }
            .cache-button {
                padding: 8px 16px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background: white;
                cursor: pointer;
                font-size: 13px;
                transition: all 0.2s;
            }
            .cache-button:hover {
                background: #f8f9fa;
                border-color: #0074d9;
            }
            .cache-button.danger {
                border-color: #dc3545;
                color: #dc3545;
            }
            .cache-button.danger:hover {
                background: #dc3545;
                color: white;
            }
        </style>
        <div class='cache-stats'>
            <div class='cache-stat-item'>
                <div class='cache-stat-label'>Total Files</div>
                <div class='cache-stat-value'>{$cacheStats['total']}</div>
            </div>
            <div class='cache-stat-item'>
                <div class='cache-stat-label'>Rate Limits</div>
                <div class='cache-stat-value'>{$cacheStats['ratelimit']}</div>
            </div>
            <div class='cache-stat-item'>
                <div class='cache-stat-label'>Bans</div>
                <div class='cache-stat-value'>{$cacheStats['ban']}</div>
            </div>
            <div class='cache-stat-item'>
                <div class='cache-stat-label'>Proxy Cache</div>
                <div class='cache-stat-value'>{$cacheStats['proxy']}</div>
            </div>
            <div class='cache-stat-item'>
                <div class='cache-stat-label'>GeoIP Cache</div>
                <div class='cache-stat-value'>{$cacheStats['geo']}</div>
            </div>
            <div class='cache-stat-item'>
                <div class='cache-stat-label'>Total Size</div>
                <div class='cache-stat-value' style='font-size: 18px;'>{$sizeFormatted}</div>
            </div>
        </div>
        <p><strong>Cache Location:</strong> <code>{$cachePath}</code></p>
        ";
        $fieldset->add($f);
        
        // Clear cache buttons
        $f = $modules->get('InputfieldMarkup');
        $f->label = 'Clear Cache';
        $f->icon = 'trash';
        $f->value = "
        <div class='cache-buttons'>
            <button type='submit' class='cache-button' name='clear_cache' value='ratelimit'>
                Clear Rate Limits ({$cacheStats['ratelimit']} files)
            </button>
            <button type='submit' class='cache-button' name='clear_cache' value='ban'>
                Clear Bans ({$cacheStats['ban']} files)
            </button>
            <button type='submit' class='cache-button' name='clear_cache' value='proxy'>
                Clear Proxy Cache ({$cacheStats['proxy']} files)
            </button>
            <button type='submit' class='cache-button' name='clear_cache' value='geo'>
                Clear GeoIP Cache ({$cacheStats['geo']} files)
            </button>
            <button type='submit' class='cache-button danger' name='clear_cache' value='all' 
                    onclick='return confirm(\"Are you sure you want to clear ALL cache files?\")'>
                Clear All Cache ({$cacheStats['total']} files)
            </button>
        </div>
        <p><em>Note: Rate limits and bans will be recreated automatically as new requests come in. Proxy and GeoIP caches will be rebuilt on next lookup.</em></p>
        ";
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === GEOLOCATION SECTION ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Geolocation Settings';
        $fieldset->collapsed = Inputfield::collapsedNo;
        
        // === SETUP INFORMATION ===
        // Show important info about data location
        $setupInfo = $modules->get('InputfieldMarkup');
        $setupInfo->label = '⚙️ Setup Information';
        $setupInfo->description = 'Important information about data persistence';
        $setupInfo->icon = 'info-circle';
        $setupInfo->collapsed = Inputfield::collapsedYes;
        
        $dataPath = wire('config')->paths->assets . 'WireWall/';
        $geoipPath = $dataPath . 'geoip/';
        $vendorPath = $dataPath . 'vendor/';
        
        $setupInfo->value = '<div style="background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
            <h3 style="margin: 0 0 10px 0; color: #1976d2;">🎯 What\'s New in 1.2.1</h3>
            <p style="margin: 0 0 10px 0;"><strong>Problem solved:</strong> GeoIP databases, vendor files, and composer dependencies are NO LONGER deleted during module updates!</p>
            <p style="margin: 0;"><strong>New location:</strong> All persistent data is now stored in:</p>
            <code style="display: block; background: #fff; padding: 10px; margin: 10px 0; border-radius: 4px;">' . htmlspecialchars($dataPath) . '</code>
        </div>
        
        <div style="background: #fff3e0; border-left: 4px solid #ff9800; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
            <h3 style="margin: 0 0 10px 0; color: #f57c00;">📦 Migration (if upgrading from 1.2.0 or earlier)</h3>
            <p style="margin: 0 0 10px 0;">Migration should happen automatically on first module load. If manual migration is needed:</p>
            <ol style="margin: 10px 0 10px 20px; line-height: 1.8;">
                <li>Create directory: <code>' . htmlspecialchars($dataPath) . '</code></li>
                <li>Move GeoIP databases to: <code>' . htmlspecialchars($geoipPath) . '</code></li>
                <li>Move vendor folder to: <code>' . htmlspecialchars($vendorPath) . '</code></li>
                <li>Move composer.json/composer.lock to: <code>' . htmlspecialchars($dataPath) . '</code></li>
                <li>Run: <code>cd ' . htmlspecialchars($dataPath) . ' && composer install</code></li>
            </ol>
        </div>
        
        <div style="background: #f1f8e9; border-left: 4px solid #8bc34a; padding: 15px; border-radius: 4px;">
            <h3 style="margin: 0 0 10px 0; color: #689f38;">✅ Fresh Installation</h3>
            <ol style="margin: 10px 0 10px 20px; line-height: 1.8;">
                <li>Download MaxMind GeoLite2 databases</li>
                <li>Place in: <code>' . htmlspecialchars($geoipPath) . '</code></li>
                <li>Run: <code>cd ' . htmlspecialchars($dataPath) . ' && composer require geoip2/geoip2:^2.0</code></li>
            </ol>
            <p style="margin: 10px 0 0 0;"><strong>📁 Current paths:</strong></p>
            <ul style="margin: 5px 0 0 20px; font-family: monospace; font-size: 13px;">
                <li>Data: ' . htmlspecialchars($dataPath) . '</li>
                <li>GeoIP: ' . htmlspecialchars($geoipPath) . '</li>
                <li>Vendor: ' . htmlspecialchars($vendorPath) . '</li>
            </ul>
        </div>';
        
        $fieldset->add($setupInfo);
        
        // Check if MaxMind databases are installed
        $countryDbPath = $geoipPath . 'GeoLite2-Country.mmdb';
        $asnDbPath = $geoipPath . 'GeoLite2-ASN.mmdb';
        $cityDbPath = $geoipPath . 'GeoLite2-City.mmdb';
        $composerAutoload = $vendorPath . 'autoload.php';
        
        $hasCountryDb = file_exists($countryDbPath);
        $hasAsnDb = file_exists($asnDbPath);
        $hasCityDb = file_exists($cityDbPath);
        $hasComposer = file_exists($composerAutoload);
        $maxmindInstalled = $hasCountryDb && $hasAsnDb && $hasComposer;
        
        // Show status or instructions based on MaxMind availability
        $f = $modules->get('InputfieldMarkup');
        
        if ($maxmindInstalled) {
            // MaxMind is installed - show success status
            $f->label = 'MaxMind GeoLite2 Status';
            $f->icon = 'check-circle';
            $f->collapsed = Inputfield::collapsedYes; // Collapse when installed
            
            $countrySize = file_exists($countryDbPath) ? round(filesize($countryDbPath) / 1024 / 1024, 2) : 0;
            $asnSize = file_exists($asnDbPath) ? round(filesize($asnDbPath) / 1024 / 1024, 2) : 0;
            $citySize = file_exists($cityDbPath) ? round(filesize($cityDbPath) / 1024 / 1024, 2) : 0;
            $countryDate = file_exists($countryDbPath) ? date('Y-m-d', filemtime($countryDbPath)) : 'N/A';
            $asnDate = file_exists($asnDbPath) ? date('Y-m-d', filemtime($asnDbPath)) : 'N/A';
            $cityDate = file_exists($cityDbPath) ? date('Y-m-d', filemtime($cityDbPath)) : 'N/A';
            
            $f->value = "
            <style>
                .maxmind-status {
                    background: #10b981;
                    color: white;
                    padding: 16px 20px;
                    margin-bottom: 20px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    font-weight: 500;
                }
                .maxmind-status-icon {
                    font-size: 24px;
                }
                .maxmind-details {
                    background: #f8f9fa;
                    padding: 16px;
                    border-left: 4px solid #10b981;
                    margin-top: 16px;
                }
                .maxmind-details table {
                    width: 100%;
                    border-collapse: collapse;
                }
                .maxmind-details td {
                    padding: 8px 0;
                    border-bottom: 1px solid #e5e7eb;
                }
                .maxmind-details td:first-child {
                    font-weight: 600;
                    color: #666;
                    width: 40%;
                }
                .maxmind-details tr:last-child td {
                    border-bottom: none;
                }
                .maxmind-update-note {
                    margin-top: 16px;
                    padding: 12px;
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    font-size: 13px;
                    color: #856404;
                }
            </style>
            <div class='maxmind-status'>
                <span class='maxmind-status-icon'>✅</span>
                <span>MaxMind GeoLite2 databases are installed and active</span>
            </div>
            <div class='maxmind-details'>
                <table>
                    <tr>
                        <td>Country Database:</td>
                        <td><code>{$countryDbPath}</code> ({$countrySize} MB)</td>
                    </tr>
                    <tr>
                        <td>ASN Database:</td>
                        <td><code>{$asnDbPath}</code> ({$asnSize} MB)</td>
                    </tr>
                    <tr>
                        <td>City Database:</td>
                        <td>" . ($hasCityDb ? "<code>{$cityDbPath}</code> ({$citySize} MB) ✅" : "<em style='color: #666;'>Not installed (optional - for detailed logging)</em>") . "</td>
                    </tr>
                    <tr>
                        <td>Composer Autoload:</td>
                        <td><code>{$composerAutoload}</code> ✅</td>
                    </tr>
                    <tr>
                        <td>Last Updated:</td>
                        <td>Country: {$countryDate} | ASN: {$asnDate}" . ($hasCityDb ? " | City: {$cityDate}" : "") . "</td>
                    </tr>
                    <tr>
                        <td>Status:</td>
                        <td><strong style='color: #10b981;'>Active - Using MaxMind for all GeoIP lookups</strong>" . ($hasCityDb ? "<br><em style='color: #666; font-size: 12px;'>City database enabled - logs will include city/region</em>" : "") . "</td>
                    </tr>
                </table>
                <div class='maxmind-update-note'>
                    <strong>💡 Update Reminder:</strong> MaxMind databases should be updated monthly. 
                    Download new versions from <a href='https://www.maxmind.com/en/accounts/current/geoip/downloads' target='_blank'>MaxMind Downloads</a> 
                    and replace the files in <code>{$geoipPath}</code>
                </div>
            </div>
            ";
        } else {
            // MaxMind not installed - show setup instructions
            $f->label = 'MaxMind Setup Instructions';
            $f->icon = 'info-circle';
            $f->collapsed = Inputfield::collapsedNo; // Expand when not installed (show warnings)
            
            $missingItems = [];
            if (!$hasCountryDb) $missingItems[] = 'GeoLite2-Country.mmdb';
            if (!$hasAsnDb) $missingItems[] = 'GeoLite2-ASN.mmdb';
            if (!$hasComposer) $missingItems[] = 'Composer dependencies (geoip2/geoip2)';
            
            $missingList = implode(', ', $missingItems);
            
            $f->value = "
            <style>
                .maxmind-warning {
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 16px;
                    margin-bottom: 20px;
                }
                .maxmind-warning strong {
                    color: #856404;
                }
                .maxmind-missing {
                    background: #f8d7da;
                    border-left: 4px solid #dc3545;
                    padding: 12px;
                    margin: 16px 0;
                    font-size: 13px;
                    color: #721c24;
                }
            </style>
            <div class='maxmind-warning'>
                <strong>⚠️ MaxMind Not Detected:</strong> WireWall is currently using HTTP API fallback (ip-api.com) for geolocation. 
                For better performance and reliability, install MaxMind GeoLite2 databases.
            </div>
            <div class='maxmind-missing'>
                <strong>Missing:</strong> {$missingList}
            </div>
            <p><strong>Setup Instructions:</strong></p>
            <ol>
                <li>Register for free at <a href='https://www.maxmind.com/en/geolite2/signup' target='_blank'>maxmind.com</a></li>
                <li>Download <strong>GeoLite2-Country.mmdb</strong> and <strong>GeoLite2-ASN.mmdb</strong> (required)</li>
                <li><em>Optional:</em> Download <strong>GeoLite2-City.mmdb</strong> for detailed logging (city/region)</li>
                <li>Place files in: <code>{$geoipPath}</code></li>
                <li>Run: <code>cd {$dataPath} && composer require geoip2/geoip2</code></li>
                <li>Refresh this page to see status update</li>
            </ol>
            <p><em>Without MaxMind databases, WireWall will automatically use ip-api.com (HTTP fallback). This works but is slower and has rate limits.</em></p>
            ";
        }
        
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === COUNTRY BLOCKING ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Country Blocking';
        $fieldset->collapsed = Inputfield::collapsedNo;
        
        $f = $modules->get('InputfieldRadios');
        $f->name = 'country_mode';
        $f->label = 'Blocking Mode';
        $f->addOption('blacklist', 'Blacklist (block selected countries)');
        $f->addOption('whitelist', 'Whitelist (allow only selected countries)');
        $f->value = $data['country_mode'] ?? 'blacklist';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldAsmSelect');
        $f->name = 'blocked_countries';
        $f->label = 'Blocked Countries';
        $f->description = 'Select countries for blacklist/whitelist mode';
        foreach (self::getCountryList() as $code => $name) {
            $f->addOption($code, "{$name} ({$code})");
        }
        // Handle both array (AsmSelect) and string (textarea) formats
        $value = $data['blocked_countries'] ?? '';
        if (is_string($value) && !empty($value)) {
            // Convert string to array for AsmSelect (manual parsing since this is static)
            $lines = preg_split('/[\r\n,]+/', $value);
            $value = array_filter(array_map('trim', $lines));
        }
        $f->value = is_array($value) ? $value : [];
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === CITY BLOCKING ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'City Blocking (Requires GeoLite2-City)';
        $fieldset->description = 'Block or allow access based on city location. Requires GeoLite2-City.mmdb database.';
        
        // Check if City database is available
        // Use new /site/assets/WireWall/ path (1.2.1+)
        $dataPath = wire('config')->paths->assets . 'WireWall/';
        $geoipPath = $dataPath . 'geoip/';
        $cityDbPath = $geoipPath . 'GeoLite2-City.mmdb';
        $hasCityDb = file_exists($cityDbPath);
        
        // Collapse if database is installed, expand if not (to show warning)
        $fieldset->collapsed = $hasCityDb ? Inputfield::collapsedYes : Inputfield::collapsedNo;
        
        if (!$hasCityDb) {
            $f = $modules->get('InputfieldMarkup');
            $f->value = "<div style='background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin-bottom: 16px;'>
                <strong>⚠️ City Database Not Installed</strong><br>
                City-based blocking requires GeoLite2-City.mmdb database.<br>
                <a href='https://www.maxmind.com/en/accounts/current/geoip/downloads' target='_blank'>Download from MaxMind</a> 
                and place in <code>{$geoipPath}</code>
            </div>";
            $fieldset->add($f);
        } else {
            $f = $modules->get('InputfieldMarkup');
            $f->value = "<div style='background: #d1fae5; border-left: 4px solid #10b981; padding: 12px; margin-bottom: 16px;'>
                <strong>✅ City Database Active</strong><br>
                City-based blocking is available. Configure rules below.
            </div>";
            $fieldset->add($f);
        }
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'city_blocking_enabled';
        $f->label = 'Enable City Blocking';
        $f->description = 'Enable or disable city-based access control';
        $f->checked = isset($data['city_blocking_enabled']) && $data['city_blocking_enabled'] ? 'checked' : '';
        if (!$hasCityDb) {
            $f->attr('disabled', 'disabled');
            $f->notes = 'Disabled - City database not installed';
        }
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldRadios');
        $f->name = 'city_mode';
        $f->label = 'City Blocking Mode';
        $f->addOption('blacklist', 'Blacklist (block selected cities)');
        $f->addOption('whitelist', 'Whitelist (allow only selected cities)');
        $f->value = $data['city_mode'] ?? 'blacklist';
        $f->showIf = 'city_blocking_enabled=1';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_cities';
        $f->label = 'Cities List';
        $f->description = 'Enter city names (one per line). Format: "City" or "City, Country"';
        $f->notes = 'Examples: Philadelphia, Beijing, London, Sydney, AU, New York, US';
        $f->rows = 8;
        $f->value = $data['blocked_cities'] ?? '';
        $f->showIf = 'city_blocking_enabled=1';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === SUBDIVISION/REGION BLOCKING ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Subdivision/Region Blocking (Requires GeoLite2-City)';
        $fieldset->description = 'Block or allow access based on subdivision/region (state, province, oblast). Requires GeoLite2-City.mmdb database.';
        
        // Collapse if database is installed, expand if not (to show warning)
        $fieldset->collapsed = $hasCityDb ? Inputfield::collapsedYes : Inputfield::collapsedNo;
        
        if (!$hasCityDb) {
            $f = $modules->get('InputfieldMarkup');
            $f->value = "<div style='background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin-bottom: 16px;'>
                <strong>⚠️ City Database Not Installed</strong><br>
                Subdivision-based blocking requires GeoLite2-City.mmdb database.<br>
                <a href='https://www.maxmind.com/en/accounts/current/geoip/downloads' target='_blank'>Download from MaxMind</a> 
                and place in <code>{$geoipPath}</code>
            </div>";
            $fieldset->add($f);
        } else {
            $f = $modules->get('InputfieldMarkup');
            $f->value = "<div style='background: #d1fae5; border-left: 4px solid #10b981; padding: 12px; margin-bottom: 16px;'>
                <strong>✅ City Database Active</strong><br>
                Subdivision-based blocking is available. Configure rules below.
            </div>";
            $fieldset->add($f);
        }
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'subdivision_blocking_enabled';
        $f->label = 'Enable Subdivision Blocking';
        $f->description = 'Enable or disable subdivision/region-based access control';
        $f->checked = isset($data['subdivision_blocking_enabled']) && $data['subdivision_blocking_enabled'] ? 'checked' : '';
        if (!$hasCityDb) {
            $f->attr('disabled', 'disabled');
            $f->notes = 'Disabled - City database not installed';
        }
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldRadios');
        $f->name = 'subdivision_mode';
        $f->label = 'Subdivision Blocking Mode';
        $f->addOption('blacklist', 'Blacklist (block selected subdivisions)');
        $f->addOption('whitelist', 'Whitelist (allow only selected subdivisions)');
        $f->value = $data['subdivision_mode'] ?? 'blacklist';
        $f->showIf = 'subdivision_blocking_enabled=1';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_subdivisions';
        $f->label = 'Subdivisions List';
        $f->description = 'Enter subdivision/region names (one per line). Format: "Subdivision" or "Subdivision, Country"';
        $f->notes = 'Examples: Pennsylvania | California, US | New South Wales, AU | Bavaria | England, GB';
        $f->rows = 8;
        $f->value = $data['blocked_subdivisions'] ?? '';
        $f->showIf = 'subdivision_blocking_enabled=1';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === ANTI-BOT / VPN / PROXY / TOR ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Anti-Bot / VPN / Proxy / Tor';
        $fieldset->collapsed = Inputfield::collapsedNo;
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_proxy_vpn_tor';
        $f->label = 'Block VPN/Proxy/Tor';
        $f->description = 'Block known VPN, proxy servers, and Tor exit nodes';
        $f->notes = 'Uses multi-API detection: ip-api.com → ipinfo.io → ipapi.co';
        $f->checked = isset($data['block_proxy_vpn_tor']) && $data['block_proxy_vpn_tor'] ? 'checked' : '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_datacenters';
        $f->label = 'Block Datacenters';
        $f->description = 'Block traffic from datacenters (AWS, Google Cloud, DigitalOcean, OVH, Hetzner, etc.)';
        $f->checked = isset($data['block_datacenters']) && $data['block_datacenters'] ? 'checked' : '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'block_asns';
        $f->label = 'Blocked ASNs';
        $f->description = 'List of ASN numbers or organization names to block (one per line)';
        $f->notes = 'Example: AS16509 or Amazon or 16509';
        $f->rows = 5;
        $f->value = $data['block_asns'] ?? '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'js_challenge_enabled';
        $f->label = 'Enable JavaScript Challenge';
        $f->description = 'Show JS challenge for suspicious requests (headless browsers, no cookies, too short UA)';
        $f->notes = 'Real browsers pass automatically. Headless bots are blocked.';
        $f->checked = isset($data['js_challenge_enabled']) && $data['js_challenge_enabled'] ? 'checked' : '';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === RATE LIMITING ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Rate Limiting';
        $fieldset->collapsed = Inputfield::collapsedNo;
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'rate_limit_enabled';
        $f->label = 'Enable Rate Limiting';
        $f->description = 'Limit requests per minute per IP address';
        $f->checked = isset($data['rate_limit_enabled']) && $data['rate_limit_enabled'] ? 'checked' : '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldInteger');
        $f->name = 'rate_limit_requests';
        $f->label = 'Requests Per Minute';
        $f->description = 'Maximum requests allowed per minute from single IP';
        $f->value = $data['rate_limit_requests'] ?? 10;
        $f->min = 1;
        $f->max = 1000;
        $f->showIf = 'rate_limit_enabled=1';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldInteger');
        $f->name = 'rate_limit_minutes';
        $f->label = 'Ban Duration (minutes)';
        $f->description = 'How long to ban IP after exceeding rate limit';
        $f->value = $data['rate_limit_minutes'] ?? 60;
        $f->min = 1;
        $f->max = 1440;
        $f->showIf = 'rate_limit_enabled=1';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === GLOBAL RULES (CATEGORIZED BOTS) ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Global Rules - Bot Categories';
        $fieldset->collapsed = Inputfield::collapsedNo;
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_bad_bots';
        $f->label = 'Block Known Bad Bots';
        $f->description = 'Block scrapers, scanners, and malicious bots';
        $f->notes = 'Blocks: wget, curl, scrapy, nmap, nikto, sqlmap, semrush, ahrefs, etc.';
        $f->checked = isset($data['block_bad_bots']) && $data['block_bad_bots'] ? 'checked' : '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_search_bots';
        $f->label = 'Block Search Engine Bots';
        $f->description = 'Block search engine crawlers (Googlebot, Bingbot, Yandex, Baidu, etc.)';
        $f->notes = '⚠️ WARNING: This will prevent your site from being indexed by search engines!';
        $f->checked = isset($data['block_search_bots']) && $data['block_search_bots'] ? 'checked' : '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_ai_bots';
        $f->label = 'Block AI Training Bots';
        $f->description = 'Block AI company bots that train on your content';
        $f->notes = 'Blocks: GPTBot, ClaudeBot, GrokBot, Perplexity, Google-Extended, etc.';
        $f->checked = isset($data['block_ai_bots']) && $data['block_ai_bots'] ? 'checked' : '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_other_bots';
        $f->label = 'Block Other Bots (Custom List)';
        $f->description = 'Block bots from your custom list below';
        $f->checked = isset($data['block_other_bots']) && $data['block_other_bots'] ? 'checked' : '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'other_bots_list';
        $f->label = 'Custom Bot Patterns';
        $f->description = 'User-Agent patterns to block (one per line)';
        $f->rows = 5;
        $f->value = $data['other_bots_list'] ?? '';
        $f->showIf = 'block_other_bots=1';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === GLOBAL RULES (PATHS/UA/REFERERS) ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Global Rules - Paths / User Agents / Referers';
        $fieldset->collapsed = Inputfield::collapsedYes;
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_paths';
        $f->label = 'Blocked Paths';
        $f->description = 'URL paths to block (one per line, supports wildcards)';
        $f->notes = 'Example: /wp-admin/* or *.php or /admin/*';
        $f->rows = 5;
        $f->value = $data['blocked_paths'] ?? '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_user_agents';
        $f->label = 'Blocked User Agents';
        $f->description = 'User-Agent patterns to block (one per line)';
        $f->rows = 5;
        $f->value = $data['blocked_user_agents'] ?? '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_referers';
        $f->label = 'Blocked Referers';
        $f->description = 'Referer domains to block (one per line)';
        $f->notes = 'Example: spam.com or bad-site.net';
        $f->rows = 5;
        $f->value = $data['blocked_referers'] ?? '';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === COUNTRY-SPECIFIC RULES ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Country-Specific Rules';
        $fieldset->collapsed = Inputfield::collapsedYes;
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'country_rules';
        $f->label = 'Country Rules';
        $f->description = 'Different rules for different countries';
        $f->notes = 'Format: COUNTRY:action:pattern (one per line)
Examples:
RU:block_path:/admin/*
CN:block_agent:BadBot
US:block_referer:spam.com';
        $f->rows = 10;
        $f->value = $data['country_rules'] ?? '';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === IP WHITELIST / BLACKLIST ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'IP Address Control';
        $fieldset->collapsed = Inputfield::collapsedYes;
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'ip_whitelist';
        $f->label = 'IP Whitelist (Always Allow)';
        $f->description = 'IPs that bypass ALL blocking rules (one per line)';
        $f->notes = 'Supports: exact (1.2.3.4), wildcard (1.2.3.*), CIDR (192.168.0.0/16)';
        $f->rows = 5;
        $f->value = $data['ip_whitelist'] ?? '';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'ip_blacklist';
        $f->label = 'IP Blacklist (Always Block)';
        $f->description = 'IPs that are ALWAYS blocked (one per line)';
        $f->notes = 'Supports: exact (1.2.3.4), wildcard (1.2.3.*), CIDR (192.168.0.0/16)';
        $f->rows = 5;
        $f->value = $data['ip_blacklist'] ?? '';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === EXCEPTIONS / WHITELIST ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Exceptions / Whitelist';
        $fieldset->description = 'Allow specific bots and IPs to bypass all WireWall checks';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'check-square';
        
        // Allowed User-Agents
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'allowedUserAgents';
        $f->label = 'Allowed User-Agents (Bots Whitelist)';
        $f->description = 'User-Agent patterns to allow (one per line). These bots will bypass ALL WireWall checks.';
        $f->notes = 'Common legitimate bots:
• Googlebot - Google Search
• Bingbot - Bing Search  
• Yandex - Yandex Search
• facebookexternalhit - Facebook crawling
• Slackbot - Slack link previews
• LinkedInBot - LinkedIn
• Twitterbot - Twitter cards
• WhatsApp - WhatsApp previews
• Applebot - Apple Search';
        $f->rows = 10;
        $f->value = isset($data['allowedUserAgents']) ? $data['allowedUserAgents'] : "Googlebot\nBingbot\nYandex\nfacebookexternalhit\nSlackbot\nLinkedInBot\nTwitterbot\nWhatsApp\nApplebot";
        $f->icon = 'robot';
        $fieldset->add($f);
        
        // Allowed IPs
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'allowedIPs';
        $f->label = 'Allowed IPs (IP Whitelist)';
        $f->description = 'IP addresses or CIDR ranges to allow (one per line). These IPs will bypass ALL WireWall checks. Supports both IPv4 and IPv6.';
        $f->notes = 'Examples (IPv4):
• 66.249.64.0/19 - Google Bot IPs
• 157.55.39.0/24 - Bing Bot IPs  
• 77.88.5.0/24 - Yandex Bot IPs
• 192.168.1.100 - Single IP
• 10.0.0.0/8 - Private network

Examples (IPv6):
• 2601:41:c780:6740::/64 - IPv6 subnet
• 2001:4860::/32 - Google IPv6 range
• 2a00:1450::/32 - Google IPv6 range
• 2001:db8::1 - Single IPv6 address

For Google Bot IPs, see: https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot';
        $f->rows = 8;
        $f->value = isset($data['allowedIPs']) ? $data['allowedIPs'] : '';
        $f->icon = 'globe';
        $fieldset->add($f);
        
        // Allowed ASNs
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'allowedASNs';
        $f->label = 'Allowed ASNs (Autonomous System Numbers)';
        $f->description = 'ASN numbers or organization names to allow (one per line). These ASNs will bypass ALL WireWall checks.';
        $f->notes = 'Major services ASNs:
• AS15169 or 15169 - Google
• AS8075 or 8075 - Microsoft (Bing)
• AS32934 or 32934 - Facebook
• AS13238 or 13238 - Yandex
• AS16509 or 16509 - Amazon AWS
• AS54113 or 54113 - Fastly CDN
• AS13335 or 13335 - Cloudflare
• AS46489 or 46489 - Twilio

You can use ASN numbers (15169) or with AS prefix (AS15169) or organization names (Google).
MaxMind GeoLite2 ASN database required for this feature.';
        $f->rows = 8;
        $f->value = isset($data['allowedASNs']) ? $data['allowedASNs'] : "15169\n8075\n32934\n13238";
        $f->icon = 'sitemap';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // === BLOCK ACTION ===
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Block Action';
        $fieldset->collapsed = Inputfield::collapsedNo;
        
        $f = $modules->get('InputfieldRadios');
        $f->name = 'block_action';
        $f->label = 'Action for Blocked Visitors';
        $f->addOption('show_page', 'Show beautiful block page');
        $f->addOption('redirect', 'Redirect to URL');
        $f->addOption('silent_404', 'Return 404 silently (stealth mode)');
        $f->value = $data['block_action'] ?? 'show_page';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldText');
        $f->name = 'redirect_url';
        $f->label = 'Redirect URL';
        $f->description = 'URL to redirect blocked visitors';
        $f->value = $data['redirect_url'] ?? '';
        $f->showIf = 'block_action=redirect';
        $fieldset->add($f);
        
        $f = $modules->get('InputfieldTextarea');
        $f->name = 'block_message';
        $f->label = 'Block Message';
        $f->description = 'Custom message shown on block page';
        $f->value = $data['block_message'] ?? 'Access from your location is currently unavailable.';
        $f->rows = 3;
        $f->showIf = 'block_action=show_page';
        $fieldset->add($f);
        
        $inputfields->add($fieldset);
        
        // Hidden field: version (auto-updated on each save)
        $f = $modules->get('InputfieldHidden');
        $f->name = 'version';
        $f->value = $data['version']; // Module version number
        $inputfields->add($f);
        
        return $inputfields;
    }
    
    /**
     * Get country list for configuration
     */
    protected static function getCountryList() {
        return [
            'US' => 'United States', 'GB' => 'United Kingdom', 'CA' => 'Canada',
            'AU' => 'Australia', 'NZ' => 'New Zealand', 'DE' => 'Germany',
            'FR' => 'France', 'IT' => 'Italy', 'ES' => 'Spain', 'RU' => 'Russia',
            'CN' => 'China', 'JP' => 'Japan', 'KR' => 'South Korea', 'BR' => 'Brazil',
            'MX' => 'Mexico', 'IN' => 'India', 'UA' => 'Ukraine', 'PL' => 'Poland',
            'NL' => 'Netherlands', 'SE' => 'Sweden', 'NO' => 'Norway', 'DK' => 'Denmark',
            'FI' => 'Finland', 'BE' => 'Belgium', 'AT' => 'Austria', 'CH' => 'Switzerland',
            'GR' => 'Greece', 'PT' => 'Portugal', 'CZ' => 'Czech Republic', 'RO' => 'Romania',
            'HU' => 'Hungary', 'BG' => 'Bulgaria', 'SK' => 'Slovakia', 'HR' => 'Croatia',
            'IE' => 'Ireland', 'LT' => 'Lithuania', 'LV' => 'Latvia', 'EE' => 'Estonia',
            'SI' => 'Slovenia', 'IS' => 'Iceland', 'MT' => 'Malta', 'CY' => 'Cyprus',
            'LU' => 'Luxembourg', 'TR' => 'Turkey', 'IL' => 'Israel', 'SA' => 'Saudi Arabia',
            'AE' => 'UAE', 'EG' => 'Egypt', 'ZA' => 'South Africa', 'NG' => 'Nigeria',
            'KE' => 'Kenya', 'AR' => 'Argentina', 'CL' => 'Chile', 'CO' => 'Colombia',
            'PE' => 'Peru', 'VE' => 'Venezuela', 'SG' => 'Singapore', 'MY' => 'Malaysia',
            'TH' => 'Thailand', 'VN' => 'Vietnam', 'PH' => 'Philippines', 'ID' => 'Indonesia',
            'PK' => 'Pakistan', 'BD' => 'Bangladesh', 'HK' => 'Hong Kong', 'TW' => 'Taiwan'
        ];
    }
    
    /**
     * Module installation - create persistent data directory
     * 
     * Creates directory in /site/assets/ instead of module directory
     */
    public function ___install() {
        $dataPath = $this->getDataPath();
        $geoipPath = $this->getGeoIPPath();
        
        // Create main data directory
        if (!is_dir($dataPath)) {
            wireMkdir($dataPath, true);
        }
        
        // Create geoip subdirectory
        if (!is_dir($geoipPath)) {
            wireMkdir($geoipPath, true);
        }
        
        // Create README with setup instructions
        $readme = $dataPath . 'README.txt';
        if (!file_exists($readme)) {
            $content = "WireWall Data Directory\n";
            $content .= "=======================\n\n";
            $content .= "This directory is persistent across module updates.\n\n";
            $content .= "Setup MaxMind GeoIP:\n";
            $content .= "1. Download GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb from maxmind.com\n";
            $content .= "2. Place in geoip/ subdirectory\n";
            $content .= "3. Run: composer require geoip2/geoip2:^2.0\n\n";
            $content .= "Directory structure:\n";
            $content .= "- geoip/        : MaxMind database files (.mmdb)\n";
            $content .= "- vendor/       : Composer dependencies\n";
            $content .= "- composer.json : Composer configuration\n";
            $content .= "- composer.lock : Dependency lock file\n";
            
            file_put_contents($readme, $content);
        }
        
        $this->wire('log')->save('wirewall', 'WireWall installed - data directory created: ' . $dataPath);
    }
    
    /**
     * Module upgrade - migrate old data if exists
     * 
     * Automatically migrates data from old module directory
     */
    public function ___upgrade($fromVersion, $toVersion) {
        // Only run migration when upgrading to 1.2.1 (version 121)
        if ($toVersion >= 121 && $fromVersion < 121) {
            $this->migrateDataToAssets();
        }
    }
    
    /**
     * Migrate data from module directory to /site/assets/WireWall/
     * 
     * Automatic migration of existing installations
     */
    protected function migrateDataToAssets() {
        $modulePath = $this->wire('config')->paths->siteModules . 'WireWall/';
        $dataPath = $this->getDataPath();
        $geoipPath = $this->getGeoIPPath();
        $vendorPath = $this->getVendorPath();
        
        // Create data directory if it doesn't exist
        if (!is_dir($dataPath)) {
            wireMkdir($dataPath, true);
        }
        
        $migrated = [];
        
        // Migrate geoip directory
        $oldGeoipPath = $modulePath . 'geoip/';
        if (is_dir($oldGeoipPath) && !is_dir($geoipPath)) {
            if (rename($oldGeoipPath, $geoipPath)) {
                $migrated[] = 'geoip directory';
            }
        }
        
        // Migrate vendor directory
        $oldVendorPath = $modulePath . 'vendor/';
        if (is_dir($oldVendorPath) && !is_dir($vendorPath)) {
            if (rename($oldVendorPath, $vendorPath)) {
                $migrated[] = 'vendor directory';
            }
        }
        
        // Migrate composer files
        $composerFiles = ['composer.json', 'composer.lock'];
        foreach ($composerFiles as $file) {
            $oldFile = $modulePath . $file;
            $newFile = $dataPath . $file;
            if (file_exists($oldFile) && !file_exists($newFile)) {
                if (copy($oldFile, $newFile)) {
                    $migrated[] = $file;
                    @unlink($oldFile); // Remove old file after successful copy
                }
            }
        }
        
        if (!empty($migrated)) {
            $this->wire('log')->save('wirewall', 'Migrated to new geoip folder location: ' . implode(', ', $migrated));
        }
    }
}