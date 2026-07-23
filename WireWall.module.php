<?php namespace ProcessWire;

/**
 * WireWall 1.7.1 - Advanced Traffic Firewall
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
 * @version 1.7.1
 * @author Maxim Semenov <maxim@smnv.org> (smnv.org)
 * @date April 24, 2026
 * @requires ProcessWire 3.0.200+, PHP 8.1+
 */

class WireWall extends WireData implements Module, ConfigurableModule {

    public static function getModuleInfo() {
        return [
            'title' => 'WireWall',
            'summary' => 'Advanced traffic firewall with VPN/Proxy/Tor detection, rate limiting, and JS challenge',
            'version' => 171,
            'autoload' => true,
            'singular' => true,
            'icon' => 'shield',
            'requires' => 'ProcessWire>=3.0.200,PHP>=8.1',
            'author' => 'Maxim Semenov',
            'href' => 'https://smnv.org',
        ];
    }

    // Cache for parsed rules (performance optimization)
    protected $parsedCache = [];
    
    // Current request data
    protected $currentAS = null;
    protected $currentCountry = null;
    protected $currentBotVerification = null;
    
    // Allow AJAX from trusted ProcessWire modules (default: enabled)
    protected $allowTrustedModules = true;
    
    // Scoped known-bot and compatibility exceptions
    protected $allowedUserAgents = '';
    protected $allowedIPs = '';
    protected $allowedASNs = '';
    protected $compatibilityUserAgents = '';
    protected $trigger_scanner_preset = 'none';
    
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
     * Get traffic history directory path (AI-friendly request history)
     */
    protected function getTrafficHistoryPath() {
        return $this->getDataPath() . 'traffic/';
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
        
        $data = @unserialize($content, ['allowed_classes' => false]);
        if (!is_array($data) || !isset($data['expire'])) {
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

        $migratedData = $this->prepareConfigFor170($data);
        if ($migratedData !== $data) {
            $this->wire('modules')->saveModuleConfigData($this, $migratedData);
            $data = $migratedData;
        }
        
        // Normalize checkbox values: convert empty strings to 0, keep 1 as is
        // This supports old configs with "" and new configs with 0/1
        $checkboxFields = [
            'enabled', 'allowTrustedModules', 'city_blocking_enabled', 
            'subdivision_blocking_enabled', 'block_proxy_vpn_tor', 
            'block_datacenters', 'js_challenge_enabled', 'rate_limit_enabled',
            'block_bad_bots', 'block_search_bots', 'block_ai_bots', 
            'block_other_bots', 'enable_stats_logging', 'enable_traffic_history',
            'disable_ajax_protection'
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
        if (isset($data['compatibilityUserAgents'])) {
            $this->compatibilityUserAgents = $data['compatibilityUserAgents'];
        }
        if (isset($data['trigger_scanner_preset'])) {
            $this->trigger_scanner_preset = $data['trigger_scanner_preset'];
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
     * Migrate legacy full-bypass exception fields to explicit 1.7 scopes.
     */
    protected function prepareConfigFor170(array $data) {
        if ((int)($data['version'] ?? 0) >= 170) {
            return $data;
        }

        // allowedIPs was a full bypass before 1.7. Preserve that behavior by
        // moving its entries to the field whose name now states that clearly.
        $legacyAllowedIPs = trim((string)($data['allowedIPs'] ?? ''));
        if ($legacyAllowedIPs !== '') {
            $data['ip_whitelist'] = $this->mergeRuleText(
                (string)($data['ip_whitelist'] ?? ''),
                $legacyAllowedIPs
            );
            $data['allowedIPs'] = '';
        }

        // Browser names were often placed in allowedUserAgents to work around
        // header heuristics. Preserve only that narrow compatibility behavior.
        $browserPatterns = $this->extractUnsafeBrowserAllowPatterns(
            (string)($data['allowedUserAgents'] ?? '')
        );
        if ($browserPatterns) {
            $data['compatibilityUserAgents'] = $this->mergeRuleText(
                (string)($data['compatibilityUserAgents'] ?? ''),
                implode("\n", $browserPatterns)
            );
        }

        $data['version'] = 170;
        return $data;
    }

    /**
     * Merge newline-delimited rules without duplicates.
     */
    protected function mergeRuleText($current, $additional) {
        return implode("\n", array_values(array_unique(array_merge(
            $this->parseRules((string)$current),
            $this->parseRules((string)$additional)
        ))));
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
            'block_other_bots', 'enable_stats_logging', 'enable_traffic_history',
            'disable_ajax_protection'
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
        // Check before any other security checks (unless AJAX protection is disabled)
        if (!$this->disable_ajax_protection && $this->allowTrustedModules && $this->isAllowedModuleRequest()) {
            return; // Allow trusted module AJAX - no logging, no blocking
        }
        
        $ip = $this->getRealClientIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $path = $page ? $page->url : parse_url($requestUri, PHP_URL_PATH);
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        
        // === PRIORITY 0.7: NEVER BLOCK LOGGED-IN PROCESSWIRE USERS ===
        // This check requires $ip to be resolved first (for accurate logging if enabled)
        if ($this->wire('user') && $this->wire('user')->isLoggedin()) {
            return; // Logged-in users always bypass all WireWall checks
        }
        
        // === PRIORITY 1: IP WHITELIST (ALWAYS ALLOW) ===
        if ($this->isIPWhitelisted($ip)) {
            $this->recordTrafficHistory($ip, null, null, true, 'ip-whitelist', $userAgent);
            $this->logAccess($ip, null, null, true, '', $userAgent);
            return;
        }
        
        // Get GeoIP data early (country + ASN) for whitelist checks
        $geoData = $this->getGeoData($ip);
        $country = $geoData['country'] ?? null;
        $asn = $geoData['asn'] ?? null;
        $this->currentAS = $asn;
        $this->currentCountry = $country;
        
        // === PRIORITY 2: ACTIVE TEMPORARY BAN ===
        if ($this->isIPBanned($ip)) {
            $this->blockAccess('temporary-ban', $ip, $country, $asn, $userAgent);
            return;
        }

        // === PRIORITY 2.5: URL / USER-AGENT TRIGGER RULES ===
        $triggerReason = $this->checkTriggerRules($ip, $userAgent, $requestUri);
        if ($triggerReason) {
            $this->blockAccess($triggerReason, $ip, $country, $asn, $userAgent);
            return;
        }

        // === PRIORITY 3: RATE LIMITING ===
        if ($this->rate_limit_enabled && $this->isRateLimited($ip)) {
            $this->blockAccess('rate-limit', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 4: IP BLACKLIST (ALWAYS BLOCK) ===
        if ($this->isIPBlacklisted($ip)) {
            $this->blockAccess('ip', $ip, null, null, $userAgent);
            return;
        }

        // Resolve scoped exceptions only after cheap abuse checks. This avoids
        // DNS work for already banned, triggered, rate-limited, or blacklisted
        // requests that merely spoof a crawler User-Agent.
        $botVerification = $this->verifyKnownBotIdentity($userAgent, $ip);
        $verifiedKnownBot = ($botVerification['status'] ?? '') === 'verified';
        $knownBotException = $this->isAllowedBot($userAgent, $ip, $asn, $verifiedKnownBot);
        $verifiedKnownBotException = $knownBotException && $verifiedKnownBot;
        $compatibilityException = $this->matchesCompatibilityUserAgent($userAgent);
        
        // === PRIORITY 5: JS CHALLENGE CHECK ===
        if ($this->js_challenge_enabled && !$knownBotException && !$compatibilityException) {
            // Check if suspicious AND no valid cookie
            if ($this->isSuspiciousRequest($userAgent) && !$this->verifyChallengeCookie()) {
                $this->showJSChallenge($ip, $userAgent);
                return;
            }
        }
        
        // === PRIORITY 6: VPN/PROXY/TOR DETECTION ===
        if (!$verifiedKnownBotException && $this->block_proxy_vpn_tor && $this->isProxyVPNTor($ip)) {
            $this->blockAccess('proxy-vpn-tor', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 7: DATACENTER DETECTION ===
        if (!$verifiedKnownBotException && $this->block_datacenters && $this->isDatacenter($ip, $asn)) {
            $this->blockAccess('datacenter', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 8: ASN BLOCKING ===
        if (!$verifiedKnownBotException && $asn && $this->isBlockedASN($asn)) {
            $this->blockAccess('asn-blocked', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 9: GLOBAL RULES (bots, paths, UA, referer) ===
        if ($this->checkGlobalRules($ip, $userAgent, $path, $referer, $knownBotException, $compatibilityException)) {
            $this->blockAccess('global', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 10: COUNTRY BLOCKING (blacklist/whitelist) ===
        if ($country && $this->checkCountryBlocking($country)) {
            $this->blockAccess('country', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === PRIORITY 10.5: CITY BLOCKING (blacklist/whitelist) ===
        if ($this->city_blocking_enabled && $this->geoipCityReader) {
            $cityData = $this->getCityData($ip);
            if ($cityData && $this->checkCityBlocking($cityData)) {
                $this->blockAccess('city-blocked', $ip, $country, $asn, $userAgent);
                return;
            }
        }
        
        // === PRIORITY 10.6: SUBDIVISION/REGION BLOCKING (blacklist/whitelist) ===
        if ($this->subdivision_blocking_enabled && $this->geoipCityReader) {
            $cityData = $this->getCityData($ip);
            if ($cityData && $this->checkSubdivisionBlocking($cityData)) {
                $this->blockAccess('subdivision-blocked', $ip, $country, $asn, $userAgent);
                return;
            }
        }
        
        // === PRIORITY 11: COUNTRY-SPECIFIC RULES ===
        if ($country && $this->checkCountryRules($country, $userAgent, $path, $referer)) {
            $this->blockAccess('country-rule', $ip, $country, $asn, $userAgent);
            return;
        }
        
        // === ACCESS ALLOWED ===
        $allowedReason = $verifiedKnownBotException
            ? 'verified-known-bot'
            : ($knownBotException ? 'known-bot' : ($compatibilityException ? 'compatibility-exception' : ''));
        $this->recordTrafficHistory($ip, $country, $asn, true, $allowedReason, $userAgent);
        if ($this->enable_stats_logging) {
            $this->logAccess($ip, $country, $asn, true, $allowedReason, $userAgent);
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
        
        // Window duration: 60 seconds (fixed "per minute" window matching the field label)
        $windowSeconds = 60;
        
        // Get current request count for this window
        $count = (int)$this->cacheGet($cacheKey);
        $count++;
        
        // Save incremented count, expiring at end of the window
        $this->cacheSet($cacheKey, $count, $windowSeconds);
        
        // Check if exceeded limit
        if ($count > $this->rate_limit_requests) {
            // Ban for configured duration (rate_limit_minutes = ban duration)
            $banTime = $this->rate_limit_minutes * 60;
            $this->cacheSet($banKey, true, $banTime);
            // IMPORTANT: Delete the rate limit counter so that after the ban expires
            // the first request doesn't immediately re-trigger a new ban.
            @unlink($this->getCachePath($cacheKey));
            return true;
        }
        
        return false;
    }

    /**
     * Check if an IP has an active temporary ban.
     */
    protected function isIPBanned($ip) {
        return $this->cacheGet("ban_{$ip}") ? true : false;
    }

    /**
     * Temporarily ban an IP using the shared ban cache.
     */
    protected function banIP($ip, $seconds) {
        $seconds = max(60, (int)$seconds);
        $this->cacheSet("ban_{$ip}", true, $seconds);
    }

    /**
     * Check URL/query string and User-Agent trigger rules.
     *
     * Rules match case-insensitive substrings by default. Wildcards are supported
     * with "*", and multiple alternatives may be separated with "|".
     */
    protected function checkTriggerRules($ip, $userAgent, $requestUri) {
        $matched = false;
        $matchedType = '';
        $matchedPreset = false;

        foreach ($this->getScannerPresetPatterns($this->trigger_scanner_preset) as $pattern) {
            if ($this->matchTriggerPattern($requestUri, $pattern)) {
                $matched = true;
                $matchedType = 'url-preset';
                $matchedPreset = true;
                break;
            }
        }

        if (!$matched && ($this->trigger_url_patterns ?? '')) {
            foreach ($this->parseTriggerPatterns($this->trigger_url_patterns) as $pattern) {
                if ($this->matchTriggerPattern($requestUri, $pattern)) {
                    $matched = true;
                    $matchedType = 'url';
                    break;
                }
            }
        }

        if (!$matched && ($this->trigger_user_agents ?? '')) {
            foreach ($this->parseTriggerPatterns($this->trigger_user_agents) as $pattern) {
                if ($this->matchTriggerPattern($userAgent, $pattern)) {
                    $matched = true;
                    $matchedType = 'user-agent';
                    break;
                }
            }
        }

        if (!$matched) {
            return false;
        }

        $action = $this->trigger_rule_action ?? 'strike';
        $banMinutes = max(1, (int)($this->trigger_ban_minutes ?? ($this->rate_limit_minutes ?? 60)));

        if ($matchedPreset || $action === 'block') {
            $this->banIP($ip, $banMinutes * 60);
            return "trigger-{$matchedType}";
        }

        return $this->addTriggerStrike($ip, $matchedType, $banMinutes);
    }

    /**
     * Return conservative scanner paths for the optional built-in preset.
     *
     * Preset matches are always blocked immediately rather than counted as
     * strikes because they target files that a ProcessWire public site should
     * never expose.
     */
    protected function getScannerPresetPatterns($preset) {
        if ($preset !== 'standard') {
            return [];
        }

        return [
            '/.env',
            '/.git',
            '/.aws',
            '/wp-config',
            '/xmlrpc.php',
            '/.debugbar',
            '/server/config',
            '/backup.zip',
            '/backup.sql',
            '/phpinfo',
        ];
    }

    /**
     * Add one trigger strike and return a block reason once the threshold is met.
     */
    protected function addTriggerStrike($ip, $matchedType, $banMinutes) {
        $cacheKey = "trigger_strike_{$ip}";
        $limit = max(1, (int)($this->trigger_strike_limit ?? 3));
        $windowMinutes = max(1, (int)($this->trigger_strike_window_minutes ?? 60));

        $count = (int)$this->cacheGet($cacheKey);
        $count++;

        if ($count >= $limit) {
            $this->banIP($ip, $banMinutes * 60);
            @unlink($this->getCachePath($cacheKey));
            return "trigger-{$matchedType}-strike-limit";
        }

        $this->cacheSet($cacheKey, $count, $windowMinutes * 60);

        if ($this->enable_stats_logging) {
            $this->wire('log')->save('wirewall', "TRIGGER STRIKE | {$ip} | {$matchedType} | {$count}/{$limit}");
        }

        return false;
    }

    /**
     * Parse trigger rules, allowing pipe-separated alternatives on each line.
     */
    protected function parseTriggerPatterns($text) {
        $patterns = [];
        foreach ($this->parseRules($text) as $rule) {
            foreach (explode('|', $rule) as $pattern) {
                $pattern = trim($pattern);
                if ($pattern !== '') {
                    $patterns[] = $pattern;
                }
            }
        }
        return $patterns;
    }

    /**
     * Match a trigger pattern against URL or User-Agent text.
     */
    protected function matchTriggerPattern($text, $pattern) {
        $text = (string)$text;
        $pattern = trim((string)$pattern);
        if ($pattern === '') return false;

        if (strpos($pattern, '*') !== false) {
            return $this->matchPattern($text, $pattern);
        }

        return stripos($text, $pattern) !== false;
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
        $this->recordTrafficHistory($ip, null, null, false, 'js-challenge', $userAgent);
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
        
        // Known datacenter ASN keywords — deliberately specific to avoid false positives.
        // 'cloud' and 'server' are intentionally excluded: many legitimate regional ISPs
        // and corporate networks include these words in their org names.
        $datacenterKeywords = [
            'amazon',      'aws',
            'google cloud', 'googlecloud',
            'azure',       'microsoft azure',
            'digitalocean', 'ovh',
            'hetzner',     'linode',
            'vultr',       'choopa',
            'cloudflare',  'akamai',
            'fastly',      'colocation',
            ' colo ',      'colo.',
            'datacenter',  'data center',
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
        
        // Detect if request is coming from localhost / private network.
        // Browsers on localhost do NOT send Client Hints (Sec-CH-UA) or sometimes
        // Sec-Fetch-* headers, so header-presence checks must be skipped for these IPs.
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
        $isLocalRequest = (
            $remoteAddr === '127.0.0.1' ||
            $remoteAddr === '::1' ||
            substr($remoteAddr, 0, 8) === '192.168.' ||
            substr($remoteAddr, 0, 7) === '10.0.0.' ||
            substr($remoteAddr, 0, 4) === '10.' ||
            preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $remoteAddr)
        );
        
        if ($looksLikeBrowser) {
            // Real browsers ALWAYS send these headers
            $hasAcceptLanguage = !empty($_SERVER['HTTP_ACCEPT_LANGUAGE']);
            $hasAcceptEncoding = !empty($_SERVER['HTTP_ACCEPT_ENCODING']);
            $hasAccept = !empty($_SERVER['HTTP_ACCEPT']);
            
            // Check if it's Firefox
            $isFirefox = (stripos($userAgent, 'Firefox') !== false && stripos($userAgent, 'Chrome') === false);
            
            // Missing critical browser headers = FAKE (but be lenient with Firefox)
            if (!$isFirefox) {
                // Strict check for Chrome, Edge, Safari
                if (!$hasAcceptLanguage || !$hasAcceptEncoding || !$hasAccept) {
                    return true;
                }
            } else {
                // Lenient check for Firefox (only Accept is required)
                if (!$hasAccept) {
                    return true;
                }
            }
            
            // Suspicious Accept header (wget/curl send only */*)
            // Skip this check for Firefox (privacy extensions may modify Accept)
            if (!$isFirefox && $hasAccept && $_SERVER['HTTP_ACCEPT'] === '*/*') {
                return true;
            }
            
            // Check Chrome version for outdated/automation detection
            if (preg_match('/Chrome\/(\d+)\.(\d+)/', $userAgent, $matches)) {
                $chromeVersion = (int)$matches[1];
                $chromeMinor = (int)$matches[2];
                
                // Chrome 90+ should have Sec-CH-UA header
                // Skip this check for localhost — browsers don't send Client Hints to http://localhost
                if ($chromeVersion >= 90 && empty($_SERVER['HTTP_SEC_CH_UA']) && !$isLocalRequest) {
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
                
                if ($isRealChrome && (int)$matches[1] >= 76 && (!$hasSecFetchSite || !$hasSecFetchMode) && !$isLocalRequest) {
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
    protected function checkGlobalRules($ip, $userAgent, $path, $referer, $knownBotException = false, $compatibilityException = false) {
        // 1. Block bad bots (scrapers, scanners)
        if (!$knownBotException && $this->block_bad_bots) {
            $badBots = $this->getBadBotPatterns();
            foreach ($badBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 2. Block search engine bots
        if (!$knownBotException && $this->block_search_bots) {
            $searchBots = $this->getSearchBotPatterns();
            foreach ($searchBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 3. Block AI bots
        if (!$knownBotException && $this->block_ai_bots) {
            $aiBots = $this->getAIBotPatterns();
            foreach ($aiBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 4. Block other bots (custom list)
        if (!$knownBotException && $this->block_other_bots && $this->other_bots_list) {
            $otherBots = $this->parseRules($this->other_bots_list);
            foreach ($otherBots as $pattern) {
                if (stripos($userAgent, $pattern) !== false) {
                    return true;
                }
            }
        }
        
        // 5. Detect fake browser
        if (!$knownBotException && !$compatibilityException && $this->detectFakeBrowser($userAgent)) {
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
        
        // List of trusted ProcessWire module POST key patterns.
        // Intentionally narrow: only well-known PW core prefixes are listed.
        // Generic words like 'field', 'page', 'process' are omitted because
        // any attacker can craft a POST body with those keys to bypass WireWall.
        $trustedPatterns = [
            'ProcessWire',     // Core ProcessWire actions (e.g. ProcessWireAction)
            'InputfieldPage',  // Page autocomplete (specific enough)
            'bookmarks',       // FieldtypeBookmarks
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
     * Verify supported crawler identities with forward-confirmed reverse DNS.
     *
     * Successful results are cached for 24 hours; failures use a short cache
     * so temporary DNS problems do not cause a lookup on every request.
     */
    protected function verifyKnownBotIdentity($userAgent, $ip) {
        $provider = $this->getVerifiableBotProvider($userAgent);
        if (!$provider || !filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->currentBotVerification = null;
            return [];
        }

        $cacheKey = 'botverify_' . $provider['name'] . '_' . sha1($ip);
        $cached = $this->cacheGet($cacheKey);
        if (is_array($cached) && isset($cached['status'])) {
            $cached['cached'] = true;
            $this->currentBotVerification = $cached;
            return $cached;
        }

        $hostname = strtolower(rtrim((string)$this->resolveReverseDNS($ip), '.'));
        $validSuffix = false;
        foreach ($provider['suffixes'] as $suffix) {
            if ($hostname === ltrim($suffix, '.') || str_ends_with($hostname, $suffix)) {
                $validSuffix = true;
                break;
            }
        }

        $forwardConfirmed = false;
        if ($validSuffix) {
            foreach ($this->resolveForwardDNS($hostname) as $resolvedIP) {
                if ($this->ipAddressesEqual($ip, $resolvedIP)) {
                    $forwardConfirmed = true;
                    break;
                }
            }
        }

        $result = [
            'provider' => $provider['name'],
            'status' => ($validSuffix && $forwardConfirmed) ? 'verified' : 'unverified',
            'cached' => false,
        ];
        $this->cacheSet($cacheKey, $result, $result['status'] === 'verified' ? 86400 : 3600);
        $this->currentBotVerification = $result;
        return $result;
    }

    /**
     * Return verification rules for crawler User-Agents with official DNS guidance.
     */
    protected function getVerifiableBotProvider($userAgent) {
        if (preg_match('/googlebot|google-inspectiontool/i', (string)$userAgent)) {
            return [
                'name' => 'google',
                'suffixes' => ['.googlebot.com', '.google.com', '.googleusercontent.com'],
            ];
        }
        if (preg_match('/bingbot|msnbot|adidxbot/i', (string)$userAgent)) {
            return [
                'name' => 'bing',
                'suffixes' => ['.search.msn.com'],
            ];
        }
        return null;
    }

    /**
     * DNS methods are isolated so verification behavior can be regression-tested.
     */
    protected function resolveReverseDNS($ip) {
        return @gethostbyaddr($ip);
    }

    protected function resolveForwardDNS($hostname) {
        $addresses = @gethostbynamel($hostname) ?: [];
        if (function_exists('dns_get_record') && defined('DNS_AAAA')) {
            $records = @dns_get_record($hostname, DNS_AAAA);
            if (is_array($records)) {
                foreach ($records as $record) {
                    if (!empty($record['ipv6'])) {
                        $addresses[] = $record['ipv6'];
                    }
                }
            }
        }
        return array_values(array_unique($addresses));
    }

    protected function ipAddressesEqual($first, $second) {
        $firstBinary = @inet_pton((string)$first);
        $secondBinary = @inet_pton((string)$second);
        return $firstBinary !== false && $secondBinary !== false && hash_equals($firstBinary, $secondBinary);
    }

    /**
     * Check whether a request matches a known-bot exception.
     *
     * A match skips bot-category and fake-browser heuristics only. It does not
     * bypass bans, triggers, rate limiting, network checks, geo rules, or
     * explicit path/User-Agent/referer blocks.
     */
    protected function isAllowedBot($userAgent, $ip, $asn = null, $verifiedIdentity = false) {
        // Check allowed User-Agents
        if ($this->allowedUserAgents) {
            $allowedAgents = $this->parseRules($this->allowedUserAgents);
            foreach ($allowedAgents as $pattern) {
                $pattern = trim($pattern);
                if (empty($pattern)) continue;
                if ($this->isUnsafeBrowserAllowPattern($pattern)) continue;
                
                // Case-insensitive match
                if (stripos($userAgent, $pattern) !== false) {
                    // Google/Bing crawler identities must pass forward-confirmed
                    // reverse DNS before a UA-only rule receives any exception.
                    if ($this->getVerifiableBotProvider($userAgent) && !$verifiedIdentity) {
                        continue;
                    }
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
     * Prevent common browser names from becoming full-firewall bypass rules.
     *
     * These values are sometimes added as compatibility workarounds for browser
     * header quirks, but a browser family name is trivial for bots to spoof.
     */
    protected function isUnsafeBrowserAllowPattern($pattern) {
        $pattern = strtolower(trim((string)$pattern));
        return in_array($pattern, [
            'firefox',
            'brave',
            'chrome',
            'chromium',
            'safari',
            'edge',
            'edg',
            'opera',
            'opr',
        ], true);
    }

    /**
     * Extract common browser-family tokens from legacy allowlist text.
     */
    protected function extractUnsafeBrowserAllowPatterns($text) {
        $patterns = [];
        foreach ($this->parseRules((string)$text) as $line) {
            foreach (preg_split('/[\s,;|]+/', $line, -1, PREG_SPLIT_NO_EMPTY) as $token) {
                if ($this->isUnsafeBrowserAllowPattern($token)) {
                    $patterns[] = trim($token);
                }
            }
        }
        return array_values(array_unique($patterns));
    }

    /**
     * Check browser/client compatibility exceptions.
     *
     * These exceptions only skip fake-browser and JavaScript-challenge
     * heuristics. Common browser names left in the legacy allowedUserAgents
     * field are automatically treated with this narrower scope.
     */
    protected function matchesCompatibilityUserAgent($userAgent) {
        $patterns = $this->parseRules($this->compatibilityUserAgents);
        $patterns = array_merge(
            $patterns,
            $this->extractUnsafeBrowserAllowPatterns($this->allowedUserAgents)
        );

        foreach (array_unique($patterns) as $pattern) {
            $pattern = trim((string)$pattern);
            if ($pattern !== '' && stripos($userAgent, $pattern) !== false) {
                return true;
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
            $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/i';
            return preg_match($regex, $text) === 1;
        }
        
        return false;
    }

    /**
     * Get real client IP (Cloudflare/Incapsula/Sucuri compatible)
     *
     * Security: proxy headers (CF-Connecting-IP, X-Forwarded-For, etc.) can be
     * spoofed by any client if the server is reached directly. Each header is only
     * trusted when REMOTE_ADDR belongs to the corresponding CDN/proxy IP range,
     * or when the admin has explicitly opted in via $config->wireWallTrustProxy.
     */
    protected function getRealClientIP() {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Admin explicit opt-in (config.php: $config->wireWallTrustProxy = true)
        $config = $this->wire('config');
        if (!empty($config->wireWallTrustProxy)) {
            // Honor custom header if specified
            $customHeader = $config->wireWallProxyHeader ?? null;
            if ($customHeader && !empty($_SERVER[$customHeader])) {
                return $this->sanitizeIP($_SERVER[$customHeader]);
            }
            // Fall through to standard header chain below
        }

        // Cloudflare — only trust CF-Connecting-IP when request arrives from a Cloudflare IP.
        // Ranges: https://www.cloudflare.com/ips/
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && $this->isCloudflareIP($remoteAddr)) {
            return $this->sanitizeIP($_SERVER['HTTP_CF_CONNECTING_IP']);
        }

        // Incapsula (Imperva) — their egress ranges are 199.83.128.0/21,
        // 198.143.32.0/21, 149.126.72.0/21, 103.28.248.0/22, 45.64.64.0/22,
        // 185.11.124.0/22, 192.230.64.0/18. Trust only from those ranges.
        if (!empty($_SERVER['HTTP_INCAP_CLIENT_IP']) && $this->isIncapsulaIP($remoteAddr)) {
            return $this->sanitizeIP($_SERVER['HTTP_INCAP_CLIENT_IP']);
        }

        // Sucuri — trust only when REMOTE_ADDR is a Sucuri proxy IP.
        if (!empty($_SERVER['HTTP_X_SUCURI_CLIENTIP']) && $this->isSucuriIP($remoteAddr)) {
            return $this->sanitizeIP($_SERVER['HTTP_X_SUCURI_CLIENTIP']);
        }

        // Standard X-Forwarded-For — only trust when explicitly opted in via
        // $config->wireWallTrustProxy, handled above. Here we skip it to
        // prevent trivial spoofing on direct-connect servers.

        // X-Real-IP — same: skip unless trust proxy is active.

        // Direct connection — the only value we can always trust.
        return $remoteAddr;
    }

    /**
     * Sanitize an IP string extracted from a header (strip port, take first value)
     */
    protected function sanitizeIP($raw) {
        // X-Forwarded-For may be a comma-separated list; take leftmost
        if (strpos($raw, ',') !== false) {
            $raw = trim(explode(',', $raw)[0]);
        }
        // Strip IPv6-mapped IPv4 prefix
        if (strpos($raw, '::ffff:') === 0) {
            $raw = substr($raw, 7);
        }
        // Strip port from IPv4 (host:port)
        if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$/', $raw, $m)) {
            return $m[1];
        }
        return $raw;
    }

    /**
     * Check if IP belongs to Cloudflare's published ranges (IPv4 + IPv6)
     * Source: https://www.cloudflare.com/ips/
     */
    protected function isCloudflareIP($ip) {
        $ipv4Ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22',   '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15',  '104.16.0.0/13',
            '104.24.0.0/14',   '172.64.0.0/13',   '131.0.72.0/22',
        ];
        $ipv6Ranges = [
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
            '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];
        $ranges = (strpos($ip, ':') !== false) ? $ipv6Ranges : $ipv4Ranges;
        foreach ($ranges as $cidr) {
            if ($this->matchCIDR($ip, $cidr)) return true;
        }
        return false;
    }

    /**
     * Check if IP belongs to Incapsula/Imperva proxy ranges
     */
    protected function isIncapsulaIP($ip) {
        $ranges = [
            '199.83.128.0/21', '198.143.32.0/21', '149.126.72.0/21',
            '103.28.248.0/22', '45.64.64.0/22',   '185.11.124.0/22',
            '192.230.64.0/18', '107.154.0.0/16',   '45.60.0.0/16',
        ];
        foreach ($ranges as $cidr) {
            if ($this->matchCIDR($ip, $cidr)) return true;
        }
        return false;
    }

    /**
     * Check if IP belongs to Sucuri proxy ranges
     */
    protected function isSucuriIP($ip) {
        $ranges = [
            '192.88.134.0/23', '185.93.228.0/22', '66.248.200.0/22',
            '208.109.0.0/22',
        ];
        foreach ($ranges as $cidr) {
            if ($this->matchCIDR($ip, $cidr)) return true;
        }
        return false;
    }

    /**
     * Block access and show block page/redirect/404
     */
    protected function blockAccess($reason, $ip, $country, $asn, $userAgent = '') {
        $this->recordTrafficHistory($ip, $country, $asn, false, $reason, $userAgent);
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

        if ($this->block_action === 'bare_404') {
            $this->sendBareBlockResponse(404);
        }

        if ($this->block_action === 'bare_410') {
            $this->sendBareBlockResponse(410);
        }
        
        // Silent 404 mode — serve ProcessWire's native 404 page
        if ($this->block_action === 'silent_404') {
            $wire = $this->wire();
            // Point ProcessWire to the 404 page and let it render normally
            $page404 = $wire->pages->get($wire->config->http404PageID);
            if ($page404 && $page404->id) {
                $wire->page = $page404;
                header('HTTP/1.1 404 Not Found');
                // Allow ProcessPageView::execute to continue with the 404 page
                return;
            }
            // Fallback if no 404 page configured
            header('HTTP/1.1 404 Not Found');
            header('Content-Type: text/html; charset=utf-8');
            echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>';
            exit;
        }
        
        // Show beautiful block page (default)
        $this->showBlockPage($country, $ip, $reason, $asn, $cityData);
    }

    /**
     * Return a minimal blocked response without templates, assets, or analytics.
     */
    protected function sendBareBlockResponse($statusCode) {
        $statusCode = $statusCode === 410 ? 410 : 404;
        $message = $statusCode === 410 ? '410 Gone' : '404 Not Found';

        http_response_code($statusCode);
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Robots-Tag: noindex, nofollow, noarchive');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        echo $message;
        exit;
    }

    /**
     * Show beautiful block page (WireWall 3.0 design)
     */
    protected function showBlockPage($country, $ip, $reason, $asn = null, $cityData = null) {
        http_response_code(403);
        
        $message = $this->block_message ?: 'Access from your location is currently unavailable.';
        
        // Get country name
        $countryNames = $this->getCountryNames();
        $countryName = $country ? ($countryNames[$country] ?? $country) : 'Unknown';
        
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
     * Store AI-friendly request history outside ProcessWire logs.
     *
     * Writes one JSON object per line to:
     * /site/assets/WireWall/traffic/traffic-YYYY-MM-DD.jsonl
     */
    protected function recordTrafficHistory($ip, $country, $asn, $allowed, $reason, $userAgent = '') {
        if (!($this->enable_traffic_history ?? true)) {
            return;
        }

        $dir = $this->getTrafficHistoryPath();
        if (!is_dir($dir) && !@mkdir($dir, 0755, true)) {
            return;
        }

        $this->protectTrafficHistoryDirectory($dir);

        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        $path = parse_url($requestUri, PHP_URL_PATH) ?: '';
        $query = parse_url($requestUri, PHP_URL_QUERY) ?: '';
        $host = $_SERVER['HTTP_HOST'] ?? ($this->wire('config')->httpHost ?? '');
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

        $cityData = null;
        if ($this->geoipCityReader) {
            $cityData = $this->getCityData($ip);
        }

        $record = [
            'schema' => 'wirewall_traffic_v1',
            'time' => date('c'),
            'unix_time' => time(),
            'status' => $allowed ? 'allowed' : 'blocked',
            'reason' => (string)$reason,
            'bot_verification' => $this->currentBotVerification,
            'ip' => (string)$ip,
            'country' => $country ?: null,
            'city' => $cityData['city'] ?? null,
            'region' => $cityData['region'] ?? null,
            'asn' => $asn ?: null,
            'method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'host' => (string)$host,
            'path' => $path,
            'query' => $query,
            'url' => $host ? "{$scheme}://{$host}{$requestUri}" : $requestUri,
            'referer' => $_SERVER['HTTP_REFERER'] ?? '',
            'user_agent' => (string)$userAgent,
            'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'sec_fetch_site' => $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '',
            'sec_fetch_mode' => $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '',
            'x_requested_with' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '',
            'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
            'forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
        ];

        $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            return;
        }

        $file = $dir . 'traffic-' . date('Y-m-d') . '.jsonl';
        @file_put_contents($file, $json . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * Prevent direct web reads from the traffic history directory when possible.
     */
    protected function protectTrafficHistoryDirectory($dir) {
        $htaccess = $dir . '.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n", LOCK_EX);
        }

        $index = $dir . 'index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php namespace ProcessWire; http_response_code(403); exit;\n", LOCK_EX);
        }
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
                foreach (scandir($cachePath) as $file) {
                    if ($file == '.' || $file == '..') continue;
                    $shouldDelete = (
                        $type === 'all' ||
                        ($type === 'ratelimit' && strpos($file, 'ratelimit_') === 0) ||
                        ($type === 'ban'       && strpos($file, 'ban_')       === 0) ||
                        ($type === 'proxy'     && strpos($file, 'proxy_')     === 0) ||
                        ($type === 'geo'       && strpos($file, 'geo_')       === 0)
                    );
                    if ($shouldDelete && is_file($cachePath . $file)) {
                        @unlink($cachePath . $file);
                        $cleared++;
                    }
                }
            }
            wire('session')->message("Cleared {$cleared} cache files ({$type})");
        }

        // =====================================================================
        // 1. GENERAL
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'General';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'shield';

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'enabled';
        $f->label = 'Enable WireWall';
        $f->description = 'Turn on the firewall protection';
        $f->checked = isset($data['enabled']) && $data['enabled'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'enable_stats_logging';
        $f->label = 'Enable Logging';
        $f->description = 'Log all blocked and allowed requests';
        $f->notes = 'View logs: Admin → Setup → Logs → wirewall';
        $f->checked = isset($data['enable_stats_logging']) && $data['enable_stats_logging'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'enable_traffic_history';
        $f->label = 'Save Traffic History';
        $f->description = 'Save allowed and blocked public requests as daily JSONL files for later AI analysis.';
        $f->notes = 'Stored outside ProcessWire logs: /site/assets/WireWall/traffic/traffic-YYYY-MM-DD.jsonl';
        $f->checked = (!isset($data['enable_traffic_history']) || $data['enable_traffic_history']) ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldRadios');
        $f->name = 'block_action';
        $f->label = 'Block Action';
        $f->addOption('show_page', 'Show block page');
        $f->addOption('silent_404', 'Silent 404 (stealth mode)');
        $f->addOption('bare_404', 'Bare 404 (no template or analytics)');
        $f->addOption('bare_410', 'Bare 410 Gone (no template or analytics)');
        $f->addOption('redirect', 'Redirect to URL');
        $f->value = $data['block_action'] ?? 'show_page';
        $f->notes = 'Bare responses are recommended for scanner and bot blocks because they contain no HTML, JavaScript, assets, or analytics.';
        $fieldset->add($f);

        $f = $modules->get('InputfieldText');
        $f->name = 'redirect_url';
        $f->label = 'Redirect URL';
        $f->value = $data['redirect_url'] ?? '';
        $f->showIf = 'block_action=redirect';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'block_message';
        $f->label = 'Block Page Message';
        $f->value = $data['block_message'] ?? 'Access from your location is currently unavailable.';
        $f->rows = 2;
        $f->showIf = 'block_action=show_page';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $inputfields->add($fieldset);
        
        // =====================================================================
        // 2. RATE LIMITING
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Rate Limiting';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'tachometer';

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'rate_limit_enabled';
        $f->label = 'Enable Rate Limiting';
        $f->description = 'Limit requests per minute per IP address';
        $f->checked = isset($data['rate_limit_enabled']) && $data['rate_limit_enabled'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldInteger');
        $f->name = 'rate_limit_requests';
        $f->label = 'Requests Per Minute';
        $f->description = 'Maximum requests allowed in the fixed 60-second counting window for one IP.';
        $f->value = $data['rate_limit_requests'] ?? 10;
        $f->min = 1;
        $f->max = 1000;
        $f->showIf = 'rate_limit_enabled=1';
        $fieldset->add($f);

        $f = $modules->get('InputfieldInteger');
        $f->name = 'rate_limit_minutes';
        $f->label = 'Ban Duration (minutes)';
        $f->description = 'How long to ban an IP after it exceeds Requests Per Minute. This does not change the 60-second counting window.';
        $f->value = $data['rate_limit_minutes'] ?? 60;
        $f->min = 1;
        $f->max = 1440;
        $f->showIf = 'rate_limit_enabled=1';
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 3. BOT PROTECTION
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Bot Protection';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'ban';

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_bad_bots';
        $f->label = 'Block Bad Bots';
        $f->description = 'Block scrapers, scanners, and malicious tools (wget, curl, scrapy, nmap, nikto, sqlmap, semrush, ahrefs…)';
        $f->checked = isset($data['block_bad_bots']) && $data['block_bad_bots'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_ai_bots';
        $f->label = 'Block AI Training Bots';
        $f->description = 'Block AI crawlers that train on your content (GPTBot, ClaudeBot, GrokBot, Perplexity, Google-Extended…)';
        $f->checked = isset($data['block_ai_bots']) && $data['block_ai_bots'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_search_bots';
        $f->label = 'Block Search Engine Bots';
        $f->description = 'Block Googlebot, Bingbot, Yandex, Baidu, etc.';
        $f->notes = '⚠️ This will prevent search engine indexing.';
        $f->checked = isset($data['block_search_bots']) && $data['block_search_bots'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'js_challenge_enabled';
        $f->label = 'JavaScript Challenge';
        $f->description = 'Show a JS challenge to suspicious requests (headless browsers, missing UA). Real browsers pass automatically.';
        $f->checked = isset($data['js_challenge_enabled']) && $data['js_challenge_enabled'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_other_bots';
        $f->label = 'Custom Bot Patterns';
        $f->description = 'Block bots matching your custom User-Agent list below';
        $f->checked = isset($data['block_other_bots']) && $data['block_other_bots'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'other_bots_list';
        $f->label = 'Custom Bot Pattern List';
        $f->description = 'User-Agent substrings to block (one per line)';
        $f->rows = 4;
        $f->value = $data['other_bots_list'] ?? '';
        $f->showIf = 'block_other_bots=1';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 4. VPN / PROXY / DATACENTER
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'VPN / Proxy / Datacenter';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'globe';

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_proxy_vpn_tor';
        $f->label = 'Block VPN / Proxy / Tor';
        $f->description = 'Detect and block VPN, proxy servers, and Tor exit nodes via ip-api.com → ipinfo.io → ipapi.co';
        $f->checked = isset($data['block_proxy_vpn_tor']) && $data['block_proxy_vpn_tor'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'block_datacenters';
        $f->label = 'Block Datacenters';
        $f->description = 'Block traffic from AWS, Google Cloud, DigitalOcean, OVH, Hetzner, Akamai, Cloudflare, etc.';
        $f->checked = isset($data['block_datacenters']) && $data['block_datacenters'] ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'block_asns';
        $f->label = 'Blocked ASNs';
        $f->description = 'ASN numbers or organisation names to block (one per line). Example: AS16509 or Amazon or 16509';
        $f->rows = 4;
        $f->value = $data['block_asns'] ?? '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 5. GEO BLOCKING
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Geo Blocking';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'map-marker';

        // MaxMind status inline
        $dataPath  = wire('config')->paths->assets . 'WireWall/';
        $geoipPath = $dataPath . 'geoip/';
        $hasCountryDb = file_exists($geoipPath . 'GeoLite2-Country.mmdb');
        $hasAsnDb     = file_exists($geoipPath . 'GeoLite2-ASN.mmdb');
        $hasCityDb    = file_exists($geoipPath . 'GeoLite2-City.mmdb');
        $hasComposer  = file_exists($dataPath . 'vendor/autoload.php');
        $maxmindOk    = $hasCountryDb && $hasAsnDb && $hasComposer;

        if ($maxmindOk) {
            $cityNote = $hasCityDb ? ' + City' : ' (City DB not installed — city/subdivision blocking unavailable)';
            $statusHtml = "<p style='color:#10b981;margin:0 0 12px'>✅ MaxMind GeoLite2 active — Country + ASN{$cityNote}.</p>";
        } else {
            $missing = [];
            if (!$hasCountryDb) $missing[] = 'GeoLite2-Country.mmdb';
            if (!$hasAsnDb)     $missing[] = 'GeoLite2-ASN.mmdb';
            if (!$hasComposer)  $missing[] = 'composer dependencies';
            $statusHtml = "<p style='color:#f59e0b;margin:0 0 12px'>⚠️ MaxMind not detected (missing: " . implode(', ', $missing) . "). Using ip-api.com fallback. <a href='https://www.maxmind.com/en/geolite2/signup' target='_blank'>Install MaxMind</a> for better performance.</p>";
        }

        $f = $modules->get('InputfieldMarkup');
        $f->value = $statusHtml;
        $fieldset->add($f);

        // Country
        $f = $modules->get('InputfieldRadios');
        $f->name = 'country_mode';
        $f->label = 'Country Mode';
        $f->addOption('blacklist', 'Blacklist — block selected countries');
        $f->addOption('whitelist', 'Whitelist — allow only selected countries');
        $f->value = $data['country_mode'] ?? 'blacklist';
        $fieldset->add($f);

        $f = $modules->get('InputfieldAsmSelect');
        $f->name = 'blocked_countries';
        $f->label = 'Countries';
        $f->description = 'Select countries for the mode above';
        foreach (self::getCountryList() as $code => $name) {
            $f->addOption($code, "{$name} ({$code})");
        }
        $value = $data['blocked_countries'] ?? '';
        if (is_string($value) && !empty($value)) {
            $lines = preg_split('/[\r\n,]+/', $value);
            $value = array_filter(array_map('trim', $lines));
        }
        $f->value = is_array($value) ? $value : [];
        $fieldset->add($f);

        // City blocking (only if City DB available)
        if ($hasCityDb) {
            $f = $modules->get('InputfieldCheckbox');
            $f->name = 'city_blocking_enabled';
            $f->label = 'Enable City Blocking';
            $f->description = 'Block or allow by city name (requires GeoLite2-City)';
            $f->checked = isset($data['city_blocking_enabled']) && $data['city_blocking_enabled'] ? 'checked' : '';
            $fieldset->add($f);

            $f = $modules->get('InputfieldRadios');
            $f->name = 'city_mode';
            $f->label = 'City Mode';
            $f->addOption('blacklist', 'Blacklist');
            $f->addOption('whitelist', 'Whitelist');
            $f->value = $data['city_mode'] ?? 'blacklist';
            $f->showIf = 'city_blocking_enabled=1';
            $fieldset->add($f);

            $f = $modules->get('InputfieldTextarea');
            $f->name = 'blocked_cities';
            $f->label = 'Cities (one per line)';
            $f->description = 'Format: "City" or "City, CC" — e.g. Philadelphia, US';
            $f->rows = 5;
            $f->value = $data['blocked_cities'] ?? '';
            $f->showIf = 'city_blocking_enabled=1';
            $f->collapsed = Inputfield::collapsedBlank;
            $fieldset->add($f);

            // Subdivision blocking
            $f = $modules->get('InputfieldCheckbox');
            $f->name = 'subdivision_blocking_enabled';
            $f->label = 'Enable Subdivision / Region Blocking';
            $f->description = 'Block or allow by state, province, oblast (requires GeoLite2-City)';
            $f->checked = isset($data['subdivision_blocking_enabled']) && $data['subdivision_blocking_enabled'] ? 'checked' : '';
            $fieldset->add($f);

            $f = $modules->get('InputfieldRadios');
            $f->name = 'subdivision_mode';
            $f->label = 'Subdivision Mode';
            $f->addOption('blacklist', 'Blacklist');
            $f->addOption('whitelist', 'Whitelist');
            $f->value = $data['subdivision_mode'] ?? 'blacklist';
            $f->showIf = 'subdivision_blocking_enabled=1';
            $fieldset->add($f);

            $f = $modules->get('InputfieldTextarea');
            $f->name = 'blocked_subdivisions';
            $f->label = 'Subdivisions (one per line)';
            $f->description = 'Format: "Subdivision" or "Subdivision, CC" — e.g. Pennsylvania, US';
            $f->rows = 5;
            $f->value = $data['blocked_subdivisions'] ?? '';
            $f->showIf = 'subdivision_blocking_enabled=1';
            $f->collapsed = Inputfield::collapsedBlank;
            $fieldset->add($f);
        } else {
            $f = $modules->get('InputfieldMarkup');
            $f->value = "<p style='color:#9ca3af;font-style:italic'>City and subdivision blocking require GeoLite2-City.mmdb. <a href='https://www.maxmind.com/en/accounts/current/geoip/downloads' target='_blank'>Download from MaxMind</a> and place in <code>{$geoipPath}</code>.</p>";
            $fieldset->add($f);
        }

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'country_rules';
        $f->label = 'Country-Specific Rules';
        $f->description = 'Apply path / UA / referer rules per country. Format: CC:action:pattern (one per line). Actions: block_path, block_agent, block_referer.';
        $f->notes = "RU:block_path:/admin/*\nCN:block_agent:BadBot\nUS:block_referer:spam.com";
        $f->rows = 5;
        $f->value = $data['country_rules'] ?? '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 6. IP CONTROL
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'IP Control';
        $fieldset->collapsed = Inputfield::collapsedNo;
        $fieldset->icon = 'lock';

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'ip_whitelist';
        $f->label = 'IP Whitelist (Always Allow)';
        $f->description = 'IPs that bypass all blocking rules. Supports exact, wildcard (*), and CIDR notation. One per line.';
        $f->rows = 4;
        $f->value = $data['ip_whitelist'] ?? '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'ip_blacklist';
        $f->label = 'IP Blacklist (Always Block)';
        $f->description = 'IPs that are always blocked. Supports exact, wildcard (*), and CIDR notation. One per line.';
        $f->rows = 4;
        $f->value = $data['ip_blacklist'] ?? '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 7. EXCEPTIONS (scoped known bots and compatibility rules)
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Exceptions';
        $fieldset->description = 'Known bots skip bot/fake-browser heuristics only. Use IP Whitelist above for a deliberate full-firewall bypass.';
        $fieldset->collapsed = Inputfield::collapsedYes;
        $fieldset->icon = 'check-square';

        $riskyAllowedPatterns = $this->extractUnsafeBrowserAllowPatterns(
            (string)($data['allowedUserAgents'] ?? '')
        );
        foreach ($this->parseRules($data['allowedUserAgents'] ?? '') as $pattern) {
            if (mb_strlen(trim($pattern)) < 4) {
                $riskyAllowedPatterns[] = trim($pattern);
            }
        }
        if ($riskyAllowedPatterns) {
            $safePatterns = array_map(
                fn($pattern) => $this->wire('sanitizer')->entities($pattern),
                array_unique($riskyAllowedPatterns)
            );
            $f = $modules->get('InputfieldMarkup');
            $f->label = 'Allowlist safety warning';
            $f->value = '<p class="uk-alert-warning" uk-alert>Broad or spoofable User-Agent values were found: <strong>'
                . implode(', ', $safePatterns)
                . '</strong>. Browser-family values are treated as compatibility exceptions and never as full bypass rules.</p>';
            $fieldset->add($f);
        }

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'allowedUserAgents';
        $f->label = 'Known Bot User-Agents';
        $f->description = 'User-Agent substrings that skip bot-category and fake-browser heuristics only. Bans, triggers, rate limits, network checks, geo rules, and explicit blocks still apply.';
        $f->notes = 'Examples: Googlebot, Bingbot, facebookexternalhit, Slackbot. Googlebot/Bingbot UA matches require cached forward-confirmed reverse DNS; other User-Agent text remains spoofable.';
        $f->rows = 6;
        $f->value = isset($data['allowedUserAgents']) ? $data['allowedUserAgents'] : "Googlebot\nBingbot\nYandex\nfacebookexternalhit\nSlackbot\nLinkedInBot\nTwitterbot\nWhatsApp\nApplebot";
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'allowedIPs';
        $f->label = 'Known Bot IPs';
        $f->description = 'IP addresses or CIDR ranges that skip bot-category and fake-browser heuristics only. Use IP Whitelist for a trusted full bypass.';
        $f->notes = "66.249.64.0/19 — Google Bot\n157.55.39.0/24 — Bing Bot\n77.88.5.0/24 — Yandex Bot";
        $f->rows = 6;
        $f->value = isset($data['allowedIPs']) ? $data['allowedIPs'] : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'allowedASNs';
        $f->label = 'Known Bot ASNs';
        $f->description = 'ASN numbers or organisation names that skip bot-category and fake-browser heuristics only. Network, rate, trigger, and explicit block rules still apply.';
        $f->notes = "15169 — Google\n8075 — Microsoft (Bing)\n32934 — Facebook\n13238 — Yandex\nAvoid broad cloud/datacenter ASNs unless their traffic should receive this scoped exception.";
        $f->rows = 5;
        $f->value = isset($data['allowedASNs']) ? $data['allowedASNs'] : "15169\n8075\n32934\n13238";
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'compatibilityUserAgents';
        $f->label = 'Browser / Client Compatibility Exceptions';
        $f->description = 'User-Agent substrings that skip only fake-browser and JavaScript-challenge heuristics. All other protections still apply.';
        $f->notes = 'Use only for a confirmed client-header compatibility problem. Broad browser names are spoofable and do not bypass rate limits, triggers, network checks, or explicit blocks.';
        $f->rows = 4;
        $f->value = $data['compatibilityUserAgents'] ?? '';
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 8. CUSTOM RULES (Paths / UA / Referers)
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Custom Block Rules';
        $fieldset->description = 'Block by path, User-Agent pattern, referer domain, or configurable trigger strikes';
        $fieldset->collapsed = Inputfield::collapsedYes;
        $fieldset->icon = 'filter';

        $hasCustomTriggers = trim((string)($data['trigger_url_patterns'] ?? '')) !== ''
            || trim((string)($data['trigger_user_agents'] ?? '')) !== '';
        $scannerPreset = $data['trigger_scanner_preset'] ?? 'none';
        if (!$hasCustomTriggers && $scannerPreset === 'none') {
            $f = $modules->get('InputfieldMarkup');
            $f->label = 'Trigger rules are inactive';
            $f->value = '<p class="uk-alert-warning" uk-alert>No scanner preset or custom trigger patterns are configured. Trigger action, strike, and ban settings will have no effect until at least one trigger source is enabled.</p>';
            $fieldset->add($f);
        }

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_paths';
        $f->label = 'Blocked Paths';
        $f->description = 'URL paths to block. Supports wildcards. One per line.';
        $f->notes = '/wp-admin/* or *.php or /xmlrpc.php';
        $f->rows = 4;
        $f->value = $data['blocked_paths'] ?? '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_user_agents';
        $f->label = 'Blocked User-Agents';
        $f->description = 'User-Agent substrings to block (one per line)';
        $f->rows = 4;
        $f->value = $data['blocked_user_agents'] ?? '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldSelect');
        $f->name = 'trigger_scanner_preset';
        $f->label = 'Scanner Trigger Preset';
        $f->description = 'Enable a maintained starter set for obvious secret/configuration probes such as .env, .git, wp-config, xmlrpc, backup archives, and phpinfo.';
        $f->notes = 'Standard preset matches are blocked and temporarily banned immediately, even when custom trigger action uses strike mode.';
        $f->addOption('none', 'Disabled');
        $f->addOption('standard', 'Standard scanner paths (recommended)');
        $f->value = $scannerPreset;
        $fieldset->add($f);

        $f = $modules->get('InputfieldRadios');
        $f->name = 'trigger_rule_action';
        $f->label = 'Trigger Rule Action';
        $f->description = 'Choose what happens when a URL/query or User-Agent trigger matches.';
        $f->addOption('strike', 'Add strike, then ban after threshold');
        $f->addOption('block', 'Block and ban immediately');
        $f->value = $data['trigger_rule_action'] ?? 'strike';
        $fieldset->add($f);

        $f = $modules->get('InputfieldInteger');
        $f->name = 'trigger_strike_limit';
        $f->label = 'Trigger Strike Limit';
        $f->description = 'Number of trigger matches before the IP is temporarily banned.';
        $f->value = $data['trigger_strike_limit'] ?? 3;
        $f->min = 1;
        $f->max = 1000;
        $f->showIf = 'trigger_rule_action=strike';
        $fieldset->add($f);

        $f = $modules->get('InputfieldInteger');
        $f->name = 'trigger_strike_window_minutes';
        $f->label = 'Trigger Strike Window (minutes)';
        $f->description = 'How long trigger strikes are remembered before resetting.';
        $f->value = $data['trigger_strike_window_minutes'] ?? 60;
        $f->min = 1;
        $f->max = 1440;
        $f->showIf = 'trigger_rule_action=strike';
        $fieldset->add($f);

        $f = $modules->get('InputfieldInteger');
        $f->name = 'trigger_ban_minutes';
        $f->label = 'Trigger Ban Duration (minutes)';
        $f->description = 'How long to ban an IP after an immediate trigger block or strike limit.';
        $f->value = $data['trigger_ban_minutes'] ?? ($data['rate_limit_minutes'] ?? 60);
        $f->min = 1;
        $f->max = 1440;
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'trigger_url_patterns';
        $f->label = 'URL / Query Trigger Patterns';
        $f->description = 'Case-insensitive URL and query string substrings that trigger the action above. Supports wildcards and pipe-separated alternatives.';
        $f->notes = 'Custom patterns follow Trigger Rule Action. Example: wp-json|wp-admin|wp-login|wp-content|wp-includes';
        $f->rows = 4;
        $f->value = $data['trigger_url_patterns'] ?? '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'trigger_user_agents';
        $f->label = 'User-Agent Trigger Patterns';
        $f->description = 'Case-insensitive User-Agent substrings that trigger the action above. Supports wildcards and pipe-separated alternatives.';
        $f->rows = 4;
        $f->value = $data['trigger_user_agents'] ?? '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'blocked_referers';
        $f->label = 'Blocked Referers';
        $f->description = 'Referer domains to block (one per line). Example: spam.com';
        $f->rows = 4;
        $f->value = $data['blocked_referers'] ?? '';
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 9. AJAX / API SETTINGS
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'AJAX & API Settings';
        $fieldset->collapsed = Inputfield::collapsedYes;
        $fieldset->icon = 'exchange';

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'allowTrustedModules';
        $f->label = 'Allow AJAX from trusted ProcessWire modules';
        $f->description = 'Recommended. Allows FieldtypeBookmarks, InputfieldPage, and other core modules to function correctly.';
        $f->checked = (!isset($data['allowTrustedModules']) || $data['allowTrustedModules']) ? 'checked' : '';
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'custom_trusted_paths';
        $f->label = 'Custom Trusted AJAX Paths';
        $f->description = 'Additional paths that bypass WireWall for POST AJAX requests (one per line). Default paths: /processwire/, /admin/, /ajax/';
        $f->notes = "/rockfrontend/\n/my-custom-ajax/";
        $f->rows = 4;
        $f->value = isset($data['custom_trusted_paths']) ? $data['custom_trusted_paths'] : '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $f = $modules->get('InputfieldTextarea');
        $f->name = 'custom_api_paths';
        $f->label = 'Custom API Paths (All HTTP Methods)';
        $f->description = 'Paths that bypass WireWall for all HTTP methods (one per line). Default: /api/, /api2/, /rest/. Only add paths secured by their own auth.';
        $f->notes = "/graphql/\n/webhook/";
        $f->rows = 4;
        $f->value = isset($data['custom_api_paths']) ? $data['custom_api_paths'] : '';
        $f->collapsed = Inputfield::collapsedBlank;
        $fieldset->add($f);

        $f = $modules->get('InputfieldCheckbox');
        $f->name = 'disable_ajax_protection';
        $f->label = 'Disable AJAX Protection Completely';
        $f->description = 'Last resort: all AJAX requests bypass WireWall regardless of origin.';
        $f->notes = '⚠️ Use only if AJAX issues cannot be resolved via trusted paths above.';
        $f->checked = isset($data['disable_ajax_protection']) && $data['disable_ajax_protection'] ? 'checked' : '';
        $fieldset->add($f);

        $inputfields->add($fieldset);

        // =====================================================================
        // 10. CACHE MANAGEMENT
        // =====================================================================
        $fieldset = $modules->get('InputfieldFieldset');
        $fieldset->label = 'Cache Management';
        $fieldset->collapsed = Inputfield::collapsedYes;
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

        // Hidden field: version (auto-updated on each save)
        $f = $modules->get('InputfieldHidden');
        $f->name = 'version';
        $f->value = $data['version'];
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
