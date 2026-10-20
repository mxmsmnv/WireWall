<?php namespace ProcessWire;
// Reuse the lightweight ProcessWire stubs and existing security regression cases.
require __DIR__ . '/WireWallBehaviorTest.php';
require_once dirname(__DIR__) . '/src/Intelligence/WireWallAppleRelayVerifier.php';
require_once dirname(__DIR__) . '/src/Intelligence/WireWallIpIntelligenceService.php';
class HookEvent {}

final class RelayAccessWall extends WireWall {
    public string $ip = '203.0.113.1';
    public string $gate = '';
    public string $decision = '';
    public int $externalLookups = 0;
    public int $feedLookups = 0;
    public function __construct(private string $directory, private WireWallAppleRelayVerifier $relay) {
        $this->enabled = 1; $this->block_proxy_vpn_tor = 1; $this->block_datacenters = 1;
        $this->allow_verified_apple_private_relay = 1; $this->rate_limit_enabled = 1;
    }
    public function __isset($name): bool { return $this->__get($name) !== null; }
    public function wire($name) {
        return match($name) {
            'config' => (object) ['urls' => (object) ['admin' => '/admin/'], 'cli' => false],
            'user' => new class { public function isLoggedin() { return false; } },
            default => null,
        };
    }
    public function getWireWallSettings() { return []; }
    protected function getAppleRelayVerifier(): WireWallAppleRelayVerifier { $this->feedLookups++; return $this->relay; }
    public function getOperationsStore() { return new WireWallOperationsStore($this->directory . '/operations'); }
    public function getIpIntelligenceService() { return new WireWallIpIntelligenceService('/missing-test.bin'); }
    protected function isAllowedModuleRequest() { return false; }
    protected function getRealClientIP() { return $this->ip; }
    protected function getGeoData($ip) { return ['country' => 'US', 'asn' => 'AS13335 Cloud provider']; }
    protected function isIPWhitelisted($ip) { return false; }
    protected function isIPBanned($ip) { return $this->gate === 'ban'; }
    protected function checkTriggerRules($ip, $userAgent, $requestUri) { return $this->gate === 'trigger' ? 'trigger' : null; }
    protected function isRateLimited($ip) { return $this->gate === 'rate'; }
    protected function isIPBlacklisted($ip) { return $this->gate === 'ip'; }
    protected function verifyKnownBotIdentity($userAgent, $ip) { return []; }
    protected function isProxyVPNTor($ip) { $this->externalLookups++; return true; }
    protected function isDatacenter($ip, $asn) { return true; }
    protected function isBlockedASN($asn) { return $this->gate === 'asn'; }
    protected function checkGlobalRules($ip, $userAgent, $path, $referer, $knownBotException = false, $compatibilityException = false) { return $this->gate === 'global'; }
    protected function checkCountryBlocking($country) { return $this->gate === 'country'; }
    protected function checkCountryRules($country, $userAgent, $path, $referer) { return false; }
    protected function isSuspiciousRequest($userAgent) { return $this->gate === 'challenge'; }
    protected function verifyChallengeCookie() { return false; }
    protected function showJSChallenge($ip, $userAgent = '') { $this->decision = 'challenge'; }
    protected function blockAccess($reason, $ip, $country, $asn, $userAgent = '') { $this->decision = $reason; }
    protected function recordTrafficHistory($ip, $country, $asn, $allowed, $reason, $userAgent = '') { $this->decision = $allowed ? 'allow' : $reason; }
}
$root = sys_get_temp_dir() . '/wirewall-relay-access-' . bin2hex(random_bytes(5));
mkdir($root, 0700, true);
$body = str_repeat("203.0.113.0/27,US,US-CA,Test,\n2001:db8::/64,US,US-CA,Test,\n", 60);
$relay = new WireWallAppleRelayVerifier($root . '/feed', fn() => $body);
$_SERVER['REQUEST_URI'] = '/sso/';
$_SERVER['HTTP_USER_AGENT'] = 'Safari iCloud Private Relay';
$wall = new RelayAccessWall($root, $relay);
$event = new HookEvent();
try {
    $wall->checkAccess($event);
    assertSameValue('allow', $wall->decision, 'Official range must pass proxy and automatic datacenter blocks.');
    assertSameValue(0, $wall->externalLookups, 'Verified relay must not be reclassified by external proxy providers.');
    foreach (['ban' => 'temporary-ban', 'trigger' => 'trigger', 'rate' => 'rate-limit', 'ip' => 'ip', 'asn' => 'asn-blocked', 'global' => 'global', 'country' => 'country'] as $gate => $expected) {
        $wall->gate = $gate; $wall->checkAccess($event);
        assertSameValue($expected, $wall->decision, 'Verified relay must preserve the ' . $gate . ' rule.');
    }
    $wall->js_challenge_enabled = 1; $wall->gate = 'challenge'; $wall->checkAccess($event);
    assertSameValue('challenge', $wall->decision, 'Verified relay must preserve suspicious-request challenges.');
    $wall->js_challenge_enabled = 0; $wall->gate = ''; $wall->ip = '203.0.113.32'; $wall->checkAccess($event);
    assertSameValue('proxy-class-unknown_proxy', $wall->decision, 'Spoofed Apple user agent outside ranges must remain blocked.');
    $wall->ip = '203.0.113.1'; $wall->allow_verified_apple_private_relay = 0;
    $before = $wall->feedLookups; $wall->checkAccess($event);
    assertSameValue('proxy-class-unknown_proxy', $wall->decision, 'Disabling the option must restore the original strict policy.');
    assertSameValue($before, $wall->feedLookups, 'Disabled option must not load or fetch Apple ranges.');
    $wall->allow_verified_apple_private_relay = 1; $wall->ip = '2001:db8::1'; $wall->checkAccess($event);
    assertSameValue('allow', $wall->decision, 'IPv6 official relay must follow the same access policy.');
    echo "WireWallAppleRelayAccessTest passed (14 access-policy assertions)\n";
} finally {
    $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    rmdir($root);
}
