<?php

declare(strict_types=1);

namespace ProcessWire;

class WireData {
    private array $wireDataValues = [];

    public function __get(string $name): mixed {
        return $this->wireDataValues[$name] ?? null;
    }

    public function __set(string $name, mixed $value): void {
        $this->wireDataValues[$name] = $value;
    }
}

interface Module {}
interface ConfigurableModule {}

require dirname(__DIR__) . '/WireWall.module.php';
require dirname(__DIR__) . '/src/WireWallMonitorProviderVerifier.php';
require dirname(__DIR__) . '/src/Storage/WireWallTrafficHistoryStore.php';
require dirname(__DIR__) . '/src/Support/WireWallIpMatcher.php';
require dirname(__DIR__) . '/src/Support/WireWallRuleMatcher.php';

final class TestableWireWall extends WireWall {
    private array $testCache = [];
    private array $reverseDNS = [];
    private array $forwardDNS = [];

    public function configureExceptions(
        string $knownUserAgents = '',
        string $knownIPs = '',
        string $knownASNs = '',
        string $compatibilityUserAgents = ''
    ): void {
        $this->allowedUserAgents = $knownUserAgents;
        $this->allowedIPs = $knownIPs;
        $this->allowedASNs = $knownASNs;
        $this->compatibilityUserAgents = $compatibilityUserAgents;
    }

    public function knownBot(
        string $userAgent,
        string $ip = '203.0.113.10',
        ?string $asn = null,
        bool $verifiedIdentity = false
    ): bool {
        return $this->isAllowedBot($userAgent, $ip, $asn, $verifiedIdentity);
    }

    public function compatibility(string $userAgent): bool {
        return $this->matchesCompatibilityUserAgent($userAgent);
    }

    public function scannerPatterns(string $preset): array {
        return $this->getScannerPresetPatterns($preset);
    }

    public function migrate170(array $data): array {
        return $this->prepareConfigFor170($data);
    }

    public function redact(array $data): array {
        return $this->redactSettingsForAI($data);
    }

    public function configureDNS(string $ip, string $hostname, array $forwardAddresses): void {
        $this->reverseDNS[$ip] = $hostname;
        $this->forwardDNS[$hostname] = $forwardAddresses;
    }

    public function verifyBot(string $userAgent, string $ip): array {
        return $this->verifyKnownBotIdentity($userAgent, $ip);
    }

    protected function resolveReverseDNS($ip) {
        return $this->reverseDNS[$ip] ?? $ip;
    }

    protected function resolveForwardDNS($hostname) {
        return $this->forwardDNS[$hostname] ?? [];
    }

    protected function cacheGet($key) {
        return $this->testCache[$key] ?? null;
    }

    protected function cacheSet($key, $value, $expire) {
        $this->testCache[$key] = $value;
        return true;
    }

    public function configureGlobalRules(array $settings): void {
        foreach ($settings as $name => $value) {
            $this->$name = $value;
        }
    }

    public function globalRule(
        string $userAgent,
        string $path,
        bool $knownBot = false,
        bool $compatibility = false
    ): bool {
        return $this->checkGlobalRules(
            '203.0.113.10',
            $userAgent,
            $path,
            '',
            $knownBot,
            $compatibility
        );
    }

    public function bare(int $statusCode): never {
        $this->sendBareBlockResponse($statusCode);
    }
}

function assertSameValue(mixed $expected, mixed $actual, string $message): void {
    if ($expected !== $actual) {
        fwrite(STDERR, "FAIL: {$message}\nExpected: " . var_export($expected, true)
            . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

$wirewall = new TestableWireWall();

if (($argv[1] ?? '') === '--bare-404') {
    $wirewall->bare(404);
}

if (($argv[1] ?? '') === '--bare-410') {
    $wirewall->bare(410);
}

$wirewall->configureExceptions("Googlebot\nChrome-Lighthouse\nFirefox, Brave", '', '', '');
assertSameValue(false, $wirewall->knownBot('Mozilla/5.0 Googlebot/2.1'), 'Verifiable bot UA must not be trusted before identity verification');
assertSameValue(false, $wirewall->knownBot('Mozilla/5.0 Firefox/152.0'), 'Browser family must not become a known-bot bypass');
assertSameValue(true, $wirewall->compatibility('Mozilla/5.0 Firefox/152.0'), 'Legacy browser family should migrate to compatibility scope');
assertSameValue(true, $wirewall->compatibility('Mozilla/5.0 Brave/1.80'), 'Comma-delimited legacy browser names should migrate to compatibility scope');

$googleIP = '66.249.66.1';
$googleHost = 'crawl-66-249-66-1.googlebot.com';
$wirewall->configureDNS($googleIP, $googleHost, [$googleIP]);
$googleVerification = $wirewall->verifyBot('Mozilla/5.0 Googlebot/2.1', $googleIP);
assertSameValue('verified', $googleVerification['status'], 'Googlebot should pass forward-confirmed reverse DNS');
assertSameValue(true, $wirewall->knownBot('Mozilla/5.0 Googlebot/2.1', $googleIP, null, true), 'Verified Googlebot may receive the configured known-bot exception');
$cachedGoogleVerification = $wirewall->verifyBot('Mozilla/5.0 Googlebot/2.1', $googleIP);
assertSameValue(true, $cachedGoogleVerification['cached'], 'Bot verification result should be cached');

$lighthouseIP = '74.125.212.133';
$lighthouseHost = 'google-proxy-74-125-212-133.google.com';
$wirewall->configureDNS($lighthouseIP, $lighthouseHost, [$lighthouseIP]);
$lighthouseVerification = $wirewall->verifyBot('Mozilla/5.0 Chrome/136.0 Chrome-Lighthouse', $lighthouseIP);
assertSameValue('verified', $lighthouseVerification['status'], 'Google Lighthouse should pass forward-confirmed reverse DNS');
assertSameValue(
    true,
    $wirewall->knownBot('Mozilla/5.0 Chrome/136.0 Chrome-Lighthouse', $lighthouseIP, 'AS15169 GOOGLE', true),
    'Verified Google Lighthouse may receive the configured known-bot exception'
);

$spoofedLighthouseIP = '203.0.113.56';
$spoofedLighthouseHost = 'google-proxy.attacker.example';
$wirewall->configureDNS($spoofedLighthouseIP, $spoofedLighthouseHost, [$spoofedLighthouseIP]);
$spoofedLighthouseVerification = $wirewall->verifyBot(
    'Mozilla/5.0 Chrome/136.0 Chrome-Lighthouse',
    $spoofedLighthouseIP
);
assertSameValue(
    'unverified',
    $spoofedLighthouseVerification['status'],
    'A spoofed Lighthouse User-Agent outside Google DNS must fail'
);

$spoofedIP = '203.0.113.55';
$spoofedHost = 'crawl.googlebot.com.attacker.example';
$wirewall->configureDNS($spoofedIP, $spoofedHost, [$spoofedIP]);
$spoofedVerification = $wirewall->verifyBot('Mozilla/5.0 Googlebot/2.1', $spoofedIP);
assertSameValue('unverified', $spoofedVerification['status'], 'A hostname containing but not ending in the official domain must fail');

$bingIP = '157.55.39.1';
$bingHost = 'msnbot-157-55-39-1.search.msn.com';
$wirewall->configureDNS($bingIP, $bingHost, [$bingIP]);
$bingVerification = $wirewall->verifyBot('Mozilla/5.0 bingbot/2.0', $bingIP);
assertSameValue('verified', $bingVerification['status'], 'Bingbot should pass forward-confirmed reverse DNS');

$migrated = $wirewall->migrate170([
    'version' => 160,
    'ip_whitelist' => '192.0.2.10',
    'allowedIPs' => "198.51.100.0/24\n192.0.2.10",
    'allowedUserAgents' => 'Firefox, Brave',
]);
assertSameValue(1110, $migrated['version'], 'Migration should record the current WireWall module version');
assertSameValue('', $migrated['allowedIPs'], 'Legacy full-bypass IPs should leave the scoped known-bot field');
assertSameValue("192.0.2.10\n198.51.100.0/24", $migrated['ip_whitelist'], 'Legacy full-bypass IPs should move to explicit whitelist without duplicates');
assertSameValue("Firefox\nBrave", $migrated['compatibilityUserAgents'], 'Legacy browser names should move to compatibility exceptions');

$redacted = $wirewall->redact([
    'ip_whitelist' => '192.0.2.10',
    'api_key' => 'sensitive',
    'provider' => ['accessToken' => 'sensitive-too', 'enabled' => 1],
]);
assertSameValue('192.0.2.10', $redacted['ip_whitelist'], 'Operational allow/block rules should remain useful in AI exports');
assertSameValue('[REDACTED]', $redacted['api_key'], 'API keys must be redacted from AI exports');
assertSameValue('[REDACTED]', $redacted['provider']['accessToken'], 'Nested token-like values must be redacted');

assertSameValue([], $wirewall->scannerPatterns('none'), 'Disabled scanner preset must add no rules');
$scannerPatterns = $wirewall->scannerPatterns('standard');
assertSameValue(true, in_array('/.env', $scannerPatterns, true), 'Standard scanner preset must protect .env');
assertSameValue(true, in_array('/wp-config', $scannerPatterns, true), 'Standard scanner preset must protect wp-config');

$wirewall->configureGlobalRules([
    'block_bad_bots' => 0,
    'block_search_bots' => 1,
    'block_ai_bots' => 0,
    'block_other_bots' => 0,
    'other_bots_list' => '',
    'blocked_paths' => '',
    'blocked_user_agents' => '',
    'blocked_referers' => '',
]);
assertSameValue(false, $wirewall->globalRule('Googlebot/2.1', '/', true), 'Known bot should skip bot-category rules');

$wirewall->configureGlobalRules(['blocked_paths' => '/private/*']);
assertSameValue(true, $wirewall->globalRule('Googlebot/2.1', '/private/report', true), 'Known bot must still obey explicit path blocks');

$feedResponses = [
    'https://my.pingdom.com/probes/ipv4' => "198.51.100.10\n203.0.113.20\n",
    'https://my.pingdom.com/probes/ipv6' => "2001:db8::10\n",
    'https://my.pingdom.com/probes/feed' => '<pingdom:ip>203.0.113.21</pingdom:ip>',
    'https://ip-ranges.datadoghq.com/synthetics.json' => '{"synthetics":{"prefixes_ipv4":["192.0.2.0/24"],"prefixes_ipv6":["2001:db8:2::/48"]}}',
];
$feedCache = [];
$verifier = new WireWallMonitorProviderVerifier(
    fn($url) => $feedResponses[$url] ?? '',
    function($key) use (&$feedCache) {
        return $feedCache[$key] ?? null;
    },
    function($key, $value, $expire) use (&$feedCache) {
        $feedCache[$key] = $value;
        return true;
    },
    fn($ip, $pattern) => $ip === $pattern
        || ($pattern === '192.0.2.0/24' && str_starts_with($ip, '192.0.2.'))
        || ($pattern === '2001:db8:2::/48' && str_starts_with($ip, '2001:db8:2:'))
);
$pingdomProvider = $verifier->getProviderForUserAgent('Pingdom.com_bot_version_1.4');
assertSameValue('pingdom', $pingdomProvider['name'], 'Pingdom User-Agent should map to the Pingdom provider');
$pingdomVerification = $verifier->verify($pingdomProvider, '198.51.100.10');
assertSameValue('verified', $pingdomVerification['status'], 'Pingdom IP from the official feed should verify');
$datadogProvider = $verifier->getProviderForUserAgent('DatadogSynthetics/1.0');
assertSameValue('datadog-synthetics', $datadogProvider['name'], 'Datadog Synthetics User-Agent should map to the Datadog provider');
$datadogVerification = $verifier->verify($datadogProvider, '192.0.2.42');
assertSameValue('verified', $datadogVerification['status'], 'Datadog CIDR from the official feed should verify');
$datadogCachedVerification = $verifier->verify($datadogProvider, '192.0.2.42');
assertSameValue(true, $datadogCachedVerification['cached'], 'Monitor provider verification should be cached');

$tempRoot = sys_get_temp_dir() . '/wirewall-store-test-' . bin2hex(random_bytes(4));
$siteRoot = $tempRoot . '/site/public/';
$assetsRoot = $siteRoot . 'site/assets/';
mkdir($assetsRoot, 0777, true);
$warnings = [];
$store = new WireWallTrafficHistoryStore(
    $siteRoot,
    $assetsRoot,
    'relative-private',
    function($message) use (&$warnings) {
        $warnings[] = $message;
    }
);
assertSameValue(true, str_ends_with($store->getPrivateDataPath(), 'public-wirewall-private/'), 'Relative private data paths should fall back to sibling private storage');
assertSameValue(1, count($warnings), 'Relative private data paths should be logged once per path resolution');
$writeOk = $store->writeRecord(['schema' => 'wirewall_traffic_v1', 'unix_time' => 123, 'status' => 'allowed'], 123);
assertSameValue(true, $writeOk, 'Traffic history store should write JSONL records');
$trafficDir = $store->getTrafficHistoryPath();
assertSameValue(true, is_file($trafficDir . '.htaccess'), 'Traffic history store should create .htaccess protection');
assertSameValue(true, is_file($trafficDir . 'index.php'), 'Traffic history store should create index.php protection');
assertSameValue(true, is_file($trafficDir . 'traffic-1970-01-01.jsonl'), 'Traffic history store should name files by record date');
assertSameValue(1, count($warnings), 'Relative private data path warning should be emitted once per store instance');

$matcher = new WireWallIpMatcher();
assertSameValue(true, $matcher->match('192.0.2.10', '192.0.2.10'), 'IP matcher should match exact IPv4 addresses');
assertSameValue(true, $matcher->match('192.0.2.10', '192.0.2.*'), 'IP matcher should match wildcard IPv4 patterns');
assertSameValue(true, $matcher->match('192.0.2.10', '192.0.2.0/24'), 'IP matcher should match IPv4 CIDR patterns');
assertSameValue(false, $matcher->match('192.0.3.10', '192.0.2.0/24'), 'IP matcher should reject IPv4 addresses outside CIDR');
assertSameValue(true, $matcher->match('2001:db8:2::42', '2001:db8:2::/48'), 'IP matcher should match IPv6 CIDR patterns');
assertSameValue(false, $matcher->match('2001:db8:3::42', '2001:db8:2::/48'), 'IP matcher should reject IPv6 addresses outside CIDR');
assertSameValue(false, $matcher->match('192.0.2.10', '2001:db8::/32'), 'IP matcher should reject mixed IP/CIDR versions');

$parsedRules = WireWallRuleMatcher::parseRuleText("\n# comment\nGooglebot\n\nBingbot\n");
assertSameValue(['Googlebot', 'Bingbot'], $parsedRules, 'Rule matcher should ignore empty lines and comments');
assertSameValue(true, WireWallRuleMatcher::matchPattern('/private/report', '/private/*'), 'Rule matcher should support wildcard patterns');
assertSameValue(false, WireWallRuleMatcher::matchPattern('StatusCake', 'statuscake'), 'Rule matcher exact wildcard-free matching remains case-sensitive');
assertSameValue(['Firefox', 'Brave'], WireWallRuleMatcher::extractUnsafeBrowserAllowPatterns('Firefox, Brave|Googlebot'), 'Rule matcher should extract unsafe browser allowlist tokens');

$configMethod = new \ReflectionMethod(WireWall::class, 'getModuleConfigInputfields');
$configSource = array_slice(
    file(dirname(__DIR__) . '/WireWall.module.php'),
    $configMethod->getStartLine() - 1,
    $configMethod->getEndLine() - $configMethod->getStartLine() + 1
);
assertSameValue(
    false,
    str_contains(implode('', $configSource), '$this'),
    'Static ProcessWire configuration callback must not reference $this'
);

echo "WireWall behavior tests passed\n";
