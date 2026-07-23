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

$wirewall->configureExceptions("Googlebot\nFirefox, Brave", '', '', '');
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
assertSameValue(170, $migrated['version'], 'Migration should record WireWall config version 170');
assertSameValue('', $migrated['allowedIPs'], 'Legacy full-bypass IPs should leave the scoped known-bot field');
assertSameValue("192.0.2.10\n198.51.100.0/24", $migrated['ip_whitelist'], 'Legacy full-bypass IPs should move to explicit whitelist without duplicates');
assertSameValue("Firefox\nBrave", $migrated['compatibilityUserAgents'], 'Legacy browser names should move to compatibility exceptions');

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

echo "WireWall behavior tests passed\n";
