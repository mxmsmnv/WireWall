<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/src/Intelligence/WireWallAppleRelayVerifier.php';
use ProcessWire\WireWallAppleRelayVerifier as Relay;

$count = 0;
function relayAssert(bool $value, string $message): void {
    global $count; $count++;
    if (!$value) throw new RuntimeException($message);
}
function invalidFeed(string $body, string $message): void {
    try { Relay::parse($body); } catch (RuntimeException $e) { relayAssert(true, $message); return; }
    relayAssert(false, $message);
}
$body = '';
for ($i = 0; $i < 100; $i++) $body .= "203.0.113.0/27,US,US-CA,Test,\n2001:db8:1::/64,US,US-CA,Test,\n";
$now = 1800000000; $fetches = 0;
$directory = sys_get_temp_dir() . '/wirewall-relay-' . bin2hex(random_bytes(5));
$fetch = function($url) use (&$body, &$fetches) {
    relayAssert($url === Relay::SOURCE, 'Only the fixed official HTTPS URL may be fetched.');
    $fetches++; return $body;
};
$clock = function() use (&$now): int { return $now; };
$relay = new Relay($directory, $fetch, $clock);
try {
    relayAssert($relay->refresh()['available'], 'A complete valid feed must be available.');
    relayAssert($relay->status()['range_count'] === 2, 'Duplicate locations must not inflate lookup ranges.');
    foreach (['203.0.113.0', '203.0.113.31', '2001:db8:1::', '2001:db8:1:0:ffff:ffff:ffff:ffff'] as $ip)
        relayAssert($relay->verify($ip), 'IPv4/IPv6 exact boundaries must match.');
    foreach (['203.0.112.255', '203.0.113.32', '2001:db8::ffff', '2001:db8:2::', 'localhost', '203.0.113.1/32', '::ffff:203.0.113.1'] as $ip)
        relayAssert(!$relay->verify($ip), 'Outside/invalid/mapped addresses must not inherit a match.');
    relayAssert($fetches === 1, 'Fresh lookups must use cache only.');
    $newRequest = new Relay($directory, $fetch, $clock);
    relayAssert($newRequest->verify('203.0.113.1') && $fetches === 1, 'Private snapshot must survive across requests.');
    $body .= "203.0.113.32/27,US,US-CA,Test,\n";
    $now += Relay::REFRESH_SECONDS + 1;
    relayAssert($newRequest->verify('203.0.113.63'), 'Daily refresh must discover newly published adjacent ranges.');
    relayAssert($newRequest->status()['range_count'] === 2, 'Adjacent ranges must merge without adding outside addresses.');
    relayAssert(!$newRequest->verify('203.0.113.64'), 'Adjacent merge must preserve the upper boundary.');
    $body = 'invalid'; $now += Relay::REFRESH_SECONDS + 1;
    relayAssert($newRequest->verify('203.0.113.1'), 'Transient failure may retain the bounded last verified feed.');
    $before = $fetches;
    $anotherRequest = new Relay($directory, $fetch, $clock);
    relayAssert($anotherRequest->verify('203.0.113.1') && $fetches === $before, 'Failed refresh must have a cross-request retry backoff.');
    $now += Relay::MAX_AGE_SECONDS + 1;
    relayAssert(!$anotherRequest->verify('203.0.113.1'), 'Expired snapshots must fail closed.');
    $valid = str_repeat("203.0.113.0/27,US,US-CA,Test,\n2001:db8::/64,US,US-CA,Test,\n", 60);
    relayAssert(count(Relay::parse(rtrim($valid))['4']) === 1, 'Apple CSV may omit the final newline.');
    invalidFeed($valid . '203.0.113.', 'Truncated records must be rejected.');
    invalidFeed(str_replace('/27', '/0', $valid), 'An IPv4 catch-all must be rejected.');
    invalidFeed(str_replace('/64', '/0', $valid), 'An IPv6 catch-all must be rejected.');
    invalidFeed(str_replace('203.0.113.0/27', '203.0.113.1/27', $valid), 'Non-network CIDRs must be rejected.');
    invalidFeed(str_replace(',US,', ',INVALID,', $valid), 'Unexpected CSV schema must be rejected.');
    invalidFeed("203.0.113.0/27,US,US-CA,Test,\n", 'Incomplete feeds must be rejected.');
    invalidFeed(str_repeat('x', 24000001), 'Oversize feeds must be rejected.');
    $corrupt = json_decode(file_get_contents($directory . '/ranges.json'), true);
    $corrupt['ranges']['4'] = [['ffffffff', '00000000']];
    file_put_contents($directory . '/ranges.json', json_encode($corrupt));
    relayAssert(!(new Relay($directory, $fetch, $clock))->verify('203.0.113.1'), 'Corrupt cache must never grant an exception.');
    try { Relay::download('http://attacker.invalid/'); relayAssert(false, 'Alternate feed URL must fail.'); }
    catch (RuntimeException $e) { relayAssert(true, 'Alternate feed URL rejected.'); }
    echo "WireWallAppleRelayTest passed ($count assertions)\n";
} finally {
    foreach (glob($directory . '/*') ?: [] as $file) unlink($file);
    if (is_dir($directory)) rmdir($directory);
}
