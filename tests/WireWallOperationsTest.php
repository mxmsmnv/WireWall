<?php namespace ProcessWire;

require dirname(__DIR__) . '/src/Storage/WireWallOperationsStore.php';
require dirname(__DIR__) . '/src/Storage/WireWallTrafficMaintenance.php';
require dirname(__DIR__) . '/src/Intelligence/WireWallIpIntelligenceService.php';

function operationsAssert(bool $condition, string $message): void {
    if (!$condition) throw new \RuntimeException($message);
}

$temp = sys_get_temp_dir() . '/wirewall-operations-' . bin2hex(random_bytes(5)) . '/';
mkdir($temp, 0750, true);

$store = new WireWallOperationsStore($temp);
$rule = $store->addEmergencyRule('country', 'sg', 3600, ['user' => 'tester', 'reason' => 'incident']);
operationsAssert($store->matchEmergencyRule('203.0.113.1', 'SG', null, false)['id'] === $rule['id'], 'Country emergency rule should match.');
operationsAssert($store->removeEmergencyRule($rule['id'], 'tester'), 'Emergency rule should be removable.');
operationsAssert($store->matchEmergencyRule('203.0.113.1', 'SG', null, false) === null, 'Removed rule must not match.');

$snapshot = $store->saveSnapshot(['enabled' => 1, 'rate' => 60], ['enabled' => 1, 'rate' => 20], ['user' => 'tester']);
operationsAssert(isset($snapshot['diff']['rate']), 'Snapshot should contain a settings diff.');
operationsAssert($store->getSnapshot($snapshot['id']) !== null, 'Snapshot should be retrievable.');

$intel = new WireWallIpIntelligenceService($temp . 'missing.bin');
$cloud = $intel->lookup('203.0.113.1', 'AS16509 Amazon AWS');
operationsAssert($cloud['proxy_class'] === 'datacenter_proxy', 'ASN baseline should classify known cloud hosting.');
operationsAssert($intel->actionFor($cloud, [], '/') === 'block', 'Datacenter proxy default should block.');
$relay = $intel->lookup('203.0.113.2', 'AS714 Apple iCloud Private Relay');
operationsAssert($relay['proxy_class'] === 'privacy_relay', 'Apple privacy relay should be classified separately.');
operationsAssert($intel->actionFor($relay, [], '/') === 'allow', 'Privacy relay default should allow normal controls.');
operationsAssert($intel->actionFor($relay, ['proxy_sensitive_action' => 'challenge'], '/checkout') === 'challenge', 'Sensitive route should tighten privacy relay handling.');

$traffic = $temp . 'traffic/';
mkdir($traffic, 0750, true);
$oldDate = date('Y-m-d', strtotime('-40 days'));
file_put_contents($traffic . 'traffic-' . $oldDate . '.jsonl', "{}\n");
$maintenance = new WireWallTrafficMaintenance($traffic);
$result = $maintenance->run(30, 7, 0);
operationsAssert($result['deleted'] === 1, 'Retention should delete expired traffic logs.');

$iterator = new \RecursiveIteratorIterator(
    new \RecursiveDirectoryIterator($temp, \FilesystemIterator::SKIP_DOTS),
    \RecursiveIteratorIterator::CHILD_FIRST
);
foreach ($iterator as $entry) {
    $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
}
rmdir($temp);

echo "WireWall operations tests passed.\n";
