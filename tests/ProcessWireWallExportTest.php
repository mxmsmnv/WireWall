<?php

declare(strict_types=1);

namespace ProcessWire;

class Process {}
interface Module {}
class WireException extends \RuntimeException {}
class Wire404Exception extends WireException {}
class WirePermissionException extends WireException {}

require dirname(__DIR__) . '/ProcessWireWall.module.php';
require dirname(__DIR__) . '/src/Dashboard/WireWallDashboardStats.php';
require dirname(__DIR__) . '/src/Storage/WireWallCacheInspector.php';

final class TestableProcessWireWall extends ProcessWireWall {
    public function __construct(private string $trafficDir) {}

    protected function getTrafficHistoryDir(): string {
        return $this->trafficDir;
    }

    protected function getCacheDir(): string {
        return $this->trafficDir . 'cache/';
    }

    public function files(): array {
        return $this->listTrafficFiles();
    }

    public function summary(array $paths): array {
        return $this->summarizeTraffic($paths);
    }

    public function rangeZip(string $from, string $to): string {
        return $this->createDateRangeZip($from, $to);
    }
}

function exportAssertSame(mixed $expected, mixed $actual, string $message): void {
    if ($expected !== $actual) {
        fwrite(
            STDERR,
            "FAIL: {$message}\nExpected: " . var_export($expected, true)
                . "\nActual: " . var_export($actual, true) . "\n"
        );
        exit(1);
    }
}

$tempDir = sys_get_temp_dir() . '/wirewall-export-' . bin2hex(random_bytes(6)) . '/';
mkdir($tempDir, 0700, true);
$today = date('Y-m-d');
$yesterday = date('Y-m-d', strtotime('-1 day'));
$todayPath = $tempDir . 'traffic-' . $today . '.jsonl';
$yesterdayPath = $tempDir . 'traffic-' . $yesterday . '.jsonl';

$rows = [
    [
        'unix_time' => time(),
        'status' => 'blocked',
        'ip' => '203.0.113.10',
        'asn' => 'AS64500 Example',
        'country' => 'US',
        'reason' => 'scanner trigger',
    ],
    [
        'unix_time' => time(),
        'status' => 'allowed',
        'ip' => '198.51.100.20',
        'asn' => 'AS64501 Example',
        'country' => 'CA',
        'reason' => 'allowed',
    ],
];
file_put_contents(
    $todayPath,
    implode("\n", array_map(
        static fn(array $row): string => json_encode($row, JSON_UNESCAPED_SLASHES),
        $rows
    )) . "\n"
);
file_put_contents($yesterdayPath, json_encode($rows[0], JSON_UNESCAPED_SLASHES) . "\n");

$dashboard = new TestableProcessWireWall($tempDir);
$files = $dashboard->files();
exportAssertSame(2, count($files), 'Dashboard should list each valid daily JSONL report');
exportAssertSame(2, $files[0]['rows'], 'Dashboard should count JSONL rows without loading the file into memory');

$summary = $dashboard->summary([$todayPath, $yesterdayPath]);
exportAssertSame(3, $summary['total'], 'Incident summary should aggregate all valid traffic rows');
exportAssertSame(2, $summary['status']['blocked'], 'Incident summary should count blocked requests');
exportAssertSame(2, $summary['top_ips']['203.0.113.10'], 'Incident summary should aggregate top IPs');

$zipPath = $dashboard->rangeZip($yesterday, $today);
$zip = new \ZipArchive();
exportAssertSame(true, $zip->open($zipPath) === true, 'Date range export should create a readable ZIP');
exportAssertSame(2, $zip->numFiles, 'Date range ZIP should include both daily reports');
$zip->close();

$cacheDir = $tempDir . 'cache/';
if (!is_dir($cacheDir)) {
    mkdir($cacheDir, 0700, true);
}
file_put_contents($cacheDir . 'ban_203_0_113_9.cache', serialize(['expire' => time() + 120]));
file_put_contents($cacheDir . 'ban_203_0_113_8.cache', serialize(['expire' => time() - 10]));
file_put_contents($cacheDir . 'ratelimit_203_0_113_9.cache', '1');
file_put_contents($cacheDir . 'proxy_203_0_113_9.cache', 'allowed');
file_put_contents($cacheDir . 'geo_203_0_113_9.cache', 'US');
$inspector = new WireWallCacheInspector($cacheDir, $tempDir);
$bans = $inspector->getActiveBans();
exportAssertSame(1, count($bans), 'Cache inspector should list only active bans');
exportAssertSame('203.0.113.9', $bans[0]['ip'], 'Cache inspector should decode ban IPs from cache filenames');
$cacheStats = $inspector->getCacheStats();
exportAssertSame(5, $cacheStats['total'], 'Cache inspector should remove expired bans while keeping unrelated cache files');
exportAssertSame(1, $cacheStats['ratelimit'], 'Cache inspector should count rate limit cache files');
exportAssertSame(1, $cacheStats['ban'], 'Cache inspector should count active ban cache files');
exportAssertSame(1, $cacheStats['proxy'], 'Cache inspector should count proxy cache files');
exportAssertSame(1, $cacheStats['geo'], 'Cache inspector should count geo cache files');
$trafficStats = $inspector->getTrafficHistoryStats();
exportAssertSame(2, $trafficStats['files'], 'Cache inspector should count traffic history JSONL files');
exportAssertSame('traffic-' . $today . '.jsonl', $trafficStats['latest'], 'Cache inspector should report latest traffic history file');

$older = date('Y-m-d', strtotime('-2 days'));
$compressedPath = $tempDir . 'traffic-' . $older . '.jsonl.gz';
$compressed = gzopen($compressedPath, 'wb6');
gzwrite($compressed, json_encode($rows[0], JSON_UNESCAPED_SLASHES) . "\n");
gzclose($compressed);
$compressedFiles = $dashboard->files();
exportAssertSame(3, count($compressedFiles), 'Dashboard should list gzip-rotated traffic reports.');
$compressedRow = array_values(array_filter($compressedFiles, static fn(array $file): bool => $file['date'] === $older))[0] ?? [];
exportAssertSame(1, $compressedRow['rows'] ?? 0, 'Dashboard should count rows in gzip-rotated reports.');
$compressedSummary = $dashboard->summary([$compressedPath]);
exportAssertSame(1, $compressedSummary['total'], 'Incident summaries should read gzip-rotated reports.');

$logPath = $tempDir . 'wirewall.txt';
$logLine = date('Y-m-d H:i:s') . "\tguest\t/\tBLOCKED | US (Ashburn, Virginia) | 203.0.113.10 | AS64500 Example | UA: TestBot | datacenter\n";
file_put_contents($logPath, "ignored\n" . $logLine . date('Y-m-d H:i:s') . "\tguest\t/\tALLOWED | CA | 198.51.100.20 | UA: Browser | allowed\n");
$dashboardStats = new WireWallDashboardStats($logPath);
$tail = $dashboardStats->readLogLines(2);
exportAssertSame(2, count($tail), 'Dashboard stats should read the requested number of trailing log lines');
$parsed = $dashboardStats->parseLine(trim($logLine));
exportAssertSame('BLOCKED', $parsed['status'], 'Dashboard stats should parse WireWall status');
exportAssertSame('US', $parsed['countryCode'], 'Dashboard stats should parse country code');
exportAssertSame('datacenter', $parsed['reason'], 'Dashboard stats should parse decision reason');
$built = $dashboardStats->buildStats($tail);
exportAssertSame(2, $built['total'], 'Dashboard stats should aggregate parsed log rows');
exportAssertSame(1, $built['blocked'], 'Dashboard stats should count blocked rows');
exportAssertSame('2m 5s', $dashboardStats->formatTTL(125), 'Dashboard stats should format TTLs');

@unlink($zipPath);
foreach (glob($cacheDir . '*') ?: [] as $file) {
    @unlink($file);
}
@rmdir($cacheDir);
@unlink($logPath);
@unlink($todayPath);
@unlink($yesterdayPath);
@unlink($compressedPath);
@rmdir($tempDir);

echo "ProcessWireWall export tests passed\n";
