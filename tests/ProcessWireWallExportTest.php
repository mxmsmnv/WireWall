<?php

declare(strict_types=1);

namespace ProcessWire;

class Process {}
interface Module {}
class WireException extends \RuntimeException {}
class Wire404Exception extends WireException {}
class WirePermissionException extends WireException {}

require dirname(__DIR__) . '/ProcessWireWall.module.php';

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

@unlink($zipPath);
@unlink($todayPath);
@unlink($yesterdayPath);
@rmdir($tempDir);

echo "ProcessWireWall export tests passed\n";
