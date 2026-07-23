<?php namespace ProcessWire;

/**
 * Reads, summarizes, and packages WireWall traffic history reports.
 */
class WireWallTrafficReportService {

    protected string $trafficDir;
    protected string $cacheDir;

    public function __construct(string $trafficDir, string $cacheDir) {
        $this->trafficDir = rtrim($trafficDir, '/\\') . DIRECTORY_SEPARATOR;
        $this->cacheDir = rtrim($cacheDir, '/\\') . DIRECTORY_SEPARATOR;
    }

    public function getTrafficFileForDate(string $date): string {
        if (!$this->isValidDate($date)) {
            throw new Wire404Exception('Invalid traffic report date.');
        }

        $path = $this->trafficDir . 'traffic-' . $date . '.jsonl';
        if (!is_file($path)) {
            throw new Wire404Exception('No traffic report exists for ' . $date . '.');
        }
        return $path;
    }

    public function isValidDate(string $date): bool {
        $parsed = \DateTimeImmutable::createFromFormat('!Y-m-d', $date);
        return $parsed instanceof \DateTimeImmutable && $parsed->format('Y-m-d') === $date;
    }

    public function countJsonlRows(string $path): int {
        $rows = 0;
        $handle = @fopen($path, 'rb');
        if (!$handle) return 0;
        while (fgets($handle) !== false) {
            $rows++;
        }
        fclose($handle);
        return $rows;
    }

    public function listTrafficFiles(): array {
        $files = [];
        if (!is_dir($this->trafficDir)) return $files;

        $indexPath = $this->cacheDir . 'traffic-report-index.json';
        $index = [];
        $indexJson = @file_get_contents($indexPath);
        if (is_string($indexJson)) {
            $decoded = json_decode($indexJson, true);
            if (is_array($decoded)) {
                $index = $decoded;
            }
        }
        $nextIndex = [];

        foreach (scandir($this->trafficDir) ?: [] as $file) {
            if (!preg_match('/^traffic-(\d{4}-\d{2}-\d{2})\.jsonl$/', $file, $match)) {
                continue;
            }
            $path = $this->trafficDir . $file;
            if (!is_file($path)) continue;
            $size = filesize($path);
            $modified = filemtime($path);
            $cached = $index[$file] ?? [];
            $rows = (
                isset($cached['size'], $cached['modified'], $cached['rows'])
                && (int)$cached['size'] === $size
                && (int)$cached['modified'] === $modified
            ) ? (int)$cached['rows'] : $this->countJsonlRows($path);
            $nextIndex[$file] = compact('size', 'modified', 'rows');
            $files[] = [
                'date' => $match[1],
                'file' => $file,
                'path' => $path,
                'size' => $size,
                'rows' => $rows,
            ];
        }

        if ((is_dir($this->cacheDir) || @mkdir($this->cacheDir, 0755, true)) && $nextIndex !== $index) {
            @file_put_contents(
                $indexPath,
                json_encode($nextIndex, JSON_UNESCAPED_SLASHES),
                LOCK_EX
            );
        }

        usort($files, static fn(array $a, array $b): int => strcmp($b['date'], $a['date']));
        return $files;
    }

    public function createDateRangeZip(string $from, string $to): string {
        if (!$this->isValidDate($from) || !$this->isValidDate($to) || $from > $to) {
            throw new WireException('Choose a valid traffic report date range.');
        }

        $start = new \DateTimeImmutable($from);
        $end = new \DateTimeImmutable($to);
        if ($start->diff($end)->days > 366) {
            throw new WireException('Traffic report ranges are limited to 366 days.');
        }
        if (!class_exists('\ZipArchive')) {
            throw new WireException('The PHP ZIP extension is required for range exports.');
        }

        $temp = tempnam(sys_get_temp_dir(), 'wirewall-range-');
        if ($temp === false) {
            throw new WireException('Could not create a temporary report.');
        }
        $zipPath = $temp . '.zip';
        @unlink($temp);

        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            throw new WireException('Could not create the traffic report archive.');
        }

        $added = 0;
        for ($date = $start; $date <= $end; $date = $date->modify('+1 day')) {
            $name = 'traffic-' . $date->format('Y-m-d') . '.jsonl';
            $path = $this->trafficDir . $name;
            if (is_file($path)) {
                $zip->addFile($path, $name);
                $added++;
            }
        }
        $zip->close();

        if ($added === 0) {
            @unlink($zipPath);
            throw new Wire404Exception('No traffic reports exist in that date range.');
        }
        return $zipPath;
    }

    public function createLast24HoursReport(): string {
        $temp = tempnam(sys_get_temp_dir(), 'wirewall-24h-');
        if ($temp === false) {
            throw new WireException('Could not create a temporary report.');
        }

        $output = fopen($temp, 'wb');
        if (!$output) {
            @unlink($temp);
            throw new WireException('Could not open the temporary report.');
        }

        $cutoff = time() - 86400;
        foreach ([date('Y-m-d', strtotime('-1 day')), date('Y-m-d')] as $date) {
            $path = $this->trafficDir . 'traffic-' . $date . '.jsonl';
            $input = @fopen($path, 'rb');
            if (!$input) continue;
            while (($line = fgets($input)) !== false) {
                $row = json_decode($line, true);
                $timestamp = is_array($row) ? (int)($row['unix_time'] ?? 0) : 0;
                if ($timestamp >= $cutoff) {
                    fwrite($output, $line);
                }
            }
            fclose($input);
        }
        fclose($output);
        return $temp;
    }

    public function summarizeTraffic(array $paths): array {
        $summary = [
            'schema' => 'wirewall_incident_summary_v1',
            'generated_at' => date('c'),
            'total' => 0,
            'status' => [],
            'top_ips' => [],
            'top_asns' => [],
            'top_countries' => [],
            'top_reasons' => [],
            'hourly' => [],
        ];

        foreach ($paths as $path) {
            $handle = @fopen($path, 'rb');
            if (!$handle) continue;
            while (($line = fgets($handle)) !== false) {
                $row = json_decode($line, true);
                if (!is_array($row)) continue;
                $summary['total']++;
                $this->incrementSummary($summary['status'], (string)($row['status'] ?? 'unknown'));
                $this->incrementSummary($summary['top_ips'], (string)($row['ip'] ?? ''));
                $this->incrementSummary($summary['top_asns'], (string)($row['asn'] ?? ''));
                $this->incrementSummary($summary['top_countries'], (string)($row['country'] ?? ''));
                $this->incrementSummary($summary['top_reasons'], (string)($row['reason'] ?? ''));
                $time = (int)($row['unix_time'] ?? 0);
                if ($time > 0) {
                    $this->incrementSummary($summary['hourly'], date('Y-m-d H:00', $time));
                }
            }
            fclose($handle);
        }

        foreach (['status', 'top_ips', 'top_asns', 'top_countries', 'top_reasons', 'hourly'] as $key) {
            arsort($summary[$key]);
            if (str_starts_with($key, 'top_')) {
                $summary[$key] = array_slice($summary[$key], 0, 25, true);
            }
        }
        return $summary;
    }

    protected function incrementSummary(array &$values, string $key): void {
        $key = trim($key);
        if ($key === '') return;
        $values[$key] = ($values[$key] ?? 0) + 1;
    }
}
