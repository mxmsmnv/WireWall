<?php namespace ProcessWire;

/**
 * ProcessWireWall - WireWall Dashboard
 *
 * Admin dashboard for the WireWall firewall module.
 * Displays real-time statistics parsed from the wirewall log and cache.
 *
 * Install: place ProcessWireWall.module.php in /site/modules/WireWall/
 * The module registers a page at Admin > Setup > WireWall
 *
 * @version 1.8.1
 * @author Maxim Semenov <maxim@smnv.org> (smnv.org)
 * @requires WireWall, ProcessWire>=3.0.200, PHP>=8.1
 */
class ProcessWireWall extends Process implements Module {

    public static function getModuleInfo() {
        return [
            'title'       => 'WireWall Dashboard',
            'summary'     => 'Firewall statistics and live event log',
            'version'     => 181,
            'author'      => 'Maxim Semenov',
            'href'     => 'https://smnv.org',
            'icon'        => 'shield',
            'requires'    => ['WireWall', 'ProcessWire>=3.0.200'],
            'permission'  => 'wirewall-dashboard',
            'permissions' => [
                'wirewall-dashboard' => 'Access WireWall Dashboard',
            ],
            'page' => [
                'name'   => 'wirewall',
                'parent' => 'setup',
                'title'  => 'WireWall',
            ],
        ];
    }

    // -------------------------------------------------------------------------
    // Helpers: paths
    // -------------------------------------------------------------------------

    protected function getLogPath(): string {
        return $this->wire('config')->paths->logs . 'wirewall.txt';
    }

    protected function getCacheDir(): string {
        return $this->wire('config')->paths->cache . 'WireWall/';
    }

    protected function getTrafficHistoryDir(): string {
        return $this->getWireWallModule()->getTrafficHistoryDirectory();
    }

    protected function getWireWallModule(): WireWall {
        $module = $this->wire('modules')->get('WireWall');
        if (!$module instanceof WireWall) {
            throw new WireException('WireWall is not installed.');
        }
        return $module;
    }

    protected function assertReportAccess(): void {
        $user = $this->wire('user');
        if (!$user || !$user->isLoggedin() || !$user->hasPermission('wirewall-dashboard')) {
            throw new WirePermissionException('WireWall dashboard permission is required.');
        }
    }

    protected function sendDownload(string $path, string $downloadName, string $contentType): never {
        if (!is_file($path) || !is_readable($path)) {
            throw new Wire404Exception('The requested WireWall report does not exist.');
        }

        $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '-', basename($downloadName));
        header('Content-Type: ' . $contentType);
        header('Content-Disposition: attachment; filename="' . $safeName . '"');
        header('Content-Length: ' . filesize($path));
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: private, no-store, max-age=0');
        readfile($path);
        exit;
    }

    protected function sendGeneratedDownload(
        string $path,
        string $downloadName,
        string $contentType
    ): never {
        register_shutdown_function(static function () use ($path): void {
            if (is_file($path)) {
                @unlink($path);
            }
        });
        $this->sendDownload($path, $downloadName, $contentType);
    }

    protected function getTrafficFileForDate(string $date): string {
        if (!$this->isValidDate($date)) {
            throw new Wire404Exception('Invalid traffic report date.');
        }

        $path = $this->getTrafficHistoryDir() . 'traffic-' . $date . '.jsonl';
        if (!is_file($path)) {
            throw new Wire404Exception('No traffic report exists for ' . $date . '.');
        }
        return $path;
    }

    protected function isValidDate(string $date): bool {
        $parsed = \DateTimeImmutable::createFromFormat('!Y-m-d', $date);
        return $parsed instanceof \DateTimeImmutable && $parsed->format('Y-m-d') === $date;
    }

    protected function countJsonlRows(string $path): int {
        $rows = 0;
        $handle = @fopen($path, 'rb');
        if (!$handle) return 0;
        while (fgets($handle) !== false) {
            $rows++;
        }
        fclose($handle);
        return $rows;
    }

    protected function listTrafficFiles(): array {
        $dir = $this->getTrafficHistoryDir();
        $files = [];
        if (!is_dir($dir)) return $files;

        $indexPath = $this->getCacheDir() . 'traffic-report-index.json';
        $index = [];
        $indexJson = @file_get_contents($indexPath);
        if (is_string($indexJson)) {
            $decoded = json_decode($indexJson, true);
            if (is_array($decoded)) {
                $index = $decoded;
            }
        }
        $nextIndex = [];

        foreach (scandir($dir) as $file) {
            if (!preg_match('/^traffic-(\d{4}-\d{2}-\d{2})\.jsonl$/', $file, $match)) {
                continue;
            }
            $path = $dir . $file;
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

        $cacheDir = dirname($indexPath);
        if ((is_dir($cacheDir) || @mkdir($cacheDir, 0755, true)) && $nextIndex !== $index) {
            @file_put_contents(
                $indexPath,
                json_encode($nextIndex, JSON_UNESCAPED_SLASHES),
                LOCK_EX
            );
        }

        usort($files, static fn(array $a, array $b): int => strcmp($b['date'], $a['date']));
        return $files;
    }

    protected function createDateRangeZip(string $from, string $to): string {
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
            $path = $this->getTrafficHistoryDir() . $name;
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

    protected function createLast24HoursReport(): string {
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
            $path = $this->getTrafficHistoryDir() . 'traffic-' . $date . '.jsonl';
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

    protected function summarizeTraffic(array $paths): array {
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

    protected function createIncidentBundle(): string {
        if (!class_exists('\ZipArchive')) {
            throw new WireException('The PHP ZIP extension is required for incident bundles.');
        }

        $temp = tempnam(sys_get_temp_dir(), 'wirewall-incident-');
        if ($temp === false) {
            throw new WireException('Could not create a temporary incident bundle.');
        }
        $zipPath = $temp . '.zip';
        @unlink($temp);

        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            throw new WireException('Could not create the incident bundle.');
        }

        $dates = [
            'today' => date('Y-m-d'),
            'yesterday' => date('Y-m-d', strtotime('-1 day')),
        ];
        $trafficPaths = [];
        foreach ($dates as $label => $date) {
            $path = $this->getTrafficHistoryDir() . 'traffic-' . $date . '.jsonl';
            if (is_file($path)) {
                $zip->addFile($path, 'traffic-' . $label . '.jsonl');
                $trafficPaths[] = $path;
            } else {
                $zip->addFromString('traffic-' . $label . '.jsonl', '');
            }
        }

        $settings = $this->getWireWallModule()->getAISettingsExport();
        $summary = $this->summarizeTraffic($trafficPaths);
        $jsonFlags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $zip->addFromString('settings.json', json_encode($settings, $jsonFlags) . "\n");
        $zip->addFromString('summary.json', json_encode($summary, $jsonFlags) . "\n");
        $zip->addFromString(
            'README.txt',
            "WireWall AI Incident Bundle\n"
            . "===========================\n\n"
            . "Generated: " . date('c') . "\n"
            . "Contents:\n"
            . "- settings.json: redacted active settings and safe environment metadata\n"
            . "- traffic-today.jsonl: today's request history, if available\n"
            . "- traffic-yesterday.jsonl: yesterday's request history, if available\n"
            . "- summary.json: aggregate counts for incident review\n\n"
            . "Treat IP addresses, URLs, referers, and User-Agents as sensitive operational data.\n"
        );
        $zip->close();
        return $zipPath;
    }

    public function ___executeDownloadSettings(): never {
        $this->assertReportAccess();
        $json = json_encode(
            $this->getWireWallModule()->getAISettingsExport(),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        $temp = tempnam(sys_get_temp_dir(), 'wirewall-settings-');
        if ($temp === false || file_put_contents($temp, $json . "\n", LOCK_EX) === false) {
            throw new WireException('Could not create the settings export.');
        }
        $this->sendGeneratedDownload(
            $temp,
            'wirewall-settings-' . date('Y-m-d-His') . '.json',
            'application/json; charset=utf-8'
        );
    }

    public function ___executeDownloadTraffic(): never {
        $this->assertReportAccess();
        $input = $this->wire('input');
        $range = (string)$input->get->text('range');
        if ($range === 'last24h') {
            $this->sendGeneratedDownload(
                $this->createLast24HoursReport(),
                'wirewall-traffic-last-24h.jsonl',
                'application/x-ndjson; charset=utf-8'
            );
        }

        if ($range === 'today' || $range === 'yesterday') {
            $date = $range === 'today' ? date('Y-m-d') : date('Y-m-d', strtotime('-1 day'));
            $this->sendDownload(
                $this->getTrafficFileForDate($date),
                'traffic-' . $date . '.jsonl',
                'application/x-ndjson; charset=utf-8'
            );
        }

        $date = (string)$input->get->text('date');
        if ($date !== '') {
            $this->sendDownload(
                $this->getTrafficFileForDate($date),
                'traffic-' . $date . '.jsonl',
                'application/x-ndjson; charset=utf-8'
            );
        }

        $from = (string)$input->get->text('from');
        $to = (string)$input->get->text('to');
        if ($from !== '' && $to !== '') {
            $this->sendGeneratedDownload(
                $this->createDateRangeZip($from, $to),
                'wirewall-traffic-' . $from . '-to-' . $to . '.zip',
                'application/zip'
            );
        }

        throw new Wire404Exception('Choose a WireWall traffic report.');
    }

    public function ___executeDownloadIncidentBundle(): never {
        $this->assertReportAccess();
        $this->sendGeneratedDownload(
            $this->createIncidentBundle(),
            'wirewall-incident-' . date('Y-m-d-His') . '.zip',
            'application/zip'
        );
    }

    // -------------------------------------------------------------------------
    // Log reading
    // -------------------------------------------------------------------------

    /**
     * Read the last $limit lines from the log file (memory-efficient tail).
     */
    protected function readLogLines(int $limit = 5000): array {
        $path = $this->getLogPath();
        if (!file_exists($path)) return [];

        $fp = fopen($path, 'rb');
        if (!$fp) return [];

        fseek($fp, 0, SEEK_END);
        $pos    = ftell($fp);
        $buffer = '';
        $lines  = [];
        $count  = 0;

        while ($pos > 0 && $count < $limit) {
            $chunk   = min(4096, $pos);
            $pos    -= $chunk;
            fseek($fp, $pos);
            $buffer  = fread($fp, $chunk) . $buffer;
            $found   = explode("\n", $buffer);
            $complete = array_slice($found, 1);
            $count   += count($complete);
            $buffer   = $found[0];
            $lines    = array_merge($complete, $lines);
        }
        if ($buffer !== '') $lines = array_merge([$buffer], $lines);
        fclose($fp);

        $lines = array_filter(array_map('trim', $lines));
        return array_slice(array_values($lines), -$limit);
    }

    /**
     * Parse one log line into a structured array.
     *
     * PW log format: "YYYY-MM-DD HH:MM:SS\tUSER\tURL\tMESSAGE"  (4 tab-separated columns)
     * WireWall msg : "STATUS | COUNTRY (City, Region) | IP | ASN | UA: ... | reason"
     */
    protected function parseLine(string $line): ?array {
        $ts      = '';
        $message = $line;

        if (str_contains($line, "\t")) {
            // PW writes: timestamp \t user \t url \t message
            $cols = explode("\t", $line);
            $ts   = trim($cols[0] ?? '');
            // Find the WireWall message: the tab-column that starts with BLOCKED/ALLOWED
            $message = '';
            foreach (array_reverse($cols) as $col) {
                $col = trim($col);
                if (str_starts_with($col, 'BLOCKED') || str_starts_with($col, 'ALLOWED')) {
                    $message = $col;
                    break;
                }
            }
            // Fallback: last column
            if ($message === '') $message = trim(end($cols));
        }

        $parts  = array_map('trim', explode(' | ', $message));
        $status = $parts[0] ?? '';
        if (!in_array($status, ['BLOCKED', 'ALLOWED'], true)) return null;

        $country     = $parts[1] ?? '';
        $ip          = $parts[2] ?? '';
        $asn = $ua = $reason = $countryCode = '';

        for ($i = 3; $i < count($parts); $i++) {
            $p = trim($parts[$i]);
            if (str_starts_with($p, 'UA: ')) {
                $ua = substr($p, 4);
            } elseif (preg_match('/^AS\d+\s/', $p) || preg_match('/^AS\d+$/', $p)) {
                $asn = $p;
            } elseif ($p !== '') {
                $reason = $p;
            }
        }

        if (preg_match('/^([A-Z]{2})(\s|$|\s\()/', $country, $m)) {
            $countryCode = $m[1];
        }

        $time = $ts ? (strtotime($ts) ?: 0) : 0;
        return compact('time', 'status', 'country', 'countryCode', 'ip', 'asn', 'ua', 'reason');
    }

    // -------------------------------------------------------------------------
    // Cache inspection
    // -------------------------------------------------------------------------

    protected function getActiveBans(): array {
        $dir  = $this->getCacheDir();
        $bans = [];
        if (!is_dir($dir)) return $bans;

        foreach (scandir($dir) as $file) {
            if (!str_starts_with($file, 'ban_')) continue;
            $content = @file_get_contents($dir . $file);
            if (!$content) continue;
            $data = @unserialize($content, ['allowed_classes' => false]);
            if (!is_array($data) || !isset($data['expire'])) continue;
            if ($data['expire'] < time()) { @unlink($dir . $file); continue; }

            $ip = str_replace('_', '.', preg_replace('/^ban_|\.cache$/', '', $file));
            $bans[] = [
                'ip'      => $ip,
                'expires' => $data['expire'],
                'ttl'     => $data['expire'] - time(),
            ];
        }

        usort($bans, fn($a, $b) => $b['ttl'] <=> $a['ttl']);
        return $bans;
    }

    protected function getCacheStats(): array {
        $dir   = $this->getCacheDir();
        $stats = ['total' => 0, 'ratelimit' => 0, 'ban' => 0, 'proxy' => 0, 'geo' => 0, 'size' => 0];
        if (!is_dir($dir)) return $stats;

        foreach (scandir($dir) as $file) {
            if ($file === '.' || $file === '..') continue;
            $path = $dir . $file;
            if (!is_file($path)) continue;
            $stats['total']++;
            $stats['size'] += filesize($path);
            if (str_starts_with($file, 'ratelimit_'))  $stats['ratelimit']++;
            elseif (str_starts_with($file, 'ban_'))    $stats['ban']++;
            elseif (str_starts_with($file, 'proxy_'))  $stats['proxy']++;
            elseif (str_starts_with($file, 'geo_'))    $stats['geo']++;
        }
        return $stats;
    }

    protected function getTrafficHistoryStats(): array {
        $dir = $this->getTrafficHistoryDir();
        $stats = ['files' => 0, 'size' => 0, 'latest' => ''];
        if (!is_dir($dir)) return $stats;

        foreach (scandir($dir) as $file) {
            if (!preg_match('/^traffic-\d{4}-\d{2}-\d{2}\.jsonl$/', $file)) continue;
            $path = $dir . $file;
            if (!is_file($path)) continue;
            $stats['files']++;
            $stats['size'] += filesize($path);
            if ($stats['latest'] === '' || $file > $stats['latest']) {
                $stats['latest'] = $file;
            }
        }

        return $stats;
    }

    // -------------------------------------------------------------------------
    // Statistics aggregation
    // -------------------------------------------------------------------------

    protected function buildStats(array $lines): array {
        $total = $blocked = $allowed = 0;
        $reasons = $countries = $ips = [];
        $byHour  = array_fill(0, 24, 0);
        $recent  = [];
        $cutoff24 = time() - 86400;

        foreach ($lines as $line) {
            $r = $this->parseLine($line);
            if (!$r) continue;
            $total++;

            if ($r['status'] === 'BLOCKED') {
                $blocked++;
                $key = $r['reason'] ?: 'unknown';
                $reasons[$key] = ($reasons[$key] ?? 0) + 1;
                if ($r['countryCode']) {
                    $countries[$r['countryCode']] = ($countries[$r['countryCode']] ?? 0) + 1;
                }
                if ($r['ip']) {
                    $ips[$r['ip']] = ($ips[$r['ip']] ?? 0) + 1;
                }
                if ($r['time'] >= $cutoff24) {
                    $byHour[(int)date('G', $r['time'])]++;
                }
            } else {
                $allowed++;
            }

            $recent[] = $r; // collect all, slice at end
        }

        arsort($reasons);
        arsort($countries);
        arsort($ips);

        return [
            'total'      => $total,
            'blocked'    => $blocked,
            'allowed'    => $allowed,
            'blockRate'  => $total > 0 ? round($blocked / $total * 100, 1) : 0,
            'uniqueIPs'  => count($ips),           // all unique blocked IPs, not just top-10
            'reasons'    => array_slice($reasons,   0, 10, true),
            'countries'  => array_slice($countries, 0, 10, true),
            'topIPs'     => array_slice($ips,       0, 10, true),
            'byHour'     => $byHour,
            'recent'     => array_reverse(array_slice($recent, -50)),
        ];
    }

    protected function formatTTL(int $seconds): string {
        $h = (int)($seconds / 3600);
        $m = (int)(($seconds % 3600) / 60);
        $s = $seconds % 60;
        if ($h > 0) return "{$h}h {$m}m";
        if ($m > 0) return "{$m}m {$s}s";
        return "{$s}s";
    }

    // -------------------------------------------------------------------------
    // Render
    // -------------------------------------------------------------------------

    public function ___execute(): string {
        $lines      = $this->readLogLines(5000);
        $stats      = $this->buildStats($lines);
        $bans       = $this->getActiveBans();
        $cacheStats = $this->getCacheStats();
        $trafficStats = $this->getTrafficHistoryStats();
        $trafficFiles = $this->listTrafficFiles();

        $sizeFormatted = $cacheStats['size'] > 1048576
            ? round($cacheStats['size'] / 1048576, 1) . ' MB'
            : round($cacheStats['size'] / 1024, 1) . ' KB';

        // Hourly chart: last 24 hours ordered from oldest to newest
        $currentHour = (int)date('G');
        $hourLabels  = [];
        $hourData    = [];
        for ($i = 23; $i >= 0; $i--) {
            $h            = ($currentHour - $i + 24) % 24;
            $hourLabels[] = sprintf('%02d:00', $h);
            $hourData[]   = $stats['byHour'][$h];
        }

        $wireWallConfig = $this->getWireWallModule()->getWireWallSettings();
        $wireWallEnabled = (bool)($wireWallConfig['enabled'] ?? 0);
        $logEnabled = (bool)($wireWallConfig['enable_stats_logging'] ?? 0);
        $trafficHistoryEnabled = !array_key_exists('enable_traffic_history', $wireWallConfig) || (bool)$wireWallConfig['enable_traffic_history'];
        $adminUrl   = $this->wire('config')->urls->admin;
        $pageUrl    = $this->wire('page')->url;
        $trafficSizeFormatted = $trafficStats['size'] > 1048576
            ? round($trafficStats['size'] / 1048576, 1) . ' MB'
            : round($trafficStats['size'] / 1024, 1) . ' KB';
        $lastEventTime = !empty($stats['recent']) && !empty($stats['recent'][0]['time'])
            ? date('M d H:i', $stats['recent'][0]['time'])
            : 'No events yet';
        $protectionLabel = $wireWallEnabled ? 'Protection active' : 'Protection paused';
        $protectionClass = $wireWallEnabled ? 'is-good' : 'is-warn';

        $formatTTL = fn(int $s) => $this->formatTTL($s);

        // ---- inline HTML output ----
        ob_start();
?>
<style>
/* WireWall Dashboard */
.ww-dash {
    --ww-red: #dc2626;
    --ww-green: #16a34a;
    --ww-amber: #d97706;
    --ww-blue: #2563eb;
    --ww-violet: #7c3aed;
    --ww-panel: var(--pw-blocks-background);
    --ww-border: var(--pw-border-color);
    color: var(--pw-text-color);
}
.ww-dash * { box-sizing: border-box; }
.ww-shell {
    display: grid;
    gap: 14px;
}
.ww-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 16px;
    border: 1px solid var(--ww-border);
    border-radius: 6px;
    background: var(--ww-panel);
}
.ww-title {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 0;
}
.ww-mark {
    width: 36px;
    height: 36px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 36px;
    border-radius: 6px;
    color: #fff;
    background: var(--ww-red);
}
.ww-title h2 {
    margin: 0;
    font-size: 20px;
    line-height: 1.2;
    letter-spacing: 0;
}
.ww-subline {
    margin: 3px 0 0;
    color: var(--pw-muted-color);
    font-size: 12px;
}
.ww-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
}
.ww-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 32px;
    padding: 6px 10px;
    border: 1px solid var(--ww-border);
    border-radius: 6px;
    background: var(--pw-inputs-background);
    color: var(--pw-text-color);
    font-size: 12px;
    font-weight: 600;
    line-height: 1;
    text-decoration: none;
}
.ww-btn:hover {
    color: var(--pw-text-color);
    border-color: var(--pw-main-color);
    text-decoration: none;
}
.ww-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 26px;
    padding: 4px 8px;
    border: 1px solid var(--ww-border);
    border-radius: 999px;
    background: var(--pw-inputs-background);
    font-size: 11px;
    font-weight: 700;
    white-space: nowrap;
}
.ww-pill:before {
    content: "";
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
}
.ww-pill.is-good { color: var(--ww-green); }
.ww-pill.is-warn { color: var(--ww-amber); }
.ww-pill.is-bad { color: var(--ww-red); }
.ww-notice {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 11px 12px;
    border: 1px solid var(--ww-border);
    border-left: 4px solid var(--ww-blue);
    border-radius: 6px;
    background: var(--ww-panel);
    font-size: 12px;
}
.ww-notice.is-warning { border-left-color: var(--ww-amber); }
.ww-notice code {
    white-space: normal;
    word-break: break-word;
}
.ww-metrics {
    display: grid;
    grid-template-columns: repeat(5, minmax(140px, 1fr));
    gap: 10px;
}
.ww-metric {
    min-height: 116px;
    padding: 14px;
    border: 1px solid var(--ww-border);
    border-radius: 6px;
    background: var(--ww-panel);
}
.ww-metric-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 12px;
}
.ww-head {
    margin: 0;
    color: var(--pw-muted-color);
    font-size: 10px;
    font-weight: 800;
    letter-spacing: .08em;
    line-height: 1.2;
    text-transform: uppercase;
}
.ww-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    flex: 0 0 26px;
    border-radius: 6px;
    color: #fff;
}
.ww-icon.is-red { background: var(--ww-red); }
.ww-icon.is-green { background: var(--ww-green); }
.ww-icon.is-amber { background: var(--ww-amber); }
.ww-icon.is-blue { background: var(--ww-blue); }
.ww-icon.is-violet { background: var(--ww-violet); }
.ww-val {
    color: var(--pw-text-color);
    font-size: 30px;
    font-weight: 800;
    line-height: 1;
    letter-spacing: 0;
}
.ww-meta {
    margin: 8px 0 0;
    color: var(--pw-muted-color);
    font-size: 12px;
    line-height: 1.35;
}
.ww-grid {
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
    gap: 12px;
}
.ww-grid-2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
}
.ww-panel {
    border: 1px solid var(--ww-border);
    border-radius: 6px;
    background: var(--ww-panel);
    overflow: hidden;
}
.ww-panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 14px;
    border-bottom: 1px solid var(--ww-border);
}
.ww-panel-body {
    padding: 14px;
}
.ww-chart {
    position: relative;
    height: 230px;
}
.ww-scroll {
    max-height: 460px;
    overflow: auto;
}
.ww-list {
    list-style: none;
    margin: 0;
    padding: 0;
}
.ww-list li {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 32px;
    padding: 7px 0;
    border-bottom: 1px solid var(--ww-border);
}
.ww-list li:last-child { border-bottom: 0; }
.ww-list-label {
    flex: 0 0 138px;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--pw-text-color);
    font-size: 12px;
    font-weight: 600;
}
.ww-list-label.is-code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 11px;
}
.ww-bar-wrap {
    display: block;
    height: 6px;
    min-width: 0;
    flex: 1;
    border-radius: 999px;
    background: var(--pw-inputs-background);
    overflow: hidden;
}
.ww-bar-fill {
    display: block;
    height: 100%;
    border-radius: 999px;
}
.ww-count {
    flex: 0 0 44px;
    color: var(--pw-muted-color);
    font-size: 11px;
    font-weight: 800;
    text-align: right;
}
.ww-empty {
    margin: 0;
    padding: 30px 0;
    color: var(--pw-muted-color);
    font-size: 12px;
    text-align: center;
}
.ww-ttl {
    display: inline-flex;
    align-items: center;
    min-height: 22px;
    padding: 2px 7px;
    border-radius: 999px;
    background: rgba(220, 38, 38, 0.1);
    color: var(--ww-red);
    font-size: 10px;
    font-weight: 800;
    white-space: nowrap;
}
.ww-reason-tag,
.ww-status {
    display: inline-flex;
    align-items: center;
    min-height: 22px;
    padding: 2px 7px;
    border-radius: 999px;
    border: 1px solid var(--ww-border);
    background: var(--pw-inputs-background);
    color: var(--pw-text-color);
    font-size: 10px;
    font-weight: 800;
    white-space: nowrap;
}
.ww-status.is-blocked {
    border-color: rgba(220, 38, 38, 0.45);
    color: var(--ww-red);
}
.ww-status.is-allowed {
    border-color: rgba(22, 163, 74, 0.45);
    color: var(--ww-green);
}
.ww-table {
    width: 100%;
    margin: 0;
    border-collapse: collapse;
    table-layout: fixed;
}
.ww-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    padding: 9px 10px;
    border-bottom: 1px solid var(--ww-border);
    background: var(--ww-panel);
    color: var(--pw-muted-color);
    font-size: 10px;
    font-weight: 800;
    letter-spacing: .08em;
    text-align: left;
    text-transform: uppercase;
}
.ww-table td {
    padding: 9px 10px;
    border-bottom: 1px solid var(--ww-border);
    color: var(--pw-text-color);
    font-size: 12px;
    vertical-align: middle;
}
.ww-table tr:hover td {
    background: rgba(37, 99, 235, 0.04);
}
.ww-truncate {
    display: block;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.ww-code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 11px;
}
@media (max-width: 1180px) {
    .ww-metrics { grid-template-columns: repeat(3, minmax(150px, 1fr)); }
    .ww-grid { grid-template-columns: 1fr; }
}
@media (max-width: 760px) {
    .ww-topbar { align-items: flex-start; flex-direction: column; }
    .ww-actions { justify-content: flex-start; }
    .ww-metrics,
    .ww-grid-2 { grid-template-columns: 1fr; }
    .ww-list-label { flex-basis: 110px; }
    .ww-table { min-width: 820px; }
}
</style>

<div class="ww-dash">
<div class="ww-shell">

    <div class="ww-topbar">
        <div class="ww-title">
            <span class="ww-mark" uk-icon="icon:shield;ratio:1.05"></span>
            <div>
                <h2>WireWall</h2>
                <p class="ww-subline">Last event: <?= htmlspecialchars($lastEventTime) ?> · <?= number_format($stats['total']) ?> recent requests indexed</p>
            </div>
        </div>
        <div class="ww-actions">
            <span class="ww-pill <?= $protectionClass ?>"><?= htmlspecialchars($protectionLabel) ?></span>
            <span class="ww-pill <?= $logEnabled ? 'is-good' : 'is-warn' ?>"><?= $logEnabled ? 'Logging on' : 'Logging off' ?></span>
            <a class="ww-btn" href="<?= $pageUrl ?>" title="Refresh dashboard">
                <span uk-icon="icon:refresh;ratio:0.8"></span>Refresh
            </a>
            <a class="ww-btn" href="<?= $adminUrl ?>module/edit?name=WireWall" title="Open WireWall settings">
                <span uk-icon="icon:cog;ratio:0.8"></span>Settings
            </a>
        </div>
    </div>

    <?php if (!$logEnabled): ?>
    <div class="ww-notice is-warning">
        <span uk-icon="icon:warning;ratio:0.9"></span>
        <div><strong>Logging is disabled.</strong> Enable logging in WireWall settings to populate dashboard events and charts.</div>
    </div>
    <?php endif; ?>

    <?php if ($trafficHistoryEnabled): ?>
    <div class="ww-notice">
        <span uk-icon="icon:download;ratio:0.9"></span>
        <div>
            <strong>Traffic history:</strong>
            <?= number_format($trafficStats['files']) ?> JSONL files, <?= $trafficSizeFormatted ?>.
            Latest: <code><?= htmlspecialchars($trafficStats['latest'] ?: 'not created yet') ?></code>.
            <div class="ww-actions" style="justify-content:flex-start;margin-top:8px">
                <a class="ww-btn" href="<?= $pageUrl ?>download-traffic/?range=today">Download today</a>
                <a class="ww-btn" href="<?= $pageUrl ?>download-traffic/?range=yesterday">Download yesterday</a>
                <a class="ww-btn" href="<?= $pageUrl ?>download-traffic/?range=last24h">Download last 24h</a>
                <a class="ww-btn" href="<?= $pageUrl ?>download-incident-bundle/">
                    <span uk-icon="icon:album;ratio:0.75"></span>Download AI incident bundle
                </a>
                <a class="ww-btn" href="<?= $pageUrl ?>download-settings/">
                    <span uk-icon="icon:cog;ratio:0.75"></span>Download settings for AI
                </a>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($trafficHistoryEnabled && !empty($trafficFiles)): ?>
    <section class="ww-panel">
        <div class="ww-panel-head">
            <p class="ww-head"><span uk-icon="icon:download;ratio:0.75" class="uk-margin-small-right"></span>Traffic reports</p>
            <span class="ww-pill"><?= count($trafficFiles) ?> days</span>
        </div>
        <div class="ww-scroll" style="max-height:340px">
            <table class="ww-table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Rows</th>
                        <th>Size</th>
                        <th style="width:140px">Download</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($trafficFiles as $trafficFile): ?>
                    <tr>
                        <td class="ww-code"><?= htmlspecialchars($trafficFile['date']) ?></td>
                        <td><?= number_format($trafficFile['rows']) ?></td>
                        <td><?= $trafficFile['size'] >= 1048576
                            ? round($trafficFile['size'] / 1048576, 1) . ' MB'
                            : round($trafficFile['size'] / 1024, 1) . ' KB' ?></td>
                        <td><a class="ww-btn" href="<?= $pageUrl ?>download-traffic/?date=<?= rawurlencode($trafficFile['date']) ?>">JSONL</a></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <div class="ww-panel-body">
            <form method="get" action="<?= $pageUrl ?>download-traffic/" class="ww-actions" style="justify-content:flex-start">
                <label>From <input class="uk-input uk-form-small" type="date" name="from" required></label>
                <label>To <input class="uk-input uk-form-small" type="date" name="to" required></label>
                <button class="ww-btn" type="submit"><span uk-icon="icon:album;ratio:0.75"></span>Download ZIP range</button>
            </form>
        </div>
    </section>
    <?php endif; ?>

    <div class="ww-metrics">
        <div class="ww-metric">
            <div class="ww-metric-top">
                <p class="ww-head">Blocked</p>
                <span class="ww-icon is-red" uk-icon="icon:ban;ratio:0.75"></span>
            </div>
            <div class="ww-val"><?= number_format($stats['blocked']) ?></div>
            <p class="ww-meta"><?= $stats['blockRate'] ?>% block rate</p>
        </div>

        <div class="ww-metric">
            <div class="ww-metric-top">
                <p class="ww-head">Allowed</p>
                <span class="ww-icon is-green" uk-icon="icon:check;ratio:0.75"></span>
            </div>
            <div class="ww-val"><?= number_format($stats['allowed']) ?></div>
            <p class="ww-meta">of <?= number_format($stats['total']) ?> requests</p>
        </div>

        <div class="ww-metric">
            <div class="ww-metric-top">
                <p class="ww-head">Blocked IPs</p>
                <span class="ww-icon is-amber" uk-icon="icon:warning;ratio:0.75"></span>
            </div>
            <div class="ww-val"><?= number_format($stats['uniqueIPs']) ?></div>
            <p class="ww-meta">unique sources</p>
        </div>

        <div class="ww-metric">
            <div class="ww-metric-top">
                <p class="ww-head">Active Bans</p>
                <span class="ww-icon is-violet" uk-icon="icon:lock;ratio:0.75"></span>
            </div>
            <div class="ww-val"><?= count($bans) ?></div>
            <p class="ww-meta"><?= number_format($cacheStats['ratelimit']) ?> rate counters</p>
        </div>

        <div class="ww-metric">
            <div class="ww-metric-top">
                <p class="ww-head">Cache</p>
                <span class="ww-icon is-blue" uk-icon="icon:database;ratio:0.75"></span>
            </div>
            <div class="ww-val"><?= number_format($cacheStats['total']) ?></div>
            <p class="ww-meta"><?= $sizeFormatted ?> on disk</p>
        </div>
    </div>

    <div class="ww-grid">
        <section class="ww-panel">
            <div class="ww-panel-head">
                <p class="ww-head"><span uk-icon="icon:clock;ratio:0.75" class="uk-margin-small-right"></span>Blocked requests - last 24 hours</p>
                <span class="ww-pill is-bad"><?= number_format(array_sum($hourData)) ?> hits</span>
            </div>
            <div class="ww-panel-body">
                <div class="ww-chart"><canvas id="ww-chart-hourly"></canvas></div>
            </div>
        </section>

        <section class="ww-panel">
            <div class="ww-panel-head">
                <p class="ww-head"><span uk-icon="icon:lock;ratio:0.75" class="uk-margin-small-right"></span>Active bans</p>
                <span class="ww-pill <?= count($bans) ? 'is-bad' : 'is-good' ?>"><?= count($bans) ?></span>
            </div>
            <div class="ww-panel-body">
            <?php if (empty($bans)): ?>
                <p class="ww-empty"><span uk-icon="icon:check;ratio:1"></span><br>No active bans</p>
            <?php else: ?>
                <ul class="ww-list">
                <?php foreach (array_slice($bans, 0, 14) as $ban): ?>
                    <li>
                        <span class="ww-list-label is-code"><?= htmlspecialchars($ban['ip']) ?></span>
                        <span class="ww-bar-wrap"><span class="ww-bar-fill" style="width:100%;background:var(--ww-red)"></span></span>
                        <span class="ww-ttl"><?= $formatTTL($ban['ttl']) ?></span>
                    </li>
                <?php endforeach; ?>
                <?php if (count($bans) > 14): ?>
                    <li><span class="ww-meta">+ <?= count($bans) - 14 ?> more</span></li>
                <?php endif; ?>
                </ul>
            <?php endif; ?>
            </div>
        </section>
    </div>

    <div class="ww-grid-2">
        <section class="ww-panel">
            <div class="ww-panel-head">
                <p class="ww-head"><span uk-icon="icon:tag;ratio:0.75" class="uk-margin-small-right"></span>Top block reasons</p>
            </div>
            <div class="ww-panel-body">
            <?php if (empty($stats['reasons'])): ?>
                <p class="ww-empty">No data yet</p>
            <?php else: $maxR = max($stats['reasons']); ?>
                <ul class="ww-list">
                <?php foreach ($stats['reasons'] as $reason => $cnt): ?>
                    <li>
                        <span class="ww-list-label" title="<?= htmlspecialchars($reason) ?>"><?= htmlspecialchars($reason) ?></span>
                        <span class="ww-bar-wrap"><span class="ww-bar-fill" style="width:<?= round($cnt/$maxR*100) ?>%;background:var(--ww-red)"></span></span>
                        <span class="ww-count"><?= number_format($cnt) ?></span>
                    </li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            </div>
        </section>

        <section class="ww-panel">
            <div class="ww-panel-head">
                <p class="ww-head"><span uk-icon="icon:world;ratio:0.75" class="uk-margin-small-right"></span>Top countries blocked</p>
            </div>
            <div class="ww-panel-body">
            <?php if (empty($stats['countries'])): ?>
                <p class="ww-empty">No data yet</p>
            <?php else: $maxC = max($stats['countries']); ?>
                <ul class="ww-list">
                <?php foreach ($stats['countries'] as $cc => $cnt): ?>
                    <li>
                        <span class="ww-list-label" title="<?= htmlspecialchars($cc) ?>"><?= htmlspecialchars($cc) ?></span>
                        <span class="ww-bar-wrap"><span class="ww-bar-fill" style="width:<?= round($cnt/$maxC*100) ?>%;background:var(--ww-blue)"></span></span>
                        <span class="ww-count"><?= number_format($cnt) ?></span>
                    </li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            </div>
        </section>
    </div>

    <div class="ww-grid-2">
        <section class="ww-panel">
            <div class="ww-panel-head">
                <p class="ww-head"><span uk-icon="icon:warning;ratio:0.75" class="uk-margin-small-right"></span>Top blocked IPs</p>
            </div>
            <div class="ww-panel-body">
            <?php if (empty($stats['topIPs'])): ?>
                <p class="ww-empty">No data yet</p>
            <?php else: $maxI = max($stats['topIPs']); ?>
                <ul class="ww-list">
                <?php foreach ($stats['topIPs'] as $ip => $cnt): ?>
                    <li>
                        <span class="ww-list-label is-code" title="<?= htmlspecialchars($ip) ?>"><?= htmlspecialchars($ip) ?></span>
                        <span class="ww-bar-wrap"><span class="ww-bar-fill" style="width:<?= round($cnt/$maxI*100) ?>%;background:var(--ww-amber)"></span></span>
                        <span class="ww-count"><?= number_format($cnt) ?></span>
                    </li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            </div>
        </section>

        <section class="ww-panel">
            <div class="ww-panel-head">
                <p class="ww-head"><span uk-icon="icon:database;ratio:0.75" class="uk-margin-small-right"></span>Cache breakdown</p>
                <a class="ww-btn" href="<?= $adminUrl ?>module/edit?name=WireWall" title="Manage cache">
                    <span uk-icon="icon:cog;ratio:0.75"></span>Manage
                </a>
            </div>
            <div class="ww-panel-body">
            <?php
            $cacheRows = [
                ['Rate limit counters', $cacheStats['ratelimit'], 'var(--ww-amber)'],
                ['Active bans',         $cacheStats['ban'],       'var(--ww-red)'],
                ['Proxy detection',     $cacheStats['proxy'],     'var(--ww-violet)'],
                ['GeoIP lookups',       $cacheStats['geo'],       'var(--ww-blue)'],
            ];
            $maxCV = max(array_column($cacheRows, 1) ?: [1]);
            ?>
                <ul class="ww-list">
                <?php foreach ($cacheRows as [$label, $val, $color]): ?>
                    <li>
                        <span class="ww-list-label"><?= htmlspecialchars($label) ?></span>
                        <span class="ww-bar-wrap"><span class="ww-bar-fill" style="width:<?= $maxCV > 0 ? round($val/$maxCV*100) : 0 ?>%;background:<?= $color ?>"></span></span>
                        <span class="ww-count"><?= number_format($val) ?></span>
                    </li>
                <?php endforeach; ?>
                </ul>
                <p class="ww-meta"><?= number_format($cacheStats['total']) ?> files · <?= $sizeFormatted ?></p>
            </div>
        </section>
    </div>

    <section class="ww-panel">
        <div class="ww-panel-head">
            <p class="ww-head"><span uk-icon="icon:list;ratio:0.75" class="uk-margin-small-right"></span>Recent events</p>
            <span class="ww-pill"><?= count($stats['recent']) ?> rows</span>
        </div>

        <?php if (empty($stats['recent'])): ?>
        <div class="ww-panel-body">
            <p class="ww-empty">No log entries yet</p>
        </div>
        <?php else: ?>
        <div class="ww-scroll">
            <table class="ww-table">
                <thead>
                    <tr>
                        <th style="width:112px">Time</th>
                        <th style="width:96px">Status</th>
                        <th style="width:132px">IP</th>
                        <th style="width:160px">Country</th>
                        <th style="width:170px">ASN</th>
                        <th style="width:132px">Reason</th>
                        <th>User-Agent</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($stats['recent'] as $r): ?>
                    <tr>
                        <td class="ww-code"><?= $r['time'] ? date('M d H:i:s', $r['time']) : '-' ?></td>
                        <td>
                        <?php if ($r['status'] === 'BLOCKED'): ?>
                            <span class="ww-status is-blocked">Blocked</span>
                        <?php else: ?>
                            <span class="ww-status is-allowed">Allowed</span>
                        <?php endif; ?>
                        </td>
                        <td><span class="ww-code ww-truncate" title="<?= htmlspecialchars($r['ip']) ?>"><?= htmlspecialchars($r['ip']) ?></span></td>
                        <td><span class="ww-truncate" title="<?= htmlspecialchars($r['country']) ?>"><?= htmlspecialchars($r['country'] ?: '-') ?></span></td>
                        <td title="<?= htmlspecialchars($r['asn']) ?>">
                        <?php if ($r['asn']): preg_match('/^(AS\d+)\s*(.*)/i', $r['asn'], $m); ?>
                            <span class="ww-code ww-truncate"><?= htmlspecialchars($m[1] ?? $r['asn']) ?></span>
                            <?php if (!empty($m[2])): ?>
                            <span class="ww-truncate" style="color:var(--pw-muted-color);font-size:10px"><?= htmlspecialchars($m[2]) ?></span>
                            <?php endif; ?>
                        <?php else: ?>
                            <span style="color:var(--pw-muted-color)">-</span>
                        <?php endif; ?>
                        </td>
                        <td>
                        <?php if ($r['reason']): ?>
                            <span class="ww-reason-tag" title="<?= htmlspecialchars($r['reason']) ?>"><?= htmlspecialchars($r['reason']) ?></span>
                        <?php else: ?>
                            <span style="color:var(--pw-muted-color)">-</span>
                        <?php endif; ?>
                        </td>
                        <td><span class="ww-truncate" style="color:var(--pw-muted-color);font-size:11px" title="<?= htmlspecialchars($r['ua']) ?>"><?= htmlspecialchars($r['ua'] ?: '-') ?></span></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </section>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
(function() {
    // PW sets dark-mode vars on <html> after page load via JS class toggle.
    // We defer reading until next frame so the theme class is already applied.
    var chartEl = document.getElementById('ww-chart-hourly');
    if (!chartEl) return;

    function buildChart() {
        // Read from <html> element — that's where AdminThemeUikit injects --pw-* vars
        var root  = document.documentElement;
        var cs    = getComputedStyle(root);
        var red   = cs.getPropertyValue('--pw-error-inline-text-color').trim() || '#c0392b';
        var grid  = cs.getPropertyValue('--pw-border-color').trim() || '#444';
        // For tick labels: try --pw-text-color, fall back to computed color of a real element
        var probe = document.querySelector('.uk-card-header .ww-head') || document.body;
        var tickColor = getComputedStyle(probe).color || '#aaa';

        function toRgba(color, a) {
            var d = document.createElement('div');
            d.style.color = color;
            document.body.appendChild(d);
            var rgb = getComputedStyle(d).color;
            document.body.removeChild(d);
            var m = rgb.match(/\d+/g);
            return m ? 'rgba('+m[0]+','+m[1]+','+m[2]+','+a+')' : color;
        }

        new Chart(chartEl, {
        type: 'bar',
        data: {
            labels: <?= json_encode($hourLabels) ?>,
            datasets: [{
                data:            <?= json_encode($hourData) ?>,
                backgroundColor: toRgba(red, 0.55),
                borderColor:     red,
                borderWidth:     1,
                borderRadius:    3,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid:  { display: false },
                    ticks: { color: tickColor, font: { size: 9 }, maxRotation: 0,
                        callback: function(v, i) { return i % 6 === 0 ? this.getLabelForValue(v) : ''; }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid:  { color: cs.getPropertyValue('--pw-border-color').trim() || grid },
                    ticks: { color: tickColor, font: { size: 9 }, precision: 0 }
                }
            }
        }
        });
    } // end buildChart

    // Defer to next animation frame — PW dark mode applies theme class after DOMContentLoaded
    if (document.readyState === 'complete') {
        requestAnimationFrame(buildChart);
    } else {
        window.addEventListener('load', function() { requestAnimationFrame(buildChart); });
    }
})();
</script>

</div><!-- .ww-dash -->
<?php
        return ob_get_clean();
    }
}
