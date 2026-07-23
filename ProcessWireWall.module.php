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
 * @version 1.11.0
 * @author Maxim Semenov <maxim@smnv.org> (smnv.org)
 * @requires WireWall, ProcessWire>=3.0.200, PHP>=8.1
 */
class ProcessWireWall extends Process implements Module {

    protected $trafficReportService = null;
    protected $cacheInspector = null;
    protected $dashboardStats = null;

    public static function getModuleInfo() {
        return [
            'title'       => 'WireWall Dashboard',
            'summary'     => 'Firewall statistics and live event log',
            'version'     => 1110,
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

    protected function getTrafficReportService(): WireWallTrafficReportService {
        if ($this->trafficReportService instanceof WireWallTrafficReportService) {
            return $this->trafficReportService;
        }

        require_once __DIR__ . '/src/Storage/WireWallTrafficReportService.php';
        $this->trafficReportService = new WireWallTrafficReportService(
            $this->getTrafficHistoryDir(),
            $this->getCacheDir()
        );
        return $this->trafficReportService;
    }

    protected function getCacheInspector(): WireWallCacheInspector {
        if ($this->cacheInspector instanceof WireWallCacheInspector) {
            return $this->cacheInspector;
        }

        require_once __DIR__ . '/src/Storage/WireWallCacheInspector.php';
        $this->cacheInspector = new WireWallCacheInspector(
            $this->getCacheDir(),
            $this->getTrafficHistoryDir()
        );
        return $this->cacheInspector;
    }

    protected function getDashboardStats(): WireWallDashboardStats {
        if ($this->dashboardStats instanceof WireWallDashboardStats) {
            return $this->dashboardStats;
        }

        require_once __DIR__ . '/src/Dashboard/WireWallDashboardStats.php';
        $this->dashboardStats = new WireWallDashboardStats($this->getLogPath());
        return $this->dashboardStats;
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
        return $this->getTrafficReportService()->getTrafficFileForDate($date);
    }

    protected function isValidDate(string $date): bool {
        return $this->getTrafficReportService()->isValidDate($date);
    }

    protected function countJsonlRows(string $path): int {
        return $this->getTrafficReportService()->countJsonlRows($path);
    }

    protected function listTrafficFiles(): array {
        return $this->getTrafficReportService()->listTrafficFiles();
    }

    protected function createDateRangeZip(string $from, string $to): string {
        return $this->getTrafficReportService()->createDateRangeZip($from, $to);
    }

    protected function createLast24HoursReport(): string {
        return $this->getTrafficReportService()->createLast24HoursReport();
    }

    protected function summarizeTraffic(array $paths): array {
        return $this->getTrafficReportService()->summarizeTraffic($paths);
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
        return $this->getDashboardStats()->readLogLines($limit);
    }

    /**
     * Parse one log line into a structured array.
     *
     * PW log format: "YYYY-MM-DD HH:MM:SS\tUSER\tURL\tMESSAGE"  (4 tab-separated columns)
     * WireWall msg : "STATUS | COUNTRY (City, Region) | IP | ASN | UA: ... | reason"
     */
    protected function parseLine(string $line): ?array {
        return $this->getDashboardStats()->parseLine($line);
    }

    // -------------------------------------------------------------------------
    // Cache inspection
    // -------------------------------------------------------------------------

    protected function getActiveBans(): array {
        return $this->getCacheInspector()->getActiveBans();
    }

    protected function getCacheStats(): array {
        return $this->getCacheInspector()->getCacheStats();
    }

    protected function getTrafficHistoryStats(): array {
        return $this->getCacheInspector()->getTrafficHistoryStats();
    }

    // -------------------------------------------------------------------------
    // Statistics aggregation
    // -------------------------------------------------------------------------

    protected function buildStats(array $lines): array {
        return $this->getDashboardStats()->buildStats($lines);
    }

    protected function formatTTL(int $seconds): string {
        return $this->getDashboardStats()->formatTTL($seconds);
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

        $this->wire('config')->styles->add(
            $this->wire('config')->urls->siteModules . 'WireWall/assets/dashboard.css?v=1110'
        );
        $this->wire('config')->scripts->add('https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js');
        $this->wire('config')->scripts->add(
            $this->wire('config')->urls->siteModules . 'WireWall/assets/dashboard.js?v=1110'
        );
        $hourLabelsAttr = htmlspecialchars(json_encode($hourLabels), ENT_QUOTES, 'UTF-8');
        $hourDataAttr = htmlspecialchars(json_encode($hourData), ENT_QUOTES, 'UTF-8');

        // ---- inline HTML output ----
        ob_start();
?>
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
                <div class="ww-chart"><canvas id="ww-chart-hourly" data-labels="<?= $hourLabelsAttr ?>" data-values="<?= $hourDataAttr ?>"></canvas></div>
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

</div><!-- .ww-dash -->
<?php
        return ob_get_clean();
    }
}
