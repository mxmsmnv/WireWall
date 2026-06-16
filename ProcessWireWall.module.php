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
 * @version 1.0.0
 * @author Maxim Semenov <maxim@smnv.org> (smnv.org)
 * @requires WireWall, ProcessWire>=3.0.200, PHP>=8.1
 */
class ProcessWireWall extends Process implements Module {

    public static function getModuleInfo() {
        return [
            'title'       => 'WireWall Dashboard',
            'summary'     => 'Firewall statistics and live event log',
            'version'     => 100,
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

        $logEnabled = (bool)($this->wire('modules')->getModuleConfigData('WireWall')['enable_stats_logging'] ?? 0);
        $adminUrl   = $this->wire('config')->urls->admin;
        $pageUrl    = $this->wire('page')->url;

        $formatTTL = fn(int $s) => $this->formatTTL($s);

        // ---- inline HTML output ----
        ob_start();
?>
<style>
/* WireWall Dashboard */
.ww-dash .uk-card-header {
    padding: 12px 15px;
}
.ww-dash .uk-card-body {
    padding: 15px;
}
.ww-dash .uk-card-small.uk-card-body {
    padding: 15px;
}
.ww-val {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    color: var(--pw-text-color);
    letter-spacing: -0.02em;
}
.ww-accent {
    width: 28px;
    height: 3px;
    border-radius: 2px;
    margin-bottom: 10px;
}
.ww-head {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--pw-muted-color);
    margin: 0;
}
.ww-chart { position: relative; height: 190px; }
.ww-scroll { max-height: 420px; overflow: auto; }
.ww-bar-wrap {
    display: block;
    height: 4px;
    border-radius: 2px;
    background: var(--pw-border-color);
    overflow: hidden;
    flex: 1;
    min-width: 0;
}
.ww-bar-fill {
    display: block;
    height: 100%;
    border-radius: 2px;
}
.ww-ttl {
    font-size: 10px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 3px;
    background: var(--pw-alert-danger);
    color: var(--pw-text-color);
    white-space: nowrap;
}
.ww-reason-tag {
    display: inline-block;
    font-size: 10px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 3px;
    background: var(--pw-inputs-background);
    border: 1px solid var(--pw-border-color);
    color: var(--pw-text-color);
}
</style>

<div class="ww-dash">

<?php if (!$logEnabled): ?>
<div class="uk-alert uk-alert-warning" uk-alert>
    <a class="uk-alert-close" uk-close></a>
    <p><span uk-icon="icon:warning;ratio:0.9" class="uk-margin-small-right"></span><strong>Logging is disabled.</strong> Enable <em>Enable Logging</em> in <a href="<?= $adminUrl ?>module/edit?name=WireWall">WireWall settings</a> to populate the dashboard.</p>
</div>
<?php endif; ?>

<!-- Stat cards -->
<div class="uk-grid-small uk-child-width-1-5@l uk-child-width-1-3@m uk-child-width-1-2 uk-margin-medium-bottom" uk-grid>

    <div><div class="uk-card uk-card-default uk-card-small uk-card-body">
        <div class="ww-accent" style="background:var(--pw-error-inline-text-color)"></div>
        <p class="ww-head uk-margin-small-bottom">Blocked</p>
        <div class="ww-val"><?= number_format($stats['blocked']) ?></div>
        <p class="uk-text-meta uk-margin-small-top"><?= $stats['blockRate'] ?>% block rate</p>
    </div></div>

    <div><div class="uk-card uk-card-default uk-card-small uk-card-body">
        <div class="ww-accent" style="background:var(--pw-alert-success)"></div>
        <p class="ww-head uk-margin-small-bottom">Allowed</p>
        <div class="ww-val"><?= number_format($stats['allowed']) ?></div>
        <p class="uk-text-meta uk-margin-small-top">of <?= number_format($stats['total']) ?> requests</p>
    </div></div>

    <div><div class="uk-card uk-card-default uk-card-small uk-card-body">
        <div class="ww-accent" style="background:#f59e0b"></div>
        <p class="ww-head uk-margin-small-bottom">Unique IPs blocked</p>
        <div class="ww-val"><?= number_format($stats['uniqueIPs']) ?></div>
        <p class="uk-text-meta uk-margin-small-top">across <?= number_format($stats['total']) ?> requests</p>
    </div></div>

    <div><div class="uk-card uk-card-default uk-card-small uk-card-body">
        <div class="ww-accent" style="background:#8b5cf6"></div>
        <p class="ww-head uk-margin-small-bottom">Active Bans</p>
        <div class="ww-val"><?= count($bans) ?></div>
        <p class="uk-text-meta uk-margin-small-top"><?= $cacheStats['ratelimit'] ?> rate limit counters</p>
    </div></div>

    <div><div class="uk-card uk-card-default uk-card-small uk-card-body">
        <div class="ww-accent" style="background:var(--pw-main-color)"></div>
        <p class="ww-head uk-margin-small-bottom">Cache files</p>
        <div class="ww-val"><?= $cacheStats['total'] ?></div>
        <p class="uk-text-meta uk-margin-small-top"><?= $sizeFormatted ?> on disk</p>
    </div></div>

</div>

<!-- Row 1: Chart + Bans -->
<div class="uk-grid-small uk-margin-medium-bottom uk-grid-match" uk-grid>

    <div class="uk-width-2-3@m">
        <div class="uk-card uk-card-default">
            <div class="uk-card-header">
                <p class="ww-head"><span uk-icon="icon:clock;ratio:0.75" class="uk-margin-small-right"></span>Blocked requests — last 24 hours</p>
            </div>
            <div class="uk-card-body">
                <div class="ww-chart"><canvas id="ww-chart-hourly"></canvas></div>
            </div>
        </div>
    </div>

    <div class="uk-width-1-3@m">
        <div class="uk-card uk-card-default">
            <div class="uk-card-header uk-flex uk-flex-between uk-flex-middle">
                <p class="ww-head"><span uk-icon="icon:ban;ratio:0.75" class="uk-margin-small-right"></span>Active Bans</p>
                <span class="uk-badge"><?= count($bans) ?></span>
            </div>
            <div class="uk-card-body uk-padding-small">
            <?php if (empty($bans)): ?>
                <p class="uk-text-muted uk-text-small uk-text-center uk-margin-remove" style="padding:32px 0">
                    <span uk-icon="icon:check;ratio:1" class="uk-display-block uk-margin-small-bottom"></span>No active bans
                </p>
            <?php else: ?>
                <ul class="uk-list uk-list-divider uk-margin-remove uk-text-small">
                <?php foreach (array_slice($bans, 0, 14) as $ban): ?>
                <li class="uk-flex uk-flex-between uk-flex-middle">
                    <code style="font-size:11px"><?= htmlspecialchars($ban['ip']) ?></code>
                    <span class="ww-ttl"><?= $formatTTL($ban['ttl']) ?></span>
                </li>
                <?php endforeach; ?>
                <?php if (count($bans) > 14): ?>
                <li class="uk-text-muted uk-text-center uk-text-small">+ <?= count($bans) - 14 ?> more</li>
                <?php endif; ?>
                </ul>
            <?php endif; ?>
            </div>
        </div>
    </div>

</div>

<!-- Row 2: Reasons + Countries -->
<div class="uk-grid-small uk-margin-medium-bottom uk-grid-match" uk-grid>

    <div class="uk-width-1-2@m">
        <div class="uk-card uk-card-default">
            <div class="uk-card-header">
                <p class="ww-head"><span uk-icon="icon:tag;ratio:0.75" class="uk-margin-small-right"></span>Top Block Reasons</p>
            </div>
            <div class="uk-card-body uk-padding-small">
            <?php if (empty($stats['reasons'])): ?>
                <p class="uk-text-muted uk-text-small uk-text-center" style="padding:24px 0"><em>No data yet</em></p>
            <?php else: $maxR = max($stats['reasons']); ?>
                <ul class="uk-list uk-list-divider uk-margin-remove">
                <?php foreach ($stats['reasons'] as $reason => $cnt): ?>
                <li class="uk-flex uk-flex-middle" style="gap:10px;padding:5px 0">
                    <span style="flex:0 0 105px;font-size:12px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                          title="<?= htmlspecialchars($reason) ?>"><?= htmlspecialchars($reason) ?></span>
                    <span class="ww-bar-wrap">
                        <span class="ww-bar-fill" style="width:<?= round($cnt/$maxR*100) ?>%;background:var(--pw-error-inline-text-color)"></span>
                    </span>
                    <span class="uk-text-muted" style="flex:0 0 32px;text-align:right;font-size:11px;font-weight:600"><?= number_format($cnt) ?></span>
                </li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="uk-width-1-2@m">
        <div class="uk-card uk-card-default">
            <div class="uk-card-header">
                <p class="ww-head"><span uk-icon="icon:world;ratio:0.75" class="uk-margin-small-right"></span>Top Countries (blocked)</p>
            </div>
            <div class="uk-card-body uk-padding-small">
            <?php if (empty($stats['countries'])): ?>
                <p class="uk-text-muted uk-text-small uk-text-center" style="padding:24px 0"><em>No data yet</em></p>
            <?php else: $maxC = max($stats['countries']); ?>
                <ul class="uk-list uk-list-divider uk-margin-remove">
                <?php foreach ($stats['countries'] as $cc => $cnt): ?>
                <li class="uk-flex uk-flex-middle" style="gap:10px;padding:5px 0">
                    <span style="flex:0 0 36px;font-size:12px;font-weight:600"><?= htmlspecialchars($cc) ?></span>
                    <span class="ww-bar-wrap">
                        <span class="ww-bar-fill" style="width:<?= round($cnt/$maxC*100) ?>%;background:#6366f1"></span>
                    </span>
                    <span class="uk-text-muted" style="flex:0 0 32px;text-align:right;font-size:11px;font-weight:600"><?= number_format($cnt) ?></span>
                </li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            </div>
        </div>
    </div>

</div>

<!-- Row 3: IPs + Cache -->
<div class="uk-grid-small uk-margin-medium-bottom uk-grid-match" uk-grid>

    <div class="uk-width-1-2@m">
        <div class="uk-card uk-card-default">
            <div class="uk-card-header">
                <p class="ww-head"><span uk-icon="icon:warning;ratio:0.75" class="uk-margin-small-right"></span>Top Blocked IPs</p>
            </div>
            <div class="uk-card-body uk-padding-small">
            <?php if (empty($stats['topIPs'])): ?>
                <p class="uk-text-muted uk-text-small uk-text-center" style="padding:24px 0"><em>No data yet</em></p>
            <?php else: $maxI = max($stats['topIPs']); ?>
                <ul class="uk-list uk-list-divider uk-margin-remove">
                <?php foreach ($stats['topIPs'] as $ip => $cnt): ?>
                <li class="uk-flex uk-flex-middle" style="gap:10px;padding:5px 0">
                    <span style="flex:0 0 120px;font-size:11px;font-family:monospace;color:var(--pw-text-color)"><?= htmlspecialchars($ip) ?></span>
                    <span class="ww-bar-wrap">
                        <span class="ww-bar-fill" style="width:<?= round($cnt/$maxI*100) ?>%;background:#f59e0b"></span>
                    </span>
                    <span class="uk-text-muted" style="flex:0 0 32px;text-align:right;font-size:11px;font-weight:600"><?= number_format($cnt) ?></span>
                </li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="uk-width-1-2@m">
        <div class="uk-card uk-card-default">
            <div class="uk-card-header">
                <p class="ww-head"><span uk-icon="icon:database;ratio:0.75" class="uk-margin-small-right"></span>Cache Breakdown</p>
            </div>
            <div class="uk-card-body uk-padding-small">
            <?php
            $cacheRows = [
                ['Rate Limit Counters', $cacheStats['ratelimit'], '#f59e0b'],
                ['Active Bans',         $cacheStats['ban'],       'var(--pw-error-inline-text-color)'],
                ['Proxy Detection',     $cacheStats['proxy'],     '#8b5cf6'],
                ['GeoIP Lookups',       $cacheStats['geo'],       'var(--pw-main-color)'],
            ];
            $maxCV = max(array_column($cacheRows, 1) ?: [1]);
            ?>
            <ul class="uk-list uk-list-divider uk-margin-remove">
            <?php foreach ($cacheRows as [$label, $val, $color]): ?>
            <li class="uk-flex uk-flex-middle" style="gap:10px;padding:5px 0">
                <span style="flex:0 0 145px;font-size:12px"><?= $label ?></span>
                <span class="ww-bar-wrap">
                    <span class="ww-bar-fill" style="width:<?= $maxCV > 0 ? round($val/$maxCV*100) : 0 ?>%;background:<?= $color ?>"></span>
                </span>
                <span class="uk-text-muted" style="flex:0 0 32px;text-align:right;font-size:11px;font-weight:600"><?= number_format($val) ?></span>
            </li>
            <?php endforeach; ?>
            </ul>
            <p class="uk-text-small uk-text-muted uk-margin-small-top">
                <?= number_format($cacheStats['total']) ?> files &bull; <?= $sizeFormatted ?>
                &bull; <a href="<?= $adminUrl ?>module/edit?name=WireWall" class="uk-link-muted">Manage cache &rarr;</a>
            </p>
            </div>
        </div>
    </div>

</div>

<!-- Recent Events -->
<div class="uk-card uk-card-default uk-margin-medium-bottom">
    <div class="uk-card-header uk-flex uk-flex-between uk-flex-middle">
        <p class="ww-head">
            <span uk-icon="icon:list;ratio:0.75" class="uk-margin-small-right"></span>Recent Events
            <span class="uk-badge uk-margin-small-left"><?= count($stats['recent']) ?></span>
        </p>
        <a href="<?= $pageUrl ?>" class="uk-link-muted uk-text-small uk-flex uk-flex-middle" style="gap:4px">
            <span uk-icon="icon:refresh;ratio:0.8"></span>Refresh
        </a>
    </div>

    <?php if (empty($stats['recent'])): ?>
    <div class="uk-card-body">
        <p class="uk-text-muted uk-text-center"><em>No log entries. Enable logging in WireWall settings.</em></p>
    </div>
    <?php else: ?>
    <div class="ww-scroll">
        <table class="uk-table uk-table-divider uk-table-small uk-table-hover" style="margin:0">
            <thead style="position:sticky;top:0;z-index:1;background:var(--pw-blocks-background)">
                <tr>
                    <th style="width:110px">Time</th>
                    <th style="width:80px">Status</th>
                    <th style="width:125px">IP</th>
                    <th style="width:160px">Country</th>
                    <th style="width:150px">ASN</th>
                    <th style="width:120px">Reason</th>
                    <th>User-Agent</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($stats['recent'] as $r): ?>
            <tr>
                <td class="uk-text-meta uk-text-nowrap"><?= $r['time'] ? date('M d H:i:s', $r['time']) : '—' ?></td>
                <td>
                <?php if ($r['status'] === 'BLOCKED'): ?>
                    <span class="uk-label uk-label-danger" style="font-size:9px;letter-spacing:.06em">BLOCKED</span>
                <?php else: ?>
                    <span class="uk-label uk-label-success" style="font-size:9px;letter-spacing:.06em">ALLOWED</span>
                <?php endif; ?>
                </td>
                <td style="font-family:monospace;font-size:11px;color:var(--pw-text-color)"><?= htmlspecialchars($r['ip']) ?></td>
                <td class="uk-text-small" style="white-space:nowrap"><?= htmlspecialchars($r['country']) ?></td>
                <td title="<?= htmlspecialchars($r['asn']) ?>">
                <?php if ($r['asn']): preg_match('/^(AS\d+)\s*(.*)/i', $r['asn'], $m); ?>
                    <span style="font-size:11px;font-family:monospace;color:var(--pw-text-color)"><?= htmlspecialchars($m[1] ?? $r['asn']) ?></span>
                    <?php if (!empty($m[2])): ?>
                    <br><span class="uk-text-muted" style="font-size:10px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:140px"><?= htmlspecialchars($m[2]) ?></span>
                    <?php endif; ?>
                <?php else: ?><span class="uk-text-muted">—</span><?php endif; ?>
                </td>
                <td>
                <?php if ($r['reason']): ?>
                    <span class="ww-reason-tag" style="white-space:nowrap"><?= htmlspecialchars($r['reason']) ?></span>
                <?php else: ?>
                    <span class="uk-text-muted">—</span>
                <?php endif; ?>
                </td>
                <td class="uk-text-muted uk-text-nowrap" style="font-size:10px;max-width:220px;overflow:hidden;text-overflow:ellipsis"
                    title="<?= htmlspecialchars($r['ua']) ?>"><?= htmlspecialchars($r['ua']) ?: '—' ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
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