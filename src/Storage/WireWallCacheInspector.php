<?php namespace ProcessWire;

/**
 * Inspects WireWall cache and traffic-history files for dashboard display.
 */
class WireWallCacheInspector {

    protected string $cacheDir;
    protected string $trafficDir;

    public function __construct(string $cacheDir, string $trafficDir) {
        $this->cacheDir = rtrim($cacheDir, '/\\') . DIRECTORY_SEPARATOR;
        $this->trafficDir = rtrim($trafficDir, '/\\') . DIRECTORY_SEPARATOR;
    }

    public function getActiveBans(): array {
        $bans = [];
        if (!is_dir($this->cacheDir)) return $bans;

        foreach (scandir($this->cacheDir) ?: [] as $file) {
            if (!str_starts_with($file, 'ban_')) continue;
            $content = @file_get_contents($this->cacheDir . $file);
            if (!$content) continue;
            $data = @unserialize($content, ['allowed_classes' => false]);
            if (!is_array($data) || !isset($data['expire'])) continue;
            if ($data['expire'] < time()) {
                @unlink($this->cacheDir . $file);
                continue;
            }

            $ip = str_replace('_', '.', preg_replace('/^ban_|\.cache$/', '', $file));
            $bans[] = [
                'ip' => $ip,
                'expires' => $data['expire'],
                'ttl' => $data['expire'] - time(),
            ];
        }

        usort($bans, static fn($a, $b) => $b['ttl'] <=> $a['ttl']);
        return $bans;
    }

    public function getCacheStats(): array {
        $stats = ['total' => 0, 'ratelimit' => 0, 'ban' => 0, 'proxy' => 0, 'geo' => 0, 'size' => 0];
        if (!is_dir($this->cacheDir)) return $stats;

        foreach (scandir($this->cacheDir) ?: [] as $file) {
            if ($file === '.' || $file === '..') continue;
            $path = $this->cacheDir . $file;
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

    public function getTrafficHistoryStats(): array {
        $stats = ['files' => 0, 'size' => 0, 'latest' => ''];
        if (!is_dir($this->trafficDir)) return $stats;

        foreach (scandir($this->trafficDir) ?: [] as $file) {
            if (!preg_match('/^traffic-\d{4}-\d{2}-\d{2}\.jsonl(?:\.gz)?$/', $file)) continue;
            $path = $this->trafficDir . $file;
            if (!is_file($path)) continue;
            $stats['files']++;
            $stats['size'] += filesize($path);
            if ($stats['latest'] === '' || $file > $stats['latest']) {
                $stats['latest'] = $file;
            }
        }

        return $stats;
    }
}
