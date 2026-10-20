<?php namespace ProcessWire;

/** Official Apple egress ranges only; no browser/ASN heuristics or visitor-IP requests. */
final class WireWallAppleRelayVerifier {
    public const SOURCE = 'https://mask-api.icloud.com/egress-ip-ranges.csv';
    public const REFRESH_SECONDS = 86400;
    public const MAX_AGE_SECONDS = 604800;
    private const MAX_BYTES = 24000000;
    private $fetch;
    private $clock;
    private ?array $snapshot = null;

    public function __construct(private string $directory, ?callable $fetch = null, ?callable $clock = null) {
        $this->fetch = $fetch ?? [self::class, 'download'];
        $this->clock = $clock ?? static fn(): int => time();
    }

    /** Nonblocking refresh lock; one failed attempt per hour, no per-request download loop. */
    public function refresh(bool $force = false): array {
        $now = ($this->clock)();
        $this->load();
        if (!$force && $this->fresh($now, self::REFRESH_SECONDS)) return $this->status();
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true)) return ['available' => false, 'error' => 'cache-directory'];
        $lock = @fopen($this->directory . '/refresh.lock', 'c+');
        if (!$lock) return ['available' => false, 'error' => 'cache-lock'];
        if (!flock($lock, LOCK_EX | LOCK_NB)) { fclose($lock); return $this->status(); }
        $temp = null;
        try {
            rewind($lock);
            $lastAttempt = (int) stream_get_contents($lock);
            if (!$force && $lastAttempt > $now - 3600) return $this->status();
            ftruncate($lock, 0); rewind($lock); fwrite($lock, (string) $now); fflush($lock);
            $body = ($this->fetch)(self::SOURCE);
            if (!is_string($body)) throw new \RuntimeException('feed-download');
            $ranges = self::parse($body);
            $snapshot = ['version' => 1, 'fetched_at' => $now, 'source' => self::SOURCE,
                'sha256' => hash('sha256', $body), 'ranges' => $ranges];
            $json = json_encode($snapshot, JSON_THROW_ON_ERROR);
            $temp = tempnam($this->directory, '.relay-');
            if ($temp === false || file_put_contents($temp, $json, LOCK_EX) !== strlen($json)
                || !chmod($temp, 0600) || !rename($temp, $this->directory . '/ranges.json')) {
                throw new \RuntimeException('cache-write');
            }
            $temp = null;
            $this->snapshot = $snapshot;
            return $this->status();
        } catch (\Throwable $e) {
            // Preserve the last verified snapshot; never turn a feed failure into an allow-all.
            return $this->status() + ['error' => 'refresh-failed'];
        } finally {
            if (is_string($temp) && is_file($temp)) @unlink($temp);
            flock($lock, LOCK_UN); fclose($lock);
        }
    }

    public function verify(string $ip): bool {
        $packed = @inet_pton($ip);
        if ($packed === false) return false;
        $this->load();
        if (!$this->fresh(($this->clock)(), self::REFRESH_SECONDS)) $this->refresh();
        if (!$this->fresh(($this->clock)(), self::MAX_AGE_SECONDS)) return false;
        $key = bin2hex($packed);
        $ranges = $this->snapshot['ranges'][strlen($packed) === 4 ? '4' : '6'] ?? [];
        $low = 0; $high = count($ranges) - 1;
        while ($low <= $high) {
            $mid = intdiv($low + $high, 2);
            [$start, $end] = $ranges[$mid];
            if (strcmp($key, $start) < 0) $high = $mid - 1;
            elseif (strcmp($key, $end) > 0) $low = $mid + 1;
            else return true;
        }
        return false;
    }

    public function status(): array {
        $this->load();
        return ['available' => $this->fresh(($this->clock)(), self::MAX_AGE_SECONDS),
            'source' => self::SOURCE, 'fetched_at' => $this->snapshot['fetched_at'] ?? null,
            'sha256' => $this->snapshot['sha256'] ?? null,
            'range_count' => count($this->snapshot['ranges']['4'] ?? []) + count($this->snapshot['ranges']['6'] ?? [])];
    }

    private function fresh(int $now, int $age): bool {
        $at = (int) ($this->snapshot['fetched_at'] ?? 0);
        return $at > 0 && $at <= $now + 60 && $at > $now - $age;
    }

    private function load(): void {
        if ($this->snapshot !== null) return;
        $this->snapshot = [];
        $file = $this->directory . '/ranges.json';
        if (!is_file($file) || filesize($file) > 4000000) return;
        $value = json_decode((string) @file_get_contents($file), true);
        if (!is_array($value) || ($value['version'] ?? null) !== 1 || ($value['source'] ?? '') !== self::SOURCE
            || !preg_match('/^[a-f0-9]{64}$/D', (string) ($value['sha256'] ?? ''))) return;
        foreach (['4' => 8, '6' => 32] as $family => $length) {
            if (!isset($value['ranges'][$family]) || !is_array($value['ranges'][$family]) || !$value['ranges'][$family]) return;
            $last = null;
            foreach ($value['ranges'][$family] as $range) {
                if (!is_array($range) || count($range) !== 2 || !isset($range[0], $range[1])
                    || !is_string($range[0]) || !is_string($range[1])
                    || !preg_match('/^[a-f0-9]{' . $length . '}$/D', $range[0])
                    || !preg_match('/^[a-f0-9]{' . $length . '}$/D', $range[1])
                    || strcmp($range[0], $range[1]) > 0 || ($last !== null && strcmp($range[0], $last) <= 0)) return;
                $last = $range[1];
            }
        }
        $this->snapshot = $value;
    }

    /** Strict, bounded Apple five-column CSV; coalesce exact adjacent ranges for cheap lookups. */
    public static function parse(string $body): array {
        if ($body === '' || strlen($body) > self::MAX_BYTES) throw new \RuntimeException('feed-size-or-truncation');
        $stream = fopen('php://temp/maxmemory:1048576', 'w+');
        fwrite($stream, $body); rewind($stream);
        $rows = 0; $sets = ['4' => [], '6' => []];
        try {
            while (($row = fgetcsv($stream, 512, ',', '"', '')) !== false) {
                if (count($row) !== 5 || ++$rows > 500000 || !preg_match('/^[A-Z]{2}$/D', $row[1])) throw new \RuntimeException('feed-schema');
                if (!preg_match('~^([0-9a-fA-F:.]+)/([0-9]{1,3})$~D', $row[0], $match)) throw new \RuntimeException('feed-cidr');
                $packed = @inet_pton($match[1]); $bits = (int) $match[2];
                if ($packed === false) throw new \RuntimeException('feed-ip');
                $max = strlen($packed) * 8;
                if ($bits < ($max === 32 ? 16 : 32) || $bits > $max) throw new \RuntimeException('feed-prefix');
                $start = ''; $end = '';
                for ($i = 0; $i < strlen($packed); $i++) {
                    $remaining = max(0, min(8, $bits - $i * 8));
                    $mask = (0xff << (8 - $remaining)) & 0xff;
                    $start .= chr(ord($packed[$i]) & $mask);
                    $end .= chr((ord($packed[$i]) & $mask) | (0xff ^ $mask));
                }
                if ($packed !== $start) throw new \RuntimeException('feed-network-boundary');
                $family = $max === 32 ? '4' : '6';
                $bucket = bin2hex(substr($start, 0, 2));
                if (!isset($sets[$family][$bucket])) $sets[$family][$bucket] = '';
                $sets[$family][$bucket] .= $start . $end;
            }
        } finally { fclose($stream); }
        if ($rows < 100 || !$sets['4'] || !$sets['6']) throw new \RuntimeException('feed-incomplete');
        $result = [];
        foreach (['4' => 4, '6' => 16] as $family => $width) {
            ksort($sets[$family], SORT_STRING); $merged = [];
            foreach ($sets[$family] as $bucket => $records) {
                $ranges = str_split($records, $width * 2);
                sort($ranges, SORT_STRING);
                unset($sets[$family][$bucket]);
                foreach ($ranges as $record) {
                $start = bin2hex(substr($record, 0, $width));
                $end = bin2hex(substr($record, $width));
                $last = count($merged) - 1;
                $adjacent = $last >= 0 ? self::increment($merged[$last][1]) : null;
                if ($last >= 0 && (strcmp($start, $merged[$last][1]) <= 0 || ($adjacent !== null && strcmp($start, $adjacent) <= 0))) {
                    if (strcmp($end, $merged[$last][1]) > 0) $merged[$last][1] = $end;
                } else $merged[] = [$start, $end];
                }
            }
            $result[$family] = $merged;
        }
        return $result;
    }

    private static function increment(string $hex): ?string {
        $bytes = hex2bin($hex);
        for ($i = strlen($bytes) - 1; $i >= 0; $i--) {
            $n = ord($bytes[$i]); $bytes[$i] = chr(($n + 1) & 0xff);
            if ($n < 255) return bin2hex($bytes);
        }
        return null;
    }

    public static function download(string $url): string {
        if ($url !== self::SOURCE || !function_exists('curl_init')) throw new \RuntimeException('feed-transport');
        $body = ''; $curl = curl_init(self::SOURCE);
        curl_setopt_array($curl, [CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 10, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_USERAGENT => 'WireWall/1.14.0 AppleRelayFeed',
            CURLOPT_WRITEFUNCTION => static function($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > self::MAX_BYTES) return 0;
                $body .= $chunk; return strlen($chunk);
            }]);
        try {
            if (curl_exec($curl) === false || curl_getinfo($curl, CURLINFO_RESPONSE_CODE) !== 200) throw new \RuntimeException('feed-http');
            return $body;
        } finally { if (PHP_VERSION_ID < 80500) curl_close($curl); }
    }
}
