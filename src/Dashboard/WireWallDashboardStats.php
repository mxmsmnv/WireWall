<?php namespace ProcessWire;

/**
 * Reads WireWall logs and builds dashboard statistics.
 */
class WireWallDashboardStats {

    protected string $logPath;

    public function __construct(string $logPath) {
        $this->logPath = $logPath;
    }

    public function readLogLines(int $limit = 5000): array {
        if (!file_exists($this->logPath)) return [];

        $fp = fopen($this->logPath, 'rb');
        if (!$fp) return [];

        fseek($fp, 0, SEEK_END);
        $pos = ftell($fp);
        $buffer = '';
        $lines = [];
        $count = 0;

        while ($pos > 0 && $count < $limit) {
            $chunk = min(4096, $pos);
            $pos -= $chunk;
            fseek($fp, $pos);
            $buffer = fread($fp, $chunk) . $buffer;
            $found = explode("\n", $buffer);
            $complete = array_slice($found, 1);
            $count += count($complete);
            $buffer = $found[0];
            $lines = array_merge($complete, $lines);
        }
        if ($buffer !== '') $lines = array_merge([$buffer], $lines);
        fclose($fp);

        $lines = array_filter(array_map('trim', $lines));
        return array_slice(array_values($lines), -$limit);
    }

    public function parseLine(string $line): ?array {
        $timestamp = '';
        $message = $line;

        if (str_contains($line, "\t")) {
            $columns = explode("\t", $line);
            $timestamp = trim($columns[0] ?? '');
            $message = '';
            foreach (array_reverse($columns) as $column) {
                $column = trim($column);
                if (str_starts_with($column, 'BLOCKED') || str_starts_with($column, 'ALLOWED')) {
                    $message = $column;
                    break;
                }
            }
            if ($message === '') $message = trim(end($columns));
        }

        $parts = array_map('trim', explode(' | ', $message));
        $status = $parts[0] ?? '';
        if (!in_array($status, ['BLOCKED', 'ALLOWED'], true)) return null;

        $country = $parts[1] ?? '';
        $ip = $parts[2] ?? '';
        $asn = $ua = $reason = $countryCode = '';

        for ($i = 3; $i < count($parts); $i++) {
            $part = trim($parts[$i]);
            if (str_starts_with($part, 'UA: ')) {
                $ua = substr($part, 4);
            } elseif (preg_match('/^AS\d+\s/', $part) || preg_match('/^AS\d+$/', $part)) {
                $asn = $part;
            } elseif ($part !== '') {
                $reason = $part;
            }
        }

        if (preg_match('/^([A-Z]{2})(\s|$|\s\()/', $country, $match)) {
            $countryCode = $match[1];
        }

        $time = $timestamp ? (strtotime($timestamp) ?: 0) : 0;
        return compact('time', 'status', 'country', 'countryCode', 'ip', 'asn', 'ua', 'reason');
    }

    public function buildStats(array $lines): array {
        $total = $blocked = $allowed = 0;
        $reasons = $countries = $ips = [];
        $byHour = array_fill(0, 24, 0);
        $recent = [];
        $cutoff24 = time() - 86400;

        foreach ($lines as $line) {
            $row = $this->parseLine($line);
            if (!$row) continue;
            $total++;

            if ($row['status'] === 'BLOCKED') {
                $blocked++;
                $key = $row['reason'] ?: 'unknown';
                $reasons[$key] = ($reasons[$key] ?? 0) + 1;
                if ($row['countryCode']) {
                    $countries[$row['countryCode']] = ($countries[$row['countryCode']] ?? 0) + 1;
                }
                if ($row['ip']) {
                    $ips[$row['ip']] = ($ips[$row['ip']] ?? 0) + 1;
                }
                if ($row['time'] >= $cutoff24) {
                    $byHour[(int)date('G', $row['time'])]++;
                }
            } else {
                $allowed++;
            }

            $recent[] = $row;
        }

        arsort($reasons);
        arsort($countries);
        arsort($ips);

        return [
            'total' => $total,
            'blocked' => $blocked,
            'allowed' => $allowed,
            'blockRate' => $total > 0 ? round($blocked / $total * 100, 1) : 0,
            'uniqueIPs' => count($ips),
            'reasons' => array_slice($reasons, 0, 10, true),
            'countries' => array_slice($countries, 0, 10, true),
            'topIPs' => array_slice($ips, 0, 10, true),
            'byHour' => $byHour,
            'recent' => array_reverse(array_slice($recent, -50)),
        ];
    }

    public function formatTTL(int $seconds): string {
        $hours = (int)($seconds / 3600);
        $minutes = (int)(($seconds % 3600) / 60);
        $remainingSeconds = $seconds % 60;
        if ($hours > 0) return "{$hours}h {$minutes}m";
        if ($minutes > 0) return "{$minutes}m {$remainingSeconds}s";
        return "{$remainingSeconds}s";
    }
}
