<?php namespace ProcessWire;

/**
 * Private, lock-safe operational state for emergency rules, audits, snapshots,
 * and notification events. No file is stored below the public document root.
 */
final class WireWallOperationsStore {
    public function __construct(private string $directory) {
        $this->directory = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . 'operations' . DIRECTORY_SEPARATOR;
    }

    public function addEmergencyRule(string $type, string $value, int $ttlSeconds, array $meta = []): array {
        $type = strtolower(trim($type));
        $value = trim($value);
        if (!in_array($type, ['ip', 'asn', 'country', 'datacenter'], true) || $value === '') {
            throw new \InvalidArgumentException('Invalid emergency rule.');
        }
        if ($type === 'ip' && filter_var($value, FILTER_VALIDATE_IP) === false) {
            throw new \InvalidArgumentException('Invalid IP address.');
        }
        if ($type === 'country' && !preg_match('/^[A-Za-z]{2}$/', $value)) {
            throw new \InvalidArgumentException('Country must be an ISO-2 code.');
        }
        if ($type === 'asn' && !preg_match('/^(?:AS)?\d+$/i', $value)) {
            throw new \InvalidArgumentException('ASN must be numeric, optionally prefixed with AS.');
        }
        $now = time();
        $rule = [
            'id' => bin2hex(random_bytes(8)),
            'type' => $type,
            'value' => $type === 'country' || $type === 'asn' ? strtoupper($value) : $value,
            'created_at' => date('c', $now),
            'created_by' => (string) ($meta['user'] ?? ''),
            'expires_at' => date('c', $now + max(300, min(604800, $ttlSeconds))),
            'reason' => substr(trim((string) ($meta['reason'] ?? 'Emergency dashboard block')), 0, 240),
        ];
        $rules = $this->getEmergencyRules();
        $rules[] = $rule;
        $this->writeJson('emergency-rules.json', $rules);
        $this->audit('emergency_rule_created', $rule);
        return $rule;
    }

    public function removeEmergencyRule(string $id, string $user = ''): bool {
        $rules = $this->getEmergencyRules();
        $kept = array_values(array_filter($rules, static fn(array $rule): bool => ($rule['id'] ?? '') !== $id));
        if (count($kept) === count($rules)) return false;
        $this->writeJson('emergency-rules.json', $kept);
        $this->audit('emergency_rule_removed', ['id' => $id, 'user' => $user]);
        return true;
    }

    public function getEmergencyRules(): array {
        $rules = $this->readJson('emergency-rules.json', []);
        $now = time();
        $active = array_values(array_filter($rules, static function ($rule) use ($now): bool {
            return is_array($rule) && strtotime((string) ($rule['expires_at'] ?? '')) > $now;
        }));
        if (count($active) !== count($rules)) $this->writeJson('emergency-rules.json', $active);
        return $active;
    }

    public function matchEmergencyRule(string $ip, ?string $country, ?string $asn, bool $datacenter): ?array {
        $asnNumber = '';
        if ($asn && preg_match('/AS(\d+)/i', $asn, $match)) $asnNumber = 'AS' . $match[1];
        foreach ($this->getEmergencyRules() as $rule) {
            $matched = match ($rule['type'] ?? '') {
                'ip' => hash_equals((string) $rule['value'], $ip),
                'country' => strtoupper((string) $rule['value']) === strtoupper((string) $country),
                'asn' => strtoupper((string) $rule['value']) === $asnNumber
                    || ltrim(strtoupper((string) $rule['value']), 'AS') === ltrim($asnNumber, 'AS'),
                'datacenter' => $datacenter,
                default => false,
            };
            if ($matched) return $rule;
        }
        return null;
    }

    public function saveSnapshot(array $previous, array $next, array $meta = []): ?array {
        $diff = self::diff($previous, $next);
        if (!$diff) return null;
        $snapshot = [
            'id' => date('YmdHis') . '-' . bin2hex(random_bytes(4)),
            'time' => date('c'),
            'user' => (string) ($meta['user'] ?? ''),
            'module_version' => (string) ($meta['module_version'] ?? ''),
            'previous' => $previous,
            'next' => $next,
            'diff' => $diff,
        ];
        $history = $this->getSnapshots();
        array_unshift($history, $snapshot);
        $this->writeJson('config-snapshots.json', array_slice($history, 0, 100));
        $this->audit('settings_changed', ['snapshot_id' => $snapshot['id'], 'user' => $snapshot['user'], 'diff' => $diff]);
        return $snapshot;
    }

    public function getSnapshots(): array {
        return array_values(array_filter($this->readJson('config-snapshots.json', []), 'is_array'));
    }

    public function getSnapshot(string $id): ?array {
        foreach ($this->getSnapshots() as $snapshot) {
            if (($snapshot['id'] ?? '') === $id) return $snapshot;
        }
        return null;
    }

    public function audit(string $event, array $context = []): void {
        $this->ensureDirectory();
        $record = ['time' => date('c'), 'event' => $event, 'context' => $context];
        $path = $this->directory . 'audit-' . date('Y-m') . '.jsonl';
        @file_put_contents(
            $path,
            json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n",
            FILE_APPEND | LOCK_EX
        );
        @chmod($path, 0600);
    }

    public static function diff(array $previous, array $next): array {
        $diff = [];
        foreach (array_unique(array_merge(array_keys($previous), array_keys($next))) as $key) {
            $old = $previous[$key] ?? null;
            $new = $next[$key] ?? null;
            if ($old !== $new) $diff[$key] = ['from' => $old, 'to' => $new];
        }
        ksort($diff);
        return $diff;
    }

    protected function readJson(string $name, array $fallback): array {
        $path = $this->directory . $name;
        if (!is_file($path)) return $fallback;
        $decoded = json_decode((string) @file_get_contents($path), true);
        return is_array($decoded) ? $decoded : $fallback;
    }

    protected function writeJson(string $name, array $data): void {
        $this->ensureDirectory();
        $path = $this->directory . $name;
        $temp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false || @file_put_contents($temp, $json . "\n", LOCK_EX) === false || !@rename($temp, $path)) {
            @unlink($temp);
            throw new \RuntimeException('Could not write WireWall operational state.');
        }
        @chmod($path, 0600);
    }

    protected function ensureDirectory(): void {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new \RuntimeException('Could not create WireWall operations directory.');
        }
        @chmod($this->directory, 0700);
    }
}
