<?php namespace ProcessWire;

/**
 * Local-first IP privacy classification. IP2Proxy BIN is optional and is only
 * used when its SDK and configured database are both available.
 */
final class WireWallIpIntelligenceService {
    private const CLASS_MAP = [
        'VPN' => 'consumer_vpn', 'TOR' => 'tor', 'DCH' => 'datacenter_proxy',
        'RES' => 'residential_proxy', 'CPN' => 'privacy_relay',
        'PUB' => 'unknown_proxy', 'WEB' => 'unknown_proxy',
        'EPN' => 'unknown_proxy', 'SES' => 'search_engine_robot',
    ];

    public function __construct(private string $databasePath, private string $autoloadPath = '') {}

    public function status(): array {
        $readable = is_file($this->databasePath) && is_readable($this->databasePath);
        return [
            'provider' => 'ip2proxy_lite',
            'path' => $this->databasePath,
            'installed' => $readable && $this->loadSdk(),
            'readable' => $readable,
            'modified_at' => $readable ? date('c', (int) filemtime($this->databasePath)) : null,
            'sdk_available' => $this->loadSdk(),
        ];
    }

    public function lookup(string $ip, ?string $asn = null): array {
        $started = microtime(true);
        $result = [
            'privacy_provider' => null,
            'proxy_type' => null,
            'proxy_class' => $this->classifyAsn((string) $asn),
            'cached' => false,
            'source' => 'local_rules',
            'provider_latency_ms' => 0,
        ];
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || !$this->loadSdk() || !is_readable($this->databasePath)) {
            $result['provider_latency_ms'] = round((microtime(true) - $started) * 1000, 2);
            return $result;
        }
        try {
            $database = new \IP2Proxy\Database($this->databasePath, \IP2Proxy\Database::FILE_IO);
            $record = $database->lookup($ip, \IP2Proxy\Database::ALL);
            $type = strtoupper(trim((string) (is_array($record) ? ($record['proxyType'] ?? $record['proxy_type'] ?? '') : '')));
            if ($type !== '' && $type !== '-') {
                $result['privacy_provider'] = 'ip2proxy_lite';
                $result['proxy_type'] = $type;
                $result['proxy_class'] = self::CLASS_MAP[$type] ?? 'unknown_proxy';
                $result['source'] = 'local_db';
            }
        } catch (\Throwable $e) {
            $result['error'] = substr($e->getMessage(), 0, 200);
        }
        $result['provider_latency_ms'] = round((microtime(true) - $started) * 1000, 2);
        return $result;
    }

    public function actionFor(array $intel, array $settings, string $path): string {
        $class = (string) ($intel['proxy_class'] ?? '');
        if ($class === '' || $class === 'search_engine_robot') return 'allow';
        $key = 'proxy_action_' . $class;
        $action = strtolower((string) ($settings[$key] ?? self::defaultAction($class)));
        if (!in_array($action, ['allow', 'challenge', 'block'], true)) $action = self::defaultAction($class);
        $sensitive = self::matchesSensitivePath($path, (string) ($settings['proxy_sensitive_paths'] ?? "/login\n/checkout\n/forms\n/api"));
        if ($sensitive) {
            $sensitiveAction = strtolower((string) ($settings['proxy_sensitive_action'] ?? 'challenge'));
            if ($sensitiveAction === 'block' || ($sensitiveAction === 'challenge' && $action === 'allow')) {
                $action = $sensitiveAction;
            }
        }
        return $action;
    }

    public static function defaultAction(string $class): string {
        return match ($class) {
            'privacy_relay', 'consumer_vpn', 'residential_proxy' => 'allow',
            'datacenter_proxy', 'tor' => 'block',
            default => 'challenge',
        };
    }

    protected function classifyAsn(string $asn): ?string {
        $value = strtolower($asn);
        if ($value === '') return null;
        if (str_contains($value, 'private relay') || str_contains($value, 'icloud relay')) return 'privacy_relay';
        if (str_contains($value, ' tor ') || str_ends_with($value, ' tor')) return 'tor';
        foreach (['amazon', 'aws', 'google cloud', 'azure', 'digitalocean', 'ovh', 'hetzner', 'linode', 'vultr', 'tencent', 'alibaba', 'huawei', 'byteplus', 'datacenter', 'data center', 'hosting'] as $keyword) {
            if (str_contains($value, $keyword)) return 'datacenter_proxy';
        }
        return null;
    }

    protected function loadSdk(): bool {
        if (class_exists('\IP2Proxy\Database')) return true;
        if ($this->autoloadPath !== '' && is_file($this->autoloadPath)) {
            require_once $this->autoloadPath;
        }
        return class_exists('\IP2Proxy\Database');
    }

    protected static function matchesSensitivePath(string $path, string $rules): bool {
        foreach (preg_split('/[\r\n,]+/', strtolower($rules)) ?: [] as $rule) {
            $rule = trim($rule);
            if ($rule !== '' && str_starts_with(strtolower($path), $rule)) return true;
        }
        return false;
    }
}
