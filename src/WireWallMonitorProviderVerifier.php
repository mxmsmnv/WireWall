<?php namespace ProcessWire;

/**
 * Verifies synthetic monitoring providers against their published IP feeds.
 */
class WireWallMonitorProviderVerifier {

    protected $httpGet;
    protected $cacheGet;
    protected $cacheSet;
    protected $matchIP;
    protected $logError;

    public function __construct(callable $httpGet, callable $cacheGet, callable $cacheSet, callable $matchIP, ?callable $logError = null) {
        $this->httpGet = $httpGet;
        $this->cacheGet = $cacheGet;
        $this->cacheSet = $cacheSet;
        $this->matchIP = $matchIP;
        $this->logError = $logError;
    }

    public static function providers() {
        return [
            [
                'name' => 'uptimerobot',
                'label' => 'UptimeRobot',
                'type' => 'official-ip-feed',
                'user_agent_patterns' => ['/uptimerobot/i'],
                'sources' => [
                    [
                        'url' => 'https://api.uptimerobot.com/meta/ips',
                        'format' => 'uptimerobot-json',
                    ],
                ],
            ],
            [
                'name' => 'pingdom',
                'label' => 'Pingdom',
                'type' => 'official-ip-feed',
                'user_agent_patterns' => ['/pingdom/i'],
                'sources' => [
                    [
                        'url' => 'https://my.pingdom.com/probes/ipv4',
                        'format' => 'text',
                    ],
                    [
                        'url' => 'https://my.pingdom.com/probes/ipv6',
                        'format' => 'text',
                    ],
                    [
                        'url' => 'https://my.pingdom.com/probes/feed',
                        'format' => 'text',
                    ],
                ],
            ],
            [
                'name' => 'statuscake',
                'label' => 'StatusCake',
                'type' => 'official-ip-feed',
                'user_agent_patterns' => ['/statuscake/i'],
                'sources' => [
                    [
                        'url' => 'https://app.statuscake.com/Workfloor/Locations.php?format=json',
                        'format' => 'json-generic',
                    ],
                    [
                        'url' => 'https://app.statuscake.com/API/SpeedLocations/json',
                        'format' => 'json-generic',
                    ],
                ],
                'static_prefixes' => [
                    '64.227.47.203',
                    '46.101.46.173',
                    '178.128.162.247',
                    '167.99.201.22',
                    '178.62.44.54',
                ],
            ],
            [
                'name' => 'datadog-synthetics',
                'label' => 'Datadog Synthetics',
                'type' => 'official-ip-feed',
                'user_agent_patterns' => ['/datadogsynthetics|datadog synthetics|synthetics.*datadog/i'],
                'sources' => [
                    [
                        'url' => 'https://ip-ranges.datadoghq.com/synthetics.json',
                        'format' => 'json-generic',
                    ],
                ],
            ],
            [
                'name' => 'newrelic-synthetics',
                'label' => 'New Relic Synthetics',
                'type' => 'official-ip-feed',
                'user_agent_patterns' => ['/newrelic.*synthetics|synthetics.*newrelic|newrelicpinger/i'],
                'sources' => [
                    [
                        'url' => 'https://s3.amazonaws.com/nr-synthetics-assets/nat-ip-dnsname/production/ip-ranges.json',
                        'format' => 'json-generic',
                    ],
                ],
            ],
        ];
    }

    public function getProviderForUserAgent($userAgent) {
        $userAgent = (string)$userAgent;
        foreach (self::providers() as $provider) {
            foreach ($provider['user_agent_patterns'] as $pattern) {
                if (preg_match($pattern, $userAgent)) {
                    return $provider;
                }
            }
        }
        return null;
    }

    public function verify(array $provider, $ip) {
        $name = $provider['name'] ?? 'monitor';
        $cacheKey = 'botverify_' . $name . '_' . sha1((string)$ip);
        $cached = ($this->cacheGet)($cacheKey);
        if (is_array($cached) && isset($cached['status'])) {
            $cached['cached'] = true;
            return $cached;
        }

        $verified = false;
        foreach ($this->getPrefixes($provider) as $prefix) {
            if (($this->matchIP)($ip, $prefix)) {
                $verified = true;
                break;
            }
        }

        $result = [
            'provider' => $name,
            'status' => $verified ? 'verified' : 'unverified',
            'method' => 'official-ip-feed',
            'cached' => false,
        ];

        ($this->cacheSet)($cacheKey, $result, $verified ? 86400 : 3600);
        return $result;
    }

    protected function getPrefixes(array $provider) {
        $name = $provider['name'] ?? 'monitor';
        $cacheKey = 'botverify_' . $name . '_prefixes';
        $cached = ($this->cacheGet)($cacheKey);
        if (is_array($cached)) {
            return $cached;
        }

        $prefixes = [];
        foreach (($provider['static_prefixes'] ?? []) as $prefix) {
            $prefixes[] = $prefix;
        }

        foreach (($provider['sources'] ?? []) as $source) {
            $url = $source['url'] ?? '';
            if (!$url) continue;
            try {
                $response = ($this->httpGet)($url);
                if ($response) {
                    $prefixes = array_merge($prefixes, $this->parseSource((string)$response, $source['format'] ?? 'text'));
                }
            } catch (\Exception $e) {
                if ($this->logError) {
                    ($this->logError)(($provider['label'] ?? $name) . ' IP feed error: ' . $e->getMessage());
                }
            }
        }

        $prefixes = array_values(array_unique(array_filter(array_map([$this, 'normalizePrefix'], $prefixes))));
        ($this->cacheSet)($cacheKey, $prefixes, $prefixes ? 86400 : 3600);
        return $prefixes;
    }

    protected function parseSource($body, $format) {
        if ($format === 'uptimerobot-json') {
            $data = json_decode($body, true);
            $prefixes = [];
            if (is_array($data) && !empty($data['prefixes']) && is_array($data['prefixes'])) {
                foreach ($data['prefixes'] as $entry) {
                    if (!empty($entry['ip_prefix'])) $prefixes[] = $entry['ip_prefix'];
                    if (!empty($entry['ipv6_prefix'])) $prefixes[] = $entry['ipv6_prefix'];
                }
            }
            return $prefixes;
        }

        if ($format === 'json-generic') {
            $data = json_decode($body, true);
            if (is_array($data)) {
                return $this->extractPrefixesFromValue($data);
            }
        }

        return $this->extractPrefixesFromText($body);
    }

    protected function extractPrefixesFromValue($value) {
        $prefixes = [];
        if (is_array($value)) {
            foreach ($value as $item) {
                $prefixes = array_merge($prefixes, $this->extractPrefixesFromValue($item));
            }
            return $prefixes;
        }
        if (is_scalar($value)) {
            return $this->extractPrefixesFromText((string)$value);
        }
        return [];
    }

    protected function extractPrefixesFromText($text) {
        $prefixes = [];
        preg_match_all('/(?<![\\w:.])(?:\\d{1,3}\\.){3}\\d{1,3}(?:\\/\\d{1,2})?(?![\\w:.])|(?<![\\w:])(?:[a-f0-9]{1,4}:){2,}[a-f0-9:.]{1,}(?:\\/\\d{1,3})?(?![\\w:])/i', (string)$text, $matches);
        foreach ($matches[0] ?? [] as $match) {
            $prefixes[] = $match;
        }
        return $prefixes;
    }

    protected function normalizePrefix($prefix) {
        $prefix = trim((string)$prefix);
        if ($prefix === '') return '';

        if (strpos($prefix, '/') !== false) {
            [$ip, $mask] = explode('/', $prefix, 2);
            $ip = trim($ip);
            $mask = trim($mask);
            if (filter_var($ip, FILTER_VALIDATE_IP) && ctype_digit($mask)) {
                return $ip . '/' . $mask;
            }
            return '';
        }

        return filter_var($prefix, FILTER_VALIDATE_IP) ? $prefix : '';
    }
}
