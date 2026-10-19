<?php namespace ProcessWire;

/**
 * Validates and combines WireWall API bypass paths owned by installed modules.
 *
 * The registry lives in WireWall settings so integrations remain attributable
 * and can remove only the paths they own.
 */
final class WireWallApiPathRegistry {
    private const DEFAULT_PATHS = ['/api/', '/api2/', '/rest/'];

    public function withIntegration(array $settings, string $owner, array $paths, bool $enabled): array {
        $owner = $this->normalizeOwner($owner);
        $integrations = $this->integrations($settings);
        if ($enabled) {
            $normalized = $this->normalizePaths($paths);
            if (!$normalized) throw new \InvalidArgumentException('A trusted API integration requires at least one path.');
            $integrations[$owner] = $normalized;
            ksort($integrations);
        } else {
            unset($integrations[$owner]);
        }
        $settings['api_path_integrations'] = $integrations;
        return $settings;
    }

    public function integration(array $settings, string $owner): array {
        $owner = $this->normalizeOwner($owner);
        $paths = $this->integrations($settings)[$owner] ?? [];
        return ['owner' => $owner, 'enabled' => (bool)$paths, 'paths' => $paths];
    }

    public function integrations(array $settings): array {
        $raw = $settings['api_path_integrations'] ?? [];
        if (!is_array($raw)) return [];
        $integrations = [];
        foreach ($raw as $owner => $paths) {
            try {
                $owner = $this->normalizeOwner((string)$owner);
                $paths = $this->normalizePaths(is_array($paths) ? $paths : []);
            } catch (\InvalidArgumentException $error) {
                continue;
            }
            if ($paths) $integrations[$owner] = $paths;
        }
        ksort($integrations);
        return $integrations;
    }

    public function allPaths(array $settings): array {
        $paths = self::DEFAULT_PATHS;
        $custom = preg_split('/\R+/', trim((string)($settings['custom_api_paths'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        foreach ($custom as $path) {
            try { $paths[] = $this->normalizePath((string)$path); }
            catch (\InvalidArgumentException $error) { continue; }
        }
        foreach ($this->integrations($settings) as $integrationPaths) array_push($paths, ...$integrationPaths);
        return array_values(array_unique($paths));
    }

    public function matches(array $settings, string $requestUri): bool {
        $requestPath = (string)(parse_url($requestUri, PHP_URL_PATH) ?: '/');
        foreach ($this->allPaths($settings) as $path) {
            if (str_starts_with($requestPath, $path)) return true;
        }
        return false;
    }

    private function normalizeOwner(string $owner): string {
        $owner = trim($owner);
        if (!preg_match('/^[A-Za-z][A-Za-z0-9_.-]{1,63}$/', $owner)) {
            throw new \InvalidArgumentException('Invalid trusted API integration owner.');
        }
        return $owner;
    }

    private function normalizePaths(array $paths): array {
        $normalized = [];
        foreach ($paths as $path) {
            if (!is_string($path)) throw new \InvalidArgumentException('Trusted API paths must be strings.');
            $normalized[] = $this->normalizePath($path);
        }
        $normalized = array_values(array_unique($normalized));
        if (count($normalized) > 20) throw new \InvalidArgumentException('Too many trusted API paths for one integration.');
        return $normalized;
    }

    private function normalizePath(string $path): string {
        $path = trim($path);
        if (
            $path === '/' || strlen($path) > 240
            || !str_starts_with($path, '/') || !str_ends_with($path, '/')
            || str_contains($path, '?') || str_contains($path, '#') || str_contains($path, '\\')
            || preg_match('/[\x00-\x20\x7f]/', $path)
        ) {
            throw new \InvalidArgumentException('Trusted API paths must be bounded absolute path prefixes ending in a slash.');
        }
        return $path;
    }
}
