<?php namespace ProcessWire;

/**
 * Stores AI-friendly WireWall traffic history outside the document root.
 */
class WireWallTrafficHistoryStore {

    protected string $siteRootPath;
    protected string $assetsPath;
    protected string $configuredPrivatePath;
    protected $logWarning;
    protected bool $warnedRelativePrivatePath = false;

    public function __construct(string $siteRootPath, string $assetsPath, string $configuredPrivatePath = '', ?callable $logWarning = null) {
        $this->siteRootPath = $siteRootPath;
        $this->assetsPath = $assetsPath;
        $this->configuredPrivatePath = $configuredPrivatePath;
        $this->logWarning = $logWarning;
    }

    public function getPrivateDataPath(): string {
        $configured = trim($this->configuredPrivatePath);
        if ($configured !== '') {
            $isAbsolute = str_starts_with($configured, '/')
                || (bool)preg_match('/^[A-Za-z]:[\/\\\\]/', $configured);
            if ($isAbsolute) {
                return rtrim($configured, '/\\') . DIRECTORY_SEPARATOR;
            }
            if (!$this->warnedRelativePrivatePath) {
                $this->warn('Ignoring relative wireWallPrivateDataPath; configure an absolute path.');
                $this->warnedRelativePrivatePath = true;
            }
        }

        $root = rtrim($this->siteRootPath, '/\\');
        return dirname($root) . DIRECTORY_SEPARATOR . basename($root)
            . '-wirewall-private' . DIRECTORY_SEPARATOR;
    }

    public function getTrafficHistoryPath(): string {
        return $this->getPrivateDataPath() . 'traffic' . DIRECTORY_SEPARATOR;
    }

    public function migrateLegacyTraffic(): void {
        $legacy = rtrim($this->assetsPath, '/\\') . DIRECTORY_SEPARATOR . 'WireWall' . DIRECTORY_SEPARATOR . 'traffic' . DIRECTORY_SEPARATOR;
        $target = $this->getTrafficHistoryPath();
        if ($legacy === $target) {
            return;
        }

        $parent = dirname(rtrim($target, '/\\'));
        if (!is_dir($parent) && !@mkdir($parent, 0700, true)) {
            $this->warn("Could not create private data directory: {$parent}");
            return;
        }
        @chmod($parent, 0700);

        if (is_dir($legacy) && !is_dir($target)) {
            if (!@rename($legacy, $target)) {
                $this->warn("Could not move legacy traffic history from {$legacy} to {$target}");
                return;
            }
        } elseif (is_dir($legacy) && is_dir($target)) {
            foreach (scandir($legacy) ?: [] as $file) {
                if (!preg_match('/^traffic-\d{4}-\d{2}-\d{2}\.jsonl$/', $file)) {
                    continue;
                }
                $destination = $target . $file;
                if (file_exists($destination)) {
                    $destination = $target . 'legacy-' . date('Ymd-His') . '-' . $file;
                }
                if (!@rename($legacy . $file, $destination)) {
                    $this->warn("Could not move legacy traffic file: {$file}");
                }
            }
        }

        if (!is_dir($target) && !@mkdir($target, 0700, true)) {
            $this->warn("Could not create private traffic directory: {$target}");
            return;
        }

        @chmod($target, 0700);
        $this->protectDirectory($target);
        foreach (glob($target . '*.jsonl') ?: [] as $file) {
            @chmod($file, 0600);
        }
    }

    public function writeRecord(array $record, ?int $timestamp = null): bool {
        $dir = $this->getTrafficHistoryPath();
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
            return false;
        }
        @chmod($dir, 0700);
        $this->protectDirectory($dir);

        $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            return false;
        }

        $timestamp = $timestamp ?: time();
        $file = $dir . 'traffic-' . date('Y-m-d', $timestamp) . '.jsonl';
        $written = @file_put_contents($file, $json . "\n", FILE_APPEND | LOCK_EX);
        if ($written === false) {
            return false;
        }
        @chmod($file, 0600);
        return true;
    }

    public function protectDirectory(string $dir): void {
        $htaccess = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . '.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n", LOCK_EX);
        }

        $index = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . 'index.php';
        if (!file_exists($index)) {
            @file_put_contents($index, "<?php namespace ProcessWire; http_response_code(403); exit;\n", LOCK_EX);
        }
    }

    protected function warn(string $message): void {
        if ($this->logWarning) {
            ($this->logWarning)($message);
        }
    }
}
