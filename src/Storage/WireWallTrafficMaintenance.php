<?php namespace ProcessWire;

final class WireWallTrafficMaintenance {
    public function __construct(private string $directory) {
        $this->directory = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR;
    }

    public function run(int $retentionDays, int $compressAfterDays, int $maxMegabytes = 0): array {
        $result = ['compressed' => 0, 'deleted' => 0, 'bytes_before' => $this->size(), 'bytes_after' => 0];
        if (!is_dir($this->directory)) return $result;
        $now = time();
        foreach (scandir($this->directory) ?: [] as $file) {
            if (!preg_match('/^traffic-(\d{4}-\d{2}-\d{2})\.jsonl(?:\.gz)?$/', $file, $match)) continue;
            $path = $this->directory . $file;
            $ageDays = (int) floor(($now - (strtotime($match[1] . ' 23:59:59') ?: $now)) / 86400);
            if ($retentionDays > 0 && $ageDays >= $retentionDays) {
                if (@unlink($path)) $result['deleted']++;
                continue;
            }
            if ($compressAfterDays > 0 && $ageDays >= $compressAfterDays && !str_ends_with($file, '.gz') && function_exists('gzopen')) {
                if ($this->compress($path)) $result['compressed']++;
            }
        }
        if ($maxMegabytes > 0) {
            $limit = $maxMegabytes * 1048576;
            $files = $this->trafficFilesOldestFirst();
            while ($this->size() > $limit && $files) {
                $path = array_shift($files);
                if (@unlink($path)) $result['deleted']++;
            }
        }
        $result['bytes_after'] = $this->size();
        return $result;
    }

    public function size(): int {
        $bytes = 0;
        if (!is_dir($this->directory)) return 0;
        foreach ($this->trafficFilesOldestFirst() as $path) $bytes += (int) filesize($path);
        return $bytes;
    }

    protected function compress(string $path): bool {
        $input = @fopen($path, 'rb');
        $output = @gzopen($path . '.gz.tmp', 'wb6');
        if (!$input || !$output) {
            if (is_resource($input)) fclose($input);
            if (is_resource($output)) gzclose($output);
            return false;
        }
        while (!feof($input)) gzwrite($output, (string) fread($input, 1048576));
        fclose($input);
        gzclose($output);
        return @rename($path . '.gz.tmp', $path . '.gz') && @unlink($path);
    }

    protected function trafficFilesOldestFirst(): array {
        $files = [];
        foreach (scandir($this->directory) ?: [] as $file) {
            if (preg_match('/^traffic-\d{4}-\d{2}-\d{2}\.jsonl(?:\.gz)?$/', $file)) $files[] = $this->directory . $file;
        }
        sort($files, SORT_STRING);
        return $files;
    }
}
