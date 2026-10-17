<?php namespace ProcessWire;

/** Short-lived, request-bound owner authorization. No private keys on the server. */
final class WireWallOwnerScannerVerifier {
    private const PATHS = ['/', '/.git/config', '/.env', '/phpinfo.php', '/info.php'];

    public function __construct(private string $stateDirectory) {}

    public static function message(string $host, string $path, string $time, string $nonce, string $key): string {
        return "wirewall-owner-readonly-v1\nhttps\n{$host}\nGET\n{$path}\n{$time}\n{$nonce}\n{$key}";
    }

    public function verify(array $server, array $grant, int $now): bool {
        if (!function_exists('sodium_crypto_sign_verify_detached')) return false;
        if (($server['REQUEST_METHOD'] ?? '') !== 'GET' || !in_array($server['REQUEST_URI'] ?? '', self::PATHS, true)) return false;
        if (!in_array($server['HTTPS'] ?? '', ['on', '1'], true)) return false;
        $host = $server['HTTP_HOST'] ?? '';
        if (!is_string($host) || !preg_match('/^[a-z0-9.-]{1,253}$/D', $host) || $host !== ($grant['host'] ?? null)) return false;
        $issued = $grant['issued_at'] ?? null;
        $expires = $grant['expires_at'] ?? null;
        if (!is_int($issued) || !is_int($expires) || $issued > $now + 5 || $expires <= $now || $expires <= $issued || $expires - $issued > 3600) return false;
        $key = $server['HTTP_X_NUCLEI_SCANNER_KEY'] ?? '';
        $time = $server['HTTP_X_NUCLEI_SCANNER_TIME'] ?? '';
        $nonce = $server['HTTP_X_NUCLEI_SCANNER_NONCE'] ?? '';
        $signature = $server['HTTP_X_NUCLEI_SCANNER_SIGNATURE'] ?? '';
        if (!is_string($key) || !preg_match('/^[a-f0-9]{16}$/D', $key) || !is_string($time) || !preg_match('/^[0-9]{10}$/D', $time)
            || !is_string($nonce) || !preg_match('/^[a-f0-9]{32}$/D', $nonce) || !is_string($signature) || strlen($signature) !== 88) return false;
        if ((int)$time < $now - 30 || (int)$time > $now + 5 || (int)$time < $issued - 5) return false;
        $public = base64_decode((string)($grant['public_key'] ?? ''), true);
        $signed = base64_decode($signature, true);
        if ($public === false || strlen($public) !== 32 || $signed === false || strlen($signed) !== 64 || substr(hash('sha256', $public), 0, 16) !== $key) return false;
        try {
            if (!sodium_crypto_sign_verify_detached($signed, self::message($host, $server['REQUEST_URI'], $time, $nonce, $key), $public)) return false;
            return $this->consume($key, $nonce, $now);
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function consume(string $key, string $nonce, int $now): bool {
        $dir = $this->stateDirectory;
        if (is_link($dir) || (!is_dir($dir) && !@mkdir($dir, 0700, true))) return false;
        if (!@chmod($dir, 0700)) return false;
        $path = rtrim($dir, '/\\') . '/' . $key . '.json';
        if (is_link($path)) return false;
        $file = @fopen($path, 'c+b');
        if (!$file) return false;
        try {
            if (!flock($file, LOCK_EX | LOCK_NB)) return false;
            if (!@chmod($path, 0600)) return false;
            $raw = stream_get_contents($file, 16385);
            if ($raw === false || strlen($raw) > 16384) return false;
            $entries = $raw === '' ? [] : json_decode($raw, true);
            if (!is_array($entries) || !array_is_list($entries) || count($entries) > 60) return false;
            $recent = [];
            $hash = hash('sha256', $nonce);
            foreach ($entries as $entry) {
                if (!is_array($entry) || !is_int($entry['time'] ?? null) || !preg_match('/^[a-f0-9]{64}$/D', $entry['nonce'] ?? '')) return false;
                if ($entry['time'] > $now + 5) return false;
                if ($entry['time'] > $now - 3600) {
                    if (hash_equals($entry['nonce'], $hash)) return false;
                    $recent[] = $entry;
                }
            }
            if (count($recent) >= 60 || count(array_filter($recent, fn($e) => $e['time'] > $now - 60)) >= 10) return false;
            $recent[] = ['time' => $now, 'nonce' => $hash];
            $data = json_encode($recent, JSON_THROW_ON_ERROR);
            rewind($file);
            if (!ftruncate($file, 0) || fwrite($file, $data) !== strlen($data) || !fflush($file)) return false;
            return true;
        } finally {
            flock($file, LOCK_UN);
            fclose($file);
        }
    }
}
