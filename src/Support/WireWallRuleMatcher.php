<?php namespace ProcessWire;

/**
 * Parses line-based rules and matches wildcard patterns.
 */
class WireWallRuleMatcher {

    public static function parseRuleText($text): array {
        $rules = [];
        foreach (explode("\n", (string)$text) as $line) {
            $line = trim($line);
            if ($line !== '' && !str_starts_with($line, '#')) {
                $rules[] = $line;
            }
        }
        return $rules;
    }

    public static function matchPattern($text, $pattern): bool {
        $text = (string)$text;
        $pattern = (string)$pattern;
        if ($text === $pattern) {
            return true;
        }

        if (strpos($pattern, '*') !== false) {
            $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/i';
            return preg_match($regex, $text) === 1;
        }

        return false;
    }

    public static function isUnsafeBrowserAllowPattern($pattern): bool {
        $pattern = strtolower(trim((string)$pattern));
        return in_array($pattern, [
            'firefox',
            'brave',
            'chrome',
            'chromium',
            'safari',
            'edge',
            'edg',
            'opera',
            'opr',
        ], true);
    }

    public static function extractUnsafeBrowserAllowPatterns($text): array {
        $patterns = [];
        foreach (self::parseRuleText((string)$text) as $line) {
            foreach (preg_split('/[\s,;|]+/', $line, -1, PREG_SPLIT_NO_EMPTY) as $token) {
                if (self::isUnsafeBrowserAllowPattern($token)) {
                    $patterns[] = trim($token);
                }
            }
        }
        return array_values(array_unique($patterns));
    }
}
