<?php namespace ProcessWire;

/**
 * Matches IP addresses against exact, wildcard, and CIDR patterns.
 */
class WireWallIpMatcher {

    public function match($ip, $pattern): bool {
        $ip = (string)$ip;
        $pattern = trim((string)$pattern);

        if ($ip === $pattern) {
            return true;
        }

        if (strpos($pattern, '/') !== false) {
            return $this->matchCIDR($ip, $pattern);
        }

        if (strpos($pattern, '*') !== false) {
            $regex = '/^' . str_replace(['.', '*'], ['\.', '.*'], $pattern) . '$/';
            return preg_match($regex, $ip) === 1;
        }

        return false;
    }

    public function matchCIDR($ip, $cidr): bool {
        if (strpos((string)$cidr, '/') === false) {
            return false;
        }

        [$subnet, $bits] = explode('/', (string)$cidr, 2);
        $bits = (int)$bits;

        $isIPv6 = strpos((string)$ip, ':') !== false;
        $isSubnetIPv6 = strpos((string)$subnet, ':') !== false;
        if ($isIPv6 !== $isSubnetIPv6) {
            return false;
        }

        return $isIPv6
            ? $this->matchIPv6CIDR($ip, $subnet, $bits)
            : $this->matchIPv4CIDR($ip, $subnet, $bits);
    }

    public function matchIPv4CIDR($ip, $subnet, $bits): bool {
        $ipLong = ip2long((string)$ip);
        $subnetLong = ip2long((string)$subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $mask = -1 << (32 - $bits);
        $subnetLong &= $mask;

        return ($ipLong & $mask) == $subnetLong;
    }

    public function matchIPv6CIDR($ip, $subnet, $bits): bool {
        $ipBinary = @inet_pton((string)$ip);
        $subnetBinary = @inet_pton((string)$subnet);

        if ($ipBinary === false || $subnetBinary === false) {
            return false;
        }

        if ($bits < 0 || $bits > 128) {
            return false;
        }

        $ipBits = '';
        $subnetBits = '';
        for ($i = 0; $i < strlen($ipBinary); $i++) {
            $ipBits .= str_pad(decbin(ord($ipBinary[$i])), 8, '0', STR_PAD_LEFT);
            $subnetBits .= str_pad(decbin(ord($subnetBinary[$i])), 8, '0', STR_PAD_LEFT);
        }

        return substr($ipBits, 0, $bits) === substr($subnetBits, 0, $bits);
    }
}
