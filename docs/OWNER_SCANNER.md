# Short-lived signed owner scanner — 1.13.0

Opt-in, disabled unless `$config->wireWallOwnerScanner` supplies a server-controlled public grant. No permanent User-Agent/IP allowlist. The signing process has a one-hour in-memory Ed25519 private key; restart loses it. The server has only its public key. No automatic renewal.

Grant fields: `host` (exact lowercase hostname), `public_key` (base64 32 bytes), integer `issued_at`, `expires_at`, at most 3600 seconds apart. Keep deployment configuration and bounded nonce state outside the web root. Absence, expiry, unreadable/corrupt state or unavailable sodium means no exception; original defenses run.

Only query-free exact GET paths `/`, `/.git/config`, `/.env`, `/phpinfo.php`, `/info.php`. TLS required. No admin, arbitrary path, port suffix, subdomain, POST or query string. Nginx denials continue independently.

Headers: `X-Nuclei-Scanner-Key` = first 16 hex characters of SHA-256(public bytes), `X-Nuclei-Scanner-Time` = 10-digit Unix seconds, `X-Nuclei-Scanner-Nonce` = 32 random hex characters, `X-Nuclei-Scanner-Signature` = base64 64-byte Ed25519 signature. Canonical bytes are these UTF-8 lines without a trailing newline:

```
wirewall-owner-readonly-v1
https
EXACT_HOST
GET
EXACT_PATH
TIMESTAMP
NONCE
KEY_ID
```

Request age ≤30 seconds; future skew ≤5 seconds. Atomic locked nonce state prevents replay; per-key caps 10 accepted requests per 60 seconds, 60/hour, at most 60 hashed entries. Private state uses 0700 directory / 0600 file. No signatures/private keys in WireWall traffic records; allowed reason is `signed-owner-scanner`.

Verification occurs after emergency rules, active bans, triggers, ordinary rate limits and IP blacklist. A valid signature skips JS/fake-browser and proxy/datacenter heuristics only. Explicit ASN/geo/path/bot blocks still run. Invalid/unsigned/expired requests get no exception. Site authorization is independent from scanner target ownership proof; both are required by NucleiPrototype.

Activation requires the site's normal immutable code release, backup and guard workflow. Provision only the public grant from the current signer, not a private key or a test fixture. Revoke by removing the grant; expiry does the same automatically. A restart needs a separately reviewed new public grant, not silent reactivation. Production smoke must compare signed root with unsigned/same-UA root; replay, wrong path/method/host, forged and expired headers must not acquire exception. Do not make the firewall globally permissive to satisfy a scan.

Validation: `php tests/WireWallOwnerScannerTest.php`, `php tests/WireWallOwnerScannerFlowTest.php` plus existing behavior/operations/export tests. The flow test executes real `checkAccess` control flow against isolated network/storage doubles, demonstrating that signed requests remain subject to eight independent defenses; it is not a substitute for final site smoke.

Primary cryptographic references: [PHP detached Ed25519 verification](https://www.php.net/manual/en/function.sodium-crypto-sign-verify-detached.php), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html). Scope, replay and rate rules are local application policy measured by the tests, not claims supplied by those references.
