<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/Support/WireWallApiPathRegistry.php';

use ProcessWire\WireWallApiPathRegistry;

function registryAssertSame($expected, $actual, string $message): void {
    if ($expected !== $actual) {
        fwrite(STDERR, $message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

function registryAssertThrows(callable $callback, string $message): void {
    try {
        $callback();
    } catch (InvalidArgumentException $error) {
        return;
    }
    fwrite(STDERR, $message . "\n");
    exit(1);
}

$registry = new WireWallApiPathRegistry();
$settings = ['custom_api_paths' => "/manual-api/\n/api/"];

registryAssertSame(true, $registry->matches($settings, '/api/status'), 'Default API prefix should match.');
registryAssertSame(true, $registry->matches($settings, '/manual-api/status?next=/private/'), 'Manual API prefix should match.');
registryAssertSame(false, $registry->matches($settings, '/public/?next=/manual-api/status'), 'A path in the query string must not match.');

$settings = $registry->withIntegration($settings, 'Messenger', [
    '/messenger-api/',
    '/messenger-mobile/',
    '/messenger-api/',
], true);
$settings = $registry->withIntegration($settings, 'Other.Module', ['/other-api/'], true);

registryAssertSame(
    ['owner' => 'Messenger', 'enabled' => true, 'paths' => ['/messenger-api/', '/messenger-mobile/']],
    $registry->integration($settings, 'Messenger'),
    'Integration should expose normalized, deduplicated paths.'
);
registryAssertSame(true, $registry->matches($settings, '/messenger-mobile/auth/start'), 'Registered prefix should match its route.');
registryAssertSame(false, $registry->matches($settings, '/x/messenger-mobile/auth/start'), 'Registered prefix must be anchored at the path start.');

$settings = $registry->withIntegration($settings, 'Messenger', [], false);
registryAssertSame(false, $registry->integration($settings, 'Messenger')['enabled'], 'Disabled integration should be removed.');
registryAssertSame(true, $registry->integration($settings, 'Other.Module')['enabled'], 'Removing one owner must preserve other owners.');
registryAssertSame(true, $registry->matches($settings, '/manual-api/status'), 'Removing an integration must preserve manual paths.');

registryAssertThrows(fn() => $registry->withIntegration([], 'x', ['/valid/'], true), 'One-character owners must be rejected.');
registryAssertThrows(fn() => $registry->withIntegration([], 'Messenger', ['/'], true), 'Root path must be rejected.');
registryAssertThrows(fn() => $registry->withIntegration([], 'Messenger', ['/route?x=1/'], true), 'Query strings must be rejected.');
registryAssertThrows(fn() => $registry->withIntegration([], 'Messenger', ['/missing-trailing-slash'], true), 'Unbounded path prefixes must be rejected.');

echo "WireWallApiPathRegistryTest passed\n";
