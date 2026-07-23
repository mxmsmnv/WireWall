# WireWall Agent Guide

This file tells AI agents and Olivia-style assistants how to understand and use the WireWall ProcessWire module.

WireWall is a security/firewall module. Treat it as protective infrastructure, not as a visual website feature.

## Module Summary

WireWall protects public ProcessWire page requests before page rendering.

Primary capabilities:

- Geo blocking by country, city, and subdivision
- IP whitelist and blacklist
- ASN blocking and ASN allow lists
- Bad bot, AI bot, search bot, fake browser, and headless browser detection
- Rate limiting and temporary bans
- VPN, proxy, Tor, and datacenter detection
- JavaScript challenge for suspicious requests
- URL and User-Agent trigger rules
- Trusted AJAX/API path bypasses
- Admin dashboard at `Admin > Setup > WireWall`
- AI-friendly traffic history in JSONL files

Core files:

- `WireWall.module.php` - autoload firewall module
- `ProcessWireWall.module.php` - admin dashboard Process module
- `src/Dashboard/WireWallDashboardStats.php` - dashboard log tailing, parsing, aggregation, and TTL formatting
- `src/WireWallMonitorProviderVerifier.php` - official IP-feed verifier for synthetic monitoring providers
- `src/Storage/WireWallCacheInspector.php` - dashboard cache, active-ban, and traffic-history inventory
- `src/Storage/WireWallTrafficHistoryStore.php` - private traffic-history path, migration, protection, and JSONL writing
- `src/Storage/WireWallTrafficReportService.php` - dashboard traffic report listing, summaries, last-24h exports, and ZIP packaging
- `src/Support/WireWallIpMatcher.php` - shared exact, wildcard, IPv4 CIDR, and IPv6 CIDR matcher
- `src/Support/WireWallRuleMatcher.php` - shared rule parsing, wildcard matching, and unsafe browser allowlist extraction
- `assets/dashboard.css` and `assets/dashboard.js` - dashboard assets loaded by `ProcessWireWall.module.php`
- `README.md` - general purpose and installation
- `INSTALL.md` - setup and server notes
- `CONFIGURATIONS.md` - known configuration profiles

Persistent runtime data:

- `/site/assets/WireWall/geoip/` - MaxMind databases
- `/site/assets/WireWall/vendor/` - Composer dependencies for GeoIP
- `../SITE-DIRECTORY-wirewall-private/traffic/` - private daily JSONL traffic history outside the document root
- `/site/assets/cache/WireWall/` - cache, rate limits, bans, proxy/geo lookups

## How Agents Should Use WireWall When Building A Website

Do not add WireWall calls to normal page templates. WireWall is an autoload module and hooks before `ProcessPageView::execute`.

When building a ProcessWire site:

1. Install and configure WireWall as a module, not as template code.
2. Keep the admin area protected from WireWall blocking. The module intentionally bypasses ProcessWire admin paths.
3. For public pages, build templates normally; WireWall checks happen before rendering.
4. For custom frontend AJAX endpoints, add their paths to `custom_trusted_paths` if they are POST AJAX endpoints.
5. For public APIs, webhooks, GraphQL, REST, AppApi, or custom API routes, add their paths to `custom_api_paths` only if those routes have their own authentication or safety checks.
6. For logged-in user workflows, remember that logged-in ProcessWire users bypass WireWall checks.
7. For analytics or AI traffic analysis, use the dashboard downloads or read JSONL files from the configured private WireWall data path, not the ProcessWire `wirewall` log.
8. For high-traffic sites, prefer local MaxMind GeoLite2 databases over HTTP fallbacks.

Do not implement a second firewall in templates unless the user explicitly asks for custom application-level rules. WireWall already handles request-level blocking.

## Current ProcessWire Integration Points

Autoload hook:

- `WireWall::init()` adds `addHookBefore('ProcessPageView::execute', $this, 'checkAccess')`

Dashboard:

- `ProcessWireWall` creates an admin page under `Admin > Setup > WireWall`
- Required permission: `wirewall-dashboard`

Configuration access:

```php
$wirewall = $modules->get('WireWall');
$configData = $wirewall->getWireWallSettings();
```

`wirewall_settings` is the canonical storage table. ProcessWire module config is
kept synchronized as a migration/rollback fallback. Use
`saveWireWallSettings()` for module-owned settings writes; normal saves from the
ProcessWire module configuration screen are synchronized automatically.

Module instance access:

```php
$wirewall = $modules->get('WireWall');
```

Prefer ProcessWire module configuration APIs over direct file edits for site-specific settings.

## Public And Agent-Usable Configuration Keys

General:

- `enabled`
- `enable_stats_logging`
- `enable_traffic_history`
- `block_action` (`show_page`, `silent_404`, `bare_404`, `bare_410`, `redirect`)
- `redirect_url`
- `block_message`

Rate limiting:

- `rate_limit_enabled`
- `rate_limit_requests`
- `rate_limit_minutes`

Bot protection:

- `block_bad_bots`
- `block_ai_bots`
- `block_search_bots`
- `js_challenge_enabled`
- `block_other_bots`
- `other_bots_list`

VPN/proxy/datacenter:

- `block_proxy_vpn_tor`
- `block_datacenters`
- `block_asns`

Geo blocking:

- `country_mode`
- `blocked_countries`
- `city_blocking_enabled`
- `city_mode`
- `blocked_cities`
- `subdivision_blocking_enabled`
- `subdivision_mode`
- `blocked_subdivisions`
- `country_rules`

IP control:

- `ip_whitelist`
- `ip_blacklist`

Exceptions:

- `allowedUserAgents`
- `allowedIPs`
- `allowedASNs`
- `compatibilityUserAgents`

`ip_whitelist` is the explicit full-firewall bypass. The `allowed*` fields above
classify known bots and skip only bot/fake-browser heuristics. Configured
Googlebot/Bingbot and Google PageSpeed Insights `Chrome-Lighthouse` UA rules
require cached forward-confirmed reverse DNS before they are trusted as UA-only
exceptions. Supported synthetic monitor UA rules, such as UptimeRobot, Pingdom,
StatusCake, Datadog Synthetics, and New Relic Synthetics, require a cached match
against the provider's official IP feed before they are trusted as UA-only
exceptions.
`compatibilityUserAgents` skips only fake-browser and JavaScript-challenge
heuristics; all bans, triggers, rate limits, network checks, geo rules, and
explicit blocks still apply.

Custom rules:

- `blocked_paths`
- `blocked_user_agents`
- `trigger_rule_action`
- `trigger_scanner_preset`
- `trigger_strike_limit`
- `trigger_strike_window_minutes`
- `trigger_ban_minutes`
- `trigger_url_patterns`
- `trigger_user_agents`
- `blocked_referers`

AJAX/API:

- `allowTrustedModules`
- `custom_trusted_paths`
- `custom_api_paths`
- `disable_ajax_protection`

Metadata:

- `version`

## Request Decision Order

When explaining behavior or debugging blocks, use this high-level order:

1. Admin area bypass
2. Trusted ProcessWire module AJAX/API bypass
3. Logged-in ProcessWire user bypass
4. IP whitelist
5. Active temporary ban
6. URL/User-Agent trigger rules
7. Rate limiting
8. IP blacklist
9. Verify supported crawler identities and classify scoped known-bot / compatibility exceptions
10. JavaScript challenge
11. VPN/proxy/Tor detection
12. Datacenter detection
13. ASN blocking
14. Global bot/path/UA/referer rules (scoped exceptions skip only their relevant heuristics)
15. Country blocking
16. City/subdivision blocking
17. Country-specific rules
18. Allowed request logging/history

The exact implementation is in `WireWall::checkAccess()`.

## Traffic History For AI Analysis

If `enable_traffic_history` is enabled, WireWall writes one JSON object per public request:

```text
../SITE-DIRECTORY-wirewall-private/traffic/traffic-YYYY-MM-DD.jsonl
```

Schema marker:

```json
{"schema":"wirewall_traffic_v1"}
```

Typical fields include:

- `time`
- `unix_time`
- `status`
- `reason`
- `ip`
- `country`
- `city`
- `region`
- `asn`
- `method`
- `host`
- `path`
- `query`
- `url`
- `referer`
- `user_agent`
- selected browser/request headers

Agents may summarize, aggregate, or export this data for analysis. Do not expose raw IP/user-agent traffic history publicly. Treat it as sensitive operational data.

## Safe Operations

Agents may do these without special approval when the user asks for ordinary maintenance or explanation:

- Read module documentation.
- Read module metadata and current ProcessWire module config.
- Explain what a setting does.
- Recommend configuration profiles from `CONFIGURATIONS.md`.
- Inspect dashboard code and log parsing behavior.
- Check whether MaxMind files exist.
- Check syntax of module files.
- Add documentation such as `README.md`, `AGENTS.md`, `API.md`, or examples.
- Improve dashboard UI without changing blocking semantics.
- Add non-invasive display of existing stats.

## Versioning And Changelog Requirements

Every code update must include a SemVer version decision and a short changelog entry.

Use `Major.Minor.Patch`:

- Major: breaking behavior, changed public expectations, removed settings, changed minimum ProcessWire/PHP requirements, or migration-risk changes.
- Minor: new features, new configuration options, new dashboard capabilities, new data outputs, or meaningful UI/UX additions that keep existing behavior compatible.
- Patch: bug fixes, small internal improvements, copy tweaks, docs-only updates, or UI polish that does not add a capability.

When code changes:

- Update the main module version in `WireWall.module.php` header and `getModuleInfo()['version']`.
- Update `README.md` version text.
- Add a top entry to `CHANGELOG.md` with the SemVer version, date, and concise bullets.
- If `ProcessWireWall.module.php` behavior changes, update its header version and `getModuleInfo()['version']` too.

ProcessWire numeric module versions should map SemVer to an integer used by ProcessWire. For this module's existing convention:

- `1.6.0` -> `160`
- `1.8.0` -> `180`
- `1.8.1` -> `181`
- `1.8.2` -> `182`
- `1.9.0` -> `190`
- `1.10.0` -> `1100`
- `1.11.0` -> `1110`
- `1.6.1` -> `161`
- `1.7.0` -> `170`
- `2.0.0` -> `200`

If this mapping becomes ambiguous for versions with two-digit minor or patch numbers, document the decision in `CHANGELOG.md` before changing it.

Docs-only changes may still use a patch bump when they materially affect agent behavior, installation, operation, or safety. Tiny typo-only changes can be noted without a version bump if the user explicitly requests no release update.

## Requires Explicit Approval

Ask before doing these:

- Enabling or disabling WireWall on a live site.
- Changing `block_action`.
- Enabling country whitelist mode.
- Adding broad country, ASN, IP, path, User-Agent, or referer blocks.
- Disabling AJAX protection globally.
- Adding public API paths to bypass lists.
- Clearing active bans or all cache files on a production site.
- Changing rate limit thresholds on a production site.
- Changing allowed bots, allowed ASNs, or whitelists in a way that affects indexing or integrations.
- Deleting or exporting traffic history that contains real visitor IPs.

## High-Risk Operations

Treat these as high risk and explain consequences before proposing:

- `disable_ajax_protection = 1`
- `country_mode = whitelist`
- Blocking search bots
- Blocking broad datacenter ASNs when the site relies on SaaS, CDN, search, payments, or webhooks
- Adding `/api/`, `/graphql/`, `/webhook/`, or similar paths to bypass lists without route-level auth
- Deleting `/site/assets/WireWall/geoip/` or `/site/assets/WireWall/vendor/`
- Editing `getRealClientIP()` or proxy trust behavior
- Changing admin bypass logic
- Turning on redirect mode to an external URL

## Forbidden By Default

Do not do these unless the user explicitly asks and accepts risk:

- Do not remove admin bypass protections.
- Do not move private WireWall traffic history back under the web document root.
- Do not hard-code a client IP, country, or ASN in module source for one site.
- Do not write site-specific business rules into the module unless the user is intentionally customizing this copy.
- Do not assume README examples reflect the current live configuration.
- Do not treat `AGENTS.md` as proof that WireWall is installed or enabled on a site.

## APIs Not To Use As Public API

Most methods in `WireWall.module.php` are protected implementation details. Agents should not call or rely on these from templates or other modules:

- `checkAccess()`
- `blockAccess()`
- `showBlockPage()`
- `showJSChallenge()`
- `getGeoData()`
- `getCityData()`
- `isRateLimited()`
- `isProxyVPNTor()`
- `isDatacenter()`
- `detectFakeBrowser()`
- `recordTrafficHistory()`
- cache helper methods

Use module configuration, documented dashboard output, and generated traffic history files instead.

## Recommended Website Blueprint Guidance

When Olivia or another agent is designing a site that will use WireWall:

- Add WireWall as an infrastructure/security module in the Blueprint.
- Mention that it protects public ProcessWire page requests automatically.
- Include a configuration step after module installation.
- Include MaxMind setup for production sites with meaningful traffic.
- Identify public API/AJAX endpoints early so their bypass/auth model is explicit.
- Include dashboard permission assignment for admins who should see security stats.
- Include traffic-history retention/export policy if AI traffic analysis is part of the project.
- Do not present WireWall as analytics software; it can generate security traffic history, but it is not a replacement for a product analytics suite.

## Common Mistakes

- Forgetting to whitelist the site owner's current IP before testing aggressive rules.
- Enabling search bot blocking on a site that needs indexing.
- Using country whitelist mode without including all markets, payment providers, webhook origins, and admin/user locations.
- Adding `/api/` to `custom_api_paths` while the API has no authentication.
- Confusing ProcessWire logs with JSONL traffic history.
- Assuming Cloudflare or CDN headers are trusted without confirming proxy settings and ranges.
- Editing module source for one-off allow/block lists instead of using module config.

## Rollback Notes

Fast rollback options:

- Disable WireWall in module config.
- Add the affected IP to `ip_whitelist`.
- Remove the problematic path, ASN, User-Agent, referer, country, city, or subdivision rule.
- Clear active bans from cache management if a legitimate IP was temporarily banned.
- Temporarily set `block_action` to `bare_404`, `silent_404`, or `show_page` if redirect behavior is causing trouble.

Do not delete persistent data directories as a first rollback step.

## Olivia Ready Status

This module is an Olivia Ready candidate.

Current level target: Level 2, Agent-Aware.

Reasons:

- Has README, INSTALL, CONFIGURATIONS, and this AGENTS.md.
- Exposes clear configuration keys.
- Has explicit safety guidance.
- Provides AI-friendly JSONL traffic history.

To reach a stronger Olivia-compatible level, add:

- `API.md` with stable public API/config documentation
- `EXAMPLES.md` with known-good configuration scenarios
- test notes for dashboard and traffic history behavior
