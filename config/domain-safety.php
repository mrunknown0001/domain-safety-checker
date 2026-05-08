<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cache settings
    |--------------------------------------------------------------------------
    */
    'cache' => [
        'enabled' => env('DOMAIN_SAFETY_CACHE_ENABLED', true),
        'ttl' => (int) env('DOMAIN_SAFETY_CACHE_TTL', 3600),
        'prefix' => env('DOMAIN_SAFETY_CACHE_PREFIX', 'domain_safety:'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Sync command throttling
    |--------------------------------------------------------------------------
    | Seconds to sleep between consecutive upstream calls in
    | `php artisan domain-safety:sync`. Sleeps only after a cache miss (cache
    | hits don't burn the rate-limit budget). 15s caps us at 4 VT calls/min,
    | matching VirusTotal's free-tier limit. Set 0 to disable.
    */
    'sync' => [
        'interval_seconds' => (int) env('DOMAIN_SAFETY_SYNC_INTERVAL', 15),
    ],

    /*
    |--------------------------------------------------------------------------
    | Verdict thresholds
    |--------------------------------------------------------------------------
    | The minimum number of VirusTotal engines that must flag a domain before
    | the verdict crosses into "suspicious" or "malicious".
    */
    'thresholds' => [
        'virustotal_malicious_min' => (int) env('VT_MALICIOUS_MIN', 2),
        'virustotal_suspicious_min' => (int) env('VT_SUSPICIOUS_MIN', 1),
        // Minimum number of engines that must mark a domain "harmless" before we'll
        // call it `clean`. Below this, with no malicious/suspicious flags either,
        // the verdict is `unknown` — silence is not approval.
        'virustotal_min_harmless_for_clean' => (int) env('VT_MIN_HARMLESS_FOR_CLEAN', 1),
        // Domains younger than this many days AND with zero "harmless" votes are
        // treated as `suspicious` — fresh registration with no positive signal is
        // a strong phishing fingerprint (set to 0 to disable).
        'virustotal_new_domain_days' => (int) env('VT_NEW_DOMAIN_DAYS', 90),
    ],

    /*
    |--------------------------------------------------------------------------
    | Heuristic signals
    |--------------------------------------------------------------------------
    | When the public APIs haven't yet flagged a domain, these signals catch
    | the long tail of fresh phishing/malware that Chrome's Enhanced Safe
    | Browsing catches via real-time analysis (not exposed in the public API).
    |
    | A domain is flagged `suspicious` when ALL of:
    |   - it's younger than `virustotal_new_domain_days`
    |   - VT's malicious/suspicious counts are zero
    |   - AND any of:
    |       • it has a VT tag in `suspicious_vt_tags` (e.g. self-signed cert)
    |       • its TLD is in `high_risk_tlds`
    */
    'heuristics' => [
        'suspicious_vt_tags' => array_values(array_filter(array_map('trim', explode(
            ',',
            (string) env('VT_SUSPICIOUS_TAGS', 'self-signed,dynamic-dns,free-dns'),
        )))),
        'high_risk_tlds' => array_values(array_filter(array_map(
            static fn ($t) => strtolower(ltrim(trim((string) $t), '.')),
            explode(',', (string) env(
                'HIGH_RISK_TLDS',
                // Curated from Spamhaus / Interisle abuse reports — TLDs with
                // disproportionately high phishing/malware ratios.
                'sbs,click,top,xyz,tk,ml,ga,cf,gq,men,live,work,icu,quest,cyou,monster,lol,mom,rest,buzz,zip,mov,cam,beauty,bond,sale,info'
            )),
        ))),
    ],

    /*
    |--------------------------------------------------------------------------
    | Providers
    |--------------------------------------------------------------------------
    */
    'providers' => [

        'virustotal' => [
            'enabled' => env('VIRUSTOTAL_ENABLED', true),
            'api_key' => env('VIRUSTOTAL_API_KEY'),
            'base_url' => env('VIRUSTOTAL_BASE_URL', 'https://www.virustotal.com/api/v3'),
            'timeout' => (int) env('VIRUSTOTAL_TIMEOUT', 10),
        ],

        'google_safe_browsing' => [
            'enabled' => env('GOOGLE_SAFE_BROWSING_ENABLED', true),
            'api_key' => env('GOOGLE_SAFE_BROWSING_API_KEY'),
            'base_url' => env('GOOGLE_SAFE_BROWSING_BASE_URL', 'https://safebrowsing.googleapis.com/v4'),
            'timeout' => (int) env('GOOGLE_SAFE_BROWSING_TIMEOUT', 10),
            'client_id' => env('GOOGLE_SAFE_BROWSING_CLIENT_ID', 'laravel-domain-checker'),
            'client_version' => env('GOOGLE_SAFE_BROWSING_CLIENT_VERSION', '1.0.0'),
        ],

        'urlhaus' => [
            'enabled' => env('URLHAUS_ENABLED', true),
            'api_key' => env('URLHAUS_API_KEY'),
            'base_url' => env('URLHAUS_BASE_URL', 'https://urlhaus-api.abuse.ch/v1'),
            'timeout' => (int) env('URLHAUS_TIMEOUT', 10),
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Telegram notifications
    |--------------------------------------------------------------------------
    | Sends a message to the configured chat whenever a domain check produces
    | a flagged (malicious/suspicious) verdict. Notifications are deduplicated
    | per-domain via the cache, so the same flagged domain doesn't spam every
    | time the result cache expires.
    */
    'telegram' => [
        'enabled' => env('TELEGRAM_ENABLED', true),
        'bot_token' => env('TELEGRAM_BOT_TOKEN'),
        'chat_id' => env('TELEGRAM_CHAT_ID'),
        'timeout' => (int) env('TELEGRAM_TIMEOUT', 8),
        // Suppress duplicate notifications for the same domain for this many
        // seconds. 86400 = 24h. Set to 0 to disable dedup.
        'dedup_ttl' => (int) env('TELEGRAM_DEDUP_TTL', 86400),
        'cache_prefix' => env('TELEGRAM_DEDUP_PREFIX', 'telegram_notified:'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Main app integration (push webhook back with safety status)
    |--------------------------------------------------------------------------
    | The main app exposes:
    |   GET  {base_url}{domains_endpoint}            — list domains to check
    |   POST {base_url}/api/webhooks/domain-safety/{domain}
    |        with X-Webhook-Secret header and JSON body { is_safe, threat_type }
    |
    | The remote endpoint blocks "bot" user agents, so we send a browser UA.
    */
    'main_app' => [
        'enabled' => env('MAIN_APP_ENABLED', true),
        'base_url' => env('MAIN_APP_BASE_URL', 'https://admin.wearenottouchingus.xyz'),
        'domains_endpoint' => env('MAIN_APP_DOMAINS_ENDPOINT', '/api/domains'),
        'webhook_path_template' => env('MAIN_APP_WEBHOOK_PATH', '/api/webhooks/domain-safety/{domain}'),
        'webhook_secret' => env('MAIN_APP_WEBHOOK_SECRET'),
        'timeout' => (int) env('MAIN_APP_TIMEOUT', 15),
        'user_agent' => env('MAIN_APP_USER_AGENT', 'Mozilla/5.0 (compatible; DomainSafetyChecker/1.0)'),
        // If true, also notify when verdict is `unknown` (treated as is_safe=true).
        // Default: skip unknowns so we never overwrite a known-bad with stale "safe".
        'notify_on_unknown' => env('MAIN_APP_NOTIFY_ON_UNKNOWN', false),
    ],

];
