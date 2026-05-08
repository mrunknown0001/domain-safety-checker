# Domain Safety Checker

A Laravel API that checks whether a domain is flagged for spam, phishing, malware, or other threats by combining results from **VirusTotal**, **Google Safe Browsing**, and **URLhaus (abuse.ch)** into a single verdict. Optionally pushes verdicts back to a "main app" via webhook.

Built on Laravel 12 (PHP 8.2+), MySQL/Redis via Sail.

---

## Features

- Three independent providers, each runs in isolation. If one provider is unconfigured or fails, the others still produce a verdict.
- Worst-wins aggregation: `malicious > suspicious > unknown > clean`.
- Heuristic rules catch fresh phishing the public APIs haven't yet listed (young domain + self-signed cert + high-abuse TLD).
- 1-hour result cache to stay under free-tier rate limits, keyed by host + path so different URLs on the same host don't collide.
- REST API for ad-hoc and batch checks (up to 20 domains/request).
- Optional webhook integration that pulls a domain list from your main app, runs checks, and POSTs verdicts back per-domain.
- Graceful degradation: missing API keys produce `skipped` results, not failures.

---

## Endpoints

All routes are prefixed with `/api/domain` and rate-limited to 30 req/min.

| Method | Path | Description |
|---|---|---|
| `GET` / `POST` | `/api/domain/check?domain={domain}` | Check a single domain |
| `POST` | `/api/domain/check-batch` | Check up to 20 domains. Body: `{ "domains": ["a.com", "b.com"] }` |

### Response shape

```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "input": "https://example.com/path?q=1",
    "safe": true,
    "verdict": "clean",
    "checked_at": "2026-05-08T10:30:00+00:00",
    "summary": {
      "total_flags": 0,
      "is_malware": false,
      "is_phishing": false,
      "is_unwanted": false,
      "providers_checked": 3,
      "providers_flagged": 0
    },
    "providers": [
      { "provider": "virustotal",           "status": "success", "flagged": false, "verdict": "clean", "details": { ... }, "error": null },
      { "provider": "google_safe_browsing", "status": "success", "flagged": false, "verdict": "clean", "details": { ... }, "error": null },
      { "provider": "urlhaus",              "status": "success", "flagged": false, "verdict": "clean", "details": { ... }, "error": null }
    ]
  }
}
```

The endpoint returns HTTP 200 even for malicious domains — the verdict lives in the body. A flagged domain is a *successful check*, not a failed request.

---

## How verdicts are decided

### VirusTotal

1. `malicious >= VT_MALICIOUS_MIN` → **malicious**
2. `malicious + suspicious >= VT_SUSPICIOUS_MIN` → **suspicious**
3. **Heuristic — young domain, no engine detections, no harmless confirmations** → **suspicious**
4. **Heuristic — young domain on a high-abuse TLD or with a suspicious VT tag** (`self-signed`, `dynamic-dns`, `free-dns`) → **suspicious**
5. `harmless < VT_MIN_HARMLESS_FOR_CLEAN` → **unknown** (silence is not approval)
6. otherwise → **clean**
7. HTTP 404 from VT → **unknown** (VT just hasn't seen the domain; not a failure)

### Google Safe Browsing

Submits 4 URL variants (http/https × bare/www); when a path is present, also submits 4 path-bearing variants. Any match across `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION` → **malicious**. Empty matches → **clean**.

### URLhaus

`POST /v1/host/` with `Auth-Key` header.

- `query_status: ok` with online URLs → **malicious**
- `query_status: ok` with only offline URLs (historical listings) → **suspicious**
- `query_status: no_results` → **clean**
- anything else → **failed**

URLhaus surfaces threat type (`malware_download`), tags (`ClearFake`, `Emotet`, etc.), first-seen date, and Spamhaus DBL classification.

### Aggregation

The orchestrator picks the worst verdict across all three providers, with the rank: `malicious > suspicious > unknown > clean`. If every provider was skipped or failed, the verdict is `unknown` — never `clean` by default.

---

## Setup

This project ships with Laravel Sail.

```bash
cp .env.example .env
docker compose up -d
docker compose exec laravel.test php artisan key:generate
docker compose exec laravel.test php artisan install:api      # generates routes/api.php (only on first install)
docker compose exec laravel.test php artisan migrate
```

### API keys

| Provider | Where to get it | Free-tier limits |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | 4 req/min, 500/day, 15.5K/month |
| Google Safe Browsing | https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com (Enable API → Credentials → Create API Key) | 10,000/day |
| URLhaus | https://auth.abuse.ch/ (free account, click "Auth-Key") | No published limit |

Drop them into `.env`:

```dotenv
VIRUSTOTAL_API_KEY=...
GOOGLE_SAFE_BROWSING_API_KEY=...
URLHAUS_API_KEY=...
```

Then `docker compose exec laravel.test php artisan config:clear`.

The 1-hour result cache (`DOMAIN_SAFETY_CACHE_TTL=3600`) is what makes this practical at scale — most repeat lookups never hit the upstream APIs.

---

## Configuration

All configuration lives in [config/domain-safety.php](config/domain-safety.php) and is driven by env vars. The full set is documented inline in [.env.example](.env.example); a tour of the most important knobs:

### Provider toggles

```dotenv
VIRUSTOTAL_ENABLED=true
GOOGLE_SAFE_BROWSING_ENABLED=true
URLHAUS_ENABLED=true
```

Set any to `false` to skip that provider entirely (returns `skipped` in the response).

### Verdict thresholds

```dotenv
VT_MALICIOUS_MIN=2              # engines flagging "malicious" needed for verdict=malicious
VT_SUSPICIOUS_MIN=1             # engines flagging malicious+suspicious for verdict=suspicious
VT_MIN_HARMLESS_FOR_CLEAN=1     # engines confirming "harmless" needed for verdict=clean
VT_NEW_DOMAIN_DAYS=90           # threshold for "young domain" heuristics (0 = disable)
```

### Heuristic signals (catch fresh phishing the APIs miss)

```dotenv
VT_SUSPICIOUS_TAGS=self-signed,dynamic-dns,free-dns
HIGH_RISK_TLDS=sbs,click,top,xyz,tk,ml,ga,cf,gq,men,live,work,icu,quest,cyou,monster,lol,mom,rest,buzz,zip,mov,cam,beauty,bond,sale,info
```

A domain is flagged `suspicious` when **all** of: (younger than `VT_NEW_DOMAIN_DAYS`) AND (zero engine detections) AND (suspicious VT tag OR high-risk TLD). Old domains bypass these rules even on quirky TLDs.

### Cache

```dotenv
DOMAIN_SAFETY_CACHE_ENABLED=true
DOMAIN_SAFETY_CACHE_TTL=3600
```

---

## Webhook integration (optional)

The checker can pull a domain list from a main app, run checks, and POST verdicts back per-domain. Driven by `php artisan domain-safety:sync`.

### Configuration

```dotenv
MAIN_APP_ENABLED=true
MAIN_APP_BASE_URL=https://your-main-app.example.com
MAIN_APP_DOMAINS_ENDPOINT=/api/domains
MAIN_APP_WEBHOOK_PATH=/api/webhooks/domain-safety/{domain}
MAIN_APP_WEBHOOK_SECRET=your-shared-secret
MAIN_APP_TIMEOUT=15
MAIN_APP_NOTIFY_ON_UNKNOWN=false
```

The main app must expose:

- `GET {MAIN_APP_BASE_URL}{MAIN_APP_DOMAINS_ENDPOINT}` returning `{ "data": [ { "domain_name": "..." }, ... ] }`
- `POST {MAIN_APP_BASE_URL}{MAIN_APP_WEBHOOK_PATH}` (with `{domain}` substituted) accepting:
  - Header: `X-Webhook-Secret: <MAIN_APP_WEBHOOK_SECRET>`
  - Body: `{ "is_safe": bool, "threat_type": "MALWARE" }` (`threat_type` optional, max 255 chars)

### Webhook payload mapping

| Verdict | `is_safe` | `threat_type` |
|---|---|---|
| `clean` | `true` | `null` |
| `unknown` | (skipped by default; `is_safe=true` if `MAIN_APP_NOTIFY_ON_UNKNOWN=true`) | `null` |
| `suspicious` | `false` | `SUSPICIOUS` (or specific GSB/URLhaus label if available) |
| `malicious` | `false` | `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, `VT_FLAGGED:engine1,engine2,...`, or `MALICIOUS` |

Priority order for `threat_type`: GSB-specific label → URLhaus malware label → VT engine names → generic verdict.

### Running the sync

```bash
docker compose exec laravel.test php artisan domain-safety:sync               # full sync
docker compose exec laravel.test php artisan domain-safety:sync --dry-run     # don't POST, just log
docker compose exec laravel.test php artisan domain-safety:sync --domain=foo.com   # one domain
docker compose exec laravel.test php artisan domain-safety:sync --interval=20      # override per-domain throttle
```

### Rate-limit throttling

VirusTotal's free tier caps you at **4 requests/min**. To stay under that, the sync command sleeps `DOMAIN_SAFETY_SYNC_INTERVAL` seconds (default **15**) between consecutive domain checks — but **only after a cache miss**. Cache hits skip the sleep entirely, so re-running sync over an already-cached set finishes in seconds.

For a 100-domain list, expect a worst-case 100 × 15s = ~25 minutes when the cache is fully cold. Set `--interval=0` (or `DOMAIN_SAFETY_SYNC_INTERVAL=0`) to disable throttling if you have a paid VirusTotal plan.

To run on a schedule, add to [routes/console.php](routes/console.php):

```php
Schedule::command('domain-safety:sync')->hourly();
```

---

## Telegram notifications (optional)

Get a Telegram message every time a domain check produces a flagged verdict (malicious or suspicious). Fires from any source — direct API check, batch endpoint, or scheduled sync.

### Setup

1. Open Telegram, message **@BotFather** → `/newbot` → save the bot token.
2. Start a chat with your new bot (or add it to a group) and send any message.
3. Get your chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates` — look for `"chat":{"id":...}`. Group chat ids are negative (e.g. `-1001234567890`).
4. Set in `.env`:

```dotenv
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=1234567890:ABC...
TELEGRAM_CHAT_ID=-1001234567890
TELEGRAM_DEDUP_TTL=86400
```

5. Clear config and send a test alert:

```bash
docker compose exec laravel.test php artisan config:clear
docker compose exec laravel.test php artisan domain-safety:test-telegram
```

### Behavior

- Fires on **cache miss** + flagged verdict, so a single domain producing many requests-per-hour generates **at most one** notification per cache cycle.
- Further deduplicated per-domain via `TELEGRAM_DEDUP_TTL` (default 24h) — a persistently flagged domain only pings once a day.
- Failures are logged to `storage/logs/laravel.log` but never raise to the caller; the API check always returns its result regardless of whether Telegram delivery succeeded.
- Message includes provider-by-provider breakdown, threat tags from URLhaus, VT engine names, and the heuristic reasons (e.g. *newly registered on high-abuse TLD .click*).

### Disable notifications

Either set `TELEGRAM_ENABLED=false` or leave `TELEGRAM_BOT_TOKEN` empty.

---

## Architecture

```
app/
├── Console/Commands/
│   ├── SyncDomainSafety.php            — domain-safety:sync command
│   └── TestTelegramNotification.php    — domain-safety:test-telegram
├── DTO/
│   └── DomainCheckResult.php           — shared per-provider response shape
├── Http/
│   ├── Controllers/Api/
│   │   └── DomainCheckController.php
│   └── Requests/
│       └── DomainCheckRequest.php
├── Providers/
│   └── DomainSafetyServiceProvider.php — singleton bindings, config injection
└── Services/
    ├── DomainSafetyService.php         — orchestrator: normalize, cache, aggregate, notify
    ├── VirusTotalService.php
    ├── GoogleSafeBrowsingService.php
    ├── UrlhausService.php
    ├── TelegramNotifier.php            — sends alerts on flagged verdicts
    └── MainAppClient.php               — pulls domain list + posts webhook back

config/domain-safety.php                — all provider, threshold, heuristic, cache, webhook, and telegram settings
routes/api.php                          — endpoint + throttle wiring
routes/console.php                      — scheduler registration
```

Adding a new provider (e.g. PhishTank, AbuseIPDB) is a four-step change:

1. Create `App\Services\NewProviderService` with a `check(string $domain): DomainCheckResult` method.
2. Add config in [config/domain-safety.php](config/domain-safety.php).
3. Register the singleton in [app/Providers/DomainSafetyServiceProvider.php](app/Providers/DomainSafetyServiceProvider.php).
4. Inject and call it in [app/Services/DomainSafetyService.php](app/Services/DomainSafetyService.php) `runProviders()`.

Existing providers don't need to be touched.

---

## Testing manually

```bash
# Clean baseline
curl "http://localhost/api/domain/check?domain=google.com"

# GSB phishing test fixture
curl "http://localhost/api/domain/check?domain=testsafebrowsing.appspot.com/s/phishing.html"

# GSB malware test fixture
curl "http://localhost/api/domain/check?domain=testsafebrowsing.appspot.com/s/malware.html"

# Batch
curl -X POST "http://localhost/api/domain/check-batch" \
  -H "Content-Type: application/json" \
  -d '{"domains":["google.com","example.com"]}'
```

To find a fresh URLhaus-listed host for testing:

```bash
curl -sS -H "Auth-Key: $URLHAUS_API_KEY" \
  "https://urlhaus-api.abuse.ch/v1/urls/recent/" \
  | jq -r '.urls[] | select(.url_status == "online") | .host' | head -5
```

---

## Common gotchas

- **VirusTotal 4-req/min limit** during testing → wait, or rely on the cache.
- **Stale VT analysis**: the public `/domains/{d}` endpoint returns the *stored* analysis, which may be days/weeks old. Trigger a fresh re-scan via `POST /domains/{d}/analyse` if you need current data.
- **GSB returns `clean` for known phishing test paths**: GSB matches at URL granularity. We submit the full URL when a path is present, plus the bare-host variants. Without a path, the test fixtures won't match.
- **URLhaus 401**: the API now requires `Auth-Key`. Older docs that show unauthenticated examples are out of date.
- **Cloudflare/anti-bot blocks on the main app**: the webhook client sends a browser User-Agent (`Mozilla/5.0 ...`) by default to bypass these.

---

## License

MIT.
