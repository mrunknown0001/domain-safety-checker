# Implementation Prompt

Copy and paste the prompt below into Claude (or any capable AI coding assistant) inside a fresh Laravel project. It will set up the entire domain safety checker end-to-end.

---

## The Prompt

```
I need you to build a Domain Safety Checker API in this fresh Laravel project. The API checks if a domain is flagged for spam, phishing, malware, or other threats by combining results from VirusTotal and Google Safe Browsing into a single verdict.

## Project Context
- This is a fresh Laravel project (Laravel 11 or 12)
- I will provide my API keys later via .env
- The deliverable is a working REST API with two endpoints

## Requirements

### Functional Requirements
1. Check a single domain via `GET /api/domain/check?domain=example.com` and `POST /api/domain/check`
2. Check up to 20 domains in batch via `POST /api/domain/check-batch`
3. Combine results from VirusTotal and Google Safe Browsing into one verdict: `clean`, `suspicious`, `malicious`, or `unknown`
4. Cache results (default 1 hour) to stay under free-tier rate limits
5. Gracefully handle missing API keys — if one provider is unconfigured or fails, the other still runs
6. Normalize input: accept `example.com`, `https://example.com`, `https://example.com/path?q=1` and reduce to bare hostname
7. Return HTTP 200 even for malicious domains (the verdict lives in the response body — a flagged domain is a successful check, not a failed request)

### Architecture Requirements
Build it modular so I can add more providers (PhishTank, URLhaus, AbuseIPDB) later without touching existing code:

- **DTO**: `App\DTO\DomainCheckResult` — shared response shape with `provider`, `status` (success/failed/skipped), `flagged` (bool), `verdict`, `details` (array), `error` fields. Include static `skipped()` and `failed()` factory methods.

- **Provider services** (each independent, same interface shape):
  - `App\Services\VirusTotalService` — calls `https://www.virustotal.com/api/v3/domains/{domain}` with `x-apikey` header. Read `data.attributes.last_analysis_stats` for malicious/suspicious counts. Return verdict based on configurable thresholds. Treat HTTP 404 as `unknown` (not failed) — VT just hasn't seen the domain. Include a `flagged_by` array of engine names that flagged it.
  - `App\Services\GoogleSafeBrowsingService` — POSTs to `https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}`. Submit 4 URL variants per domain (http/https × bare/www). Check threat types: MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION. Empty `matches` = clean.

- **Orchestrator**: `App\Services\DomainSafetyService` — normalizes input, runs all enabled providers, caches the result, aggregates verdicts. Verdict precedence: `malicious > suspicious > unknown > clean` (worst wins). If every provider failed/skipped, verdict is `unknown` — never `clean` by default.

- **Form request**: `App\Http\Requests\DomainCheckRequest` — validates the domain field with a regex that accepts both bare hostnames and full URLs.

- **Controller**: `App\Http\Controllers\Api\DomainCheckController` with `check()` and `batch()` methods. Batch validates `domains` is an array of 1-20 strings.

- **Service provider**: `App\Providers\DomainSafetyServiceProvider` — binds the three services as singletons, injecting config values via constructor.

- **Config file**: `config/domain-safety.php` with sections for each provider (enabled flag, api_key, base_url, timeout), cache settings (enabled, ttl, prefix), and verdict thresholds (`virustotal_malicious_min` default 2, `virustotal_suspicious_min` default 1).

### Response Shape
Single check response:
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "safe": true,
    "verdict": "clean",
    "checked_at": "2026-05-07T10:30:00+00:00",
    "summary": {
      "total_flags": 0,
      "is_malware": false,
      "is_phishing": false,
      "is_unwanted": false,
      "providers_checked": 2,
      "providers_flagged": 0
    },
    "providers": [
      { "provider": "virustotal", "status": "success", "flagged": false, "verdict": "clean", "details": { ... }, "error": null },
      { "provider": "google_safe_browsing", "status": "success", "flagged": false, "verdict": "clean", "details": { ... }, "error": null }
    ]
  }
}
```

The `summary` object derives `is_phishing` from Google's `SOCIAL_ENGINEERING` threat type, `is_malware` from `MALWARE`, `is_unwanted` from `UNWANTED_SOFTWARE` or `POTENTIALLY_HARMFUL_APPLICATION`.

### Routes
Add to `routes/api.php` under prefix `domain` with `throttle:30,1` middleware:
- `GET|POST /api/domain/check`
- `POST /api/domain/check-batch`

If `routes/api.php` doesn't exist (Laravel 11+ default), run `php artisan install:api` first.

### Error Handling
- Wrap every HTTP call in try/catch and log warnings (don't bubble exceptions to the user)
- Use Laravel's `Http` facade with `->timeout()` set from config
- If API key is empty, return a `skipped` result with reason "API key not configured"
- If HTTP call returns non-2xx, return `failed` result with the status code and body in the error field

### Environment Variables
Add to `.env.example` and document in README:
```
VIRUSTOTAL_ENABLED=true
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_ENABLED=true
GOOGLE_SAFE_BROWSING_API_KEY=
GOOGLE_SAFE_BROWSING_CLIENT_ID=laravel-domain-checker
GOOGLE_SAFE_BROWSING_CLIENT_VERSION=1.0.0
DOMAIN_SAFETY_CACHE_ENABLED=true
DOMAIN_SAFETY_CACHE_TTL=3600
VT_MALICIOUS_MIN=2
VT_SUSPICIOUS_MIN=1
```

### Free-tier Limits to Respect
- VirusTotal: 4 requests/min, 500/day, 15.5K/month
- Google Safe Browsing: 10,000/day
- The 1-hour cache is what makes this practical at scale

## Deliverables

1. Create all the files described above
2. Register the service provider in `bootstrap/providers.php` (Laravel 11+) or `config/app.php` (Laravel 10)
3. Update `.env.example` with the new variables
4. Run `php artisan install:api` if needed
5. Run `php artisan config:clear` at the end
6. Provide a brief test command using curl to verify it works

## Testing
After implementation, verify with these test domains:
- `google.com` → should return verdict `clean`
- `testsafebrowsing.appspot.com/s/malware.html` → should be flagged by Google Safe Browsing as malware
- `testsafebrowsing.appspot.com/s/phishing.html` → should be flagged as phishing (SOCIAL_ENGINEERING)

Build it now. Use PHP 8.2+ features (constructor property promotion, readonly properties where appropriate, match expressions, named arguments). Add docblocks to public methods and inline comments for non-obvious logic only.
```

---

## Tips for using this prompt

1. **Run it in an empty Laravel project.** A fresh `composer create-project laravel/laravel my-app` gives the cleanest baseline.

2. **Get your API keys first** so you can test immediately:
   - VirusTotal: https://www.virustotal.com/gui/my-apikey (instant, free)
   - Google Safe Browsing: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com (enable API → Credentials → Create API Key)

3. **If you're using Claude Code**, drop this prompt into a `.md` file in your repo and reference it. Claude Code can read your existing structure and integrate cleanly.

4. **After it's built**, test with:
   ```bash
   php artisan serve
   curl "http://localhost:8000/api/domain/check?domain=google.com"
   curl "http://localhost:8000/api/domain/check?domain=testsafebrowsing.appspot.com/s/malware.html"
   ```

5. **Common gotchas to watch for**:
   - Forgetting to register the service provider → endpoints return 500
   - Skipping `php artisan install:api` on Laravel 11+ → `routes/api.php` doesn't exist, routes won't load
   - Using `config()` before `config:clear` → old cached values
   - Hitting the VirusTotal 4/min limit during testing → wait or rely on cache