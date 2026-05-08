<?php

declare(strict_types=1);

namespace App\Services;

use App\DTO\DomainCheckResult;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * URLhaus (abuse.ch) host lookup. Returns malicious URLs / domains hosting
 * malware, with threat type and tags. Free with required Auth-Key header
 * (register at https://auth.abuse.ch/).
 */
final class UrlhausService
{
    public const NAME = 'urlhaus';

    public function __construct(
        private readonly bool $enabled,
        private readonly ?string $apiKey,
        private readonly string $baseUrl,
        private readonly int $timeout,
    ) {}

    public function check(string $domain): DomainCheckResult
    {
        if (! $this->enabled) {
            return DomainCheckResult::skipped(self::NAME, 'Provider disabled');
        }

        if (empty($this->apiKey)) {
            return DomainCheckResult::skipped(self::NAME, 'API key not configured');
        }

        $url = rtrim($this->baseUrl, '/').'/host/';

        try {
            $response = Http::withHeaders(['Auth-Key' => $this->apiKey])
                ->timeout($this->timeout)
                ->acceptJson()
                ->asForm()
                ->post($url, ['host' => $domain]);
        } catch (Throwable $e) {
            Log::warning('URLhaus request failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            return DomainCheckResult::failed(self::NAME, $e->getMessage());
        }

        if (! $response->successful()) {
            Log::warning('URLhaus returned non-2xx', [
                'domain' => $domain,
                'status' => $response->status(),
                'body' => $response->body(),
            ]);

            return DomainCheckResult::failed(
                provider: self::NAME,
                error: 'HTTP '.$response->status().': '.$response->body(),
                details: ['http_status' => $response->status()],
            );
        }

        $json = (array) $response->json();
        $status = (string) ($json['query_status'] ?? '');

        if ($status === 'no_results') {
            return DomainCheckResult::success(
                provider: self::NAME,
                flagged: false,
                verdict: DomainCheckResult::VERDICT_CLEAN,
                details: ['query_status' => $status, 'url_count' => 0],
            );
        }

        if ($status !== 'ok') {
            // invalid_host, http_post_expected, etc. — surface as failed.
            return DomainCheckResult::failed(
                provider: self::NAME,
                error: 'URLhaus query_status='.$status,
                details: ['query_status' => $status],
            );
        }

        $urls = (array) ($json['urls'] ?? []);
        $onlineCount = 0;
        $offlineCount = 0;
        $threats = [];
        $tags = [];

        foreach ($urls as $u) {
            $urlStatus = (string) ($u['url_status'] ?? '');
            if ($urlStatus === 'online') {
                $onlineCount++;
            } else {
                $offlineCount++;
            }

            if (! empty($u['threat'])) {
                $threats[] = (string) $u['threat'];
            }
            foreach ((array) ($u['tags'] ?? []) as $tag) {
                $tags[] = (string) $tag;
            }
        }

        $threats = array_values(array_unique($threats));
        $tags = array_values(array_unique($tags));

        // Online malicious URLs → malicious. Only-offline (historical) → suspicious:
        // URLhaus listed it before, even if currently down it's a strong red flag.
        $verdict = $onlineCount > 0
            ? DomainCheckResult::VERDICT_MALICIOUS
            : DomainCheckResult::VERDICT_SUSPICIOUS;

        return DomainCheckResult::success(
            provider: self::NAME,
            flagged: true,
            verdict: $verdict,
            details: [
                'query_status' => $status,
                'url_count' => count($urls),
                'online_count' => $onlineCount,
                'offline_count' => $offlineCount,
                'threats' => $threats,
                'tags' => $tags,
                'firstseen' => $json['firstseen'] ?? null,
                'urlhaus_reference' => $json['urlhaus_reference'] ?? null,
                'blacklists' => $json['blacklists'] ?? null,
            ],
        );
    }
}
