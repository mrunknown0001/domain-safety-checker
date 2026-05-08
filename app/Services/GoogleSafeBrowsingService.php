<?php

declare(strict_types=1);

namespace App\Services;

use App\DTO\DomainCheckResult;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

final class GoogleSafeBrowsingService
{
    public const NAME = 'google_safe_browsing';

    private const THREAT_TYPES = [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
    ];

    public function __construct(
        private readonly bool $enabled,
        private readonly ?string $apiKey,
        private readonly string $baseUrl,
        private readonly int $timeout,
        private readonly string $clientId,
        private readonly string $clientVersion,
    ) {}

    /**
     * Check a domain or full URL against Google Safe Browsing's threatMatches endpoint.
     *
     * GSB matches on URLs (including path), so when a path is present we submit
     * the path-bearing variants in addition to the bare-host variants.
     */
    public function check(string $input): DomainCheckResult
    {
        if (! $this->enabled) {
            return DomainCheckResult::skipped(self::NAME, 'Provider disabled');
        }

        if (empty($this->apiKey)) {
            return DomainCheckResult::skipped(self::NAME, 'API key not configured');
        }

        $variants = $this->urlVariants($input);

        if (empty($variants)) {
            return DomainCheckResult::failed(self::NAME, 'Could not parse a hostname from input');
        }

        $url = rtrim($this->baseUrl, '/').'/threatMatches:find?key='.urlencode($this->apiKey);

        $payload = [
            'client' => [
                'clientId' => $this->clientId,
                'clientVersion' => $this->clientVersion,
            ],
            'threatInfo' => [
                'threatTypes' => self::THREAT_TYPES,
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => array_map(
                    static fn (string $u): array => ['url' => $u],
                    $variants,
                ),
            ],
        ];

        try {
            $response = Http::timeout($this->timeout)
                ->acceptJson()
                ->asJson()
                ->post($url, $payload);
        } catch (Throwable $e) {
            Log::warning('Google Safe Browsing request failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            return DomainCheckResult::failed(self::NAME, $e->getMessage());
        }

        if (! $response->successful()) {
            Log::warning('Google Safe Browsing returned non-2xx', [
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

        $matches = (array) data_get($response->json(), 'matches', []);

        if (empty($matches)) {
            return DomainCheckResult::success(
                provider: self::NAME,
                flagged: false,
                verdict: DomainCheckResult::VERDICT_CLEAN,
                details: [
                    'matches' => [],
                    'threat_types' => [],
                ],
            );
        }

        $threatTypes = array_values(array_unique(
            array_filter(array_map(
                static fn (array $m): ?string => $m['threatType'] ?? null,
                $matches,
            )),
        ));

        return DomainCheckResult::success(
            provider: self::NAME,
            flagged: true,
            verdict: DomainCheckResult::VERDICT_MALICIOUS,
            details: [
                'matches' => $matches,
                'threat_types' => $threatTypes,
            ],
        );
    }

    /**
     * Build URL variants Safe Browsing should match against. Always includes the
     * four bare-host variants (http/https × bare/www); if the input carries a
     * path or query, also includes the path-bearing variants so GSB can hit
     * URL-specific signatures.
     */
    private function urlVariants(string $input): array
    {
        $trimmed = trim($input);
        if ($trimmed === '') {
            return [];
        }

        $candidate = preg_match('#^https?://#i', $trimmed) === 1
            ? $trimmed
            : 'http://'.$trimmed;

        $parts = parse_url($candidate);
        $host = strtolower(ltrim((string) ($parts['host'] ?? ''), '.'));

        if ($host === '') {
            return [];
        }

        $path = (string) ($parts['path'] ?? '');
        $query = isset($parts['query']) ? '?'.$parts['query'] : '';
        $tail = $path.$query;

        $www = str_starts_with($host, 'www.') ? $host : 'www.'.$host;
        $noWww = str_starts_with($host, 'www.') ? substr($host, 4) : $host;

        $variants = [
            'http://'.$noWww,
            'https://'.$noWww,
            'http://'.$www,
            'https://'.$www,
        ];

        if ($tail !== '' && $tail !== '/') {
            $variants[] = 'http://'.$noWww.$tail;
            $variants[] = 'https://'.$noWww.$tail;
            $variants[] = 'http://'.$www.$tail;
            $variants[] = 'https://'.$www.$tail;
        }

        return array_values(array_unique($variants));
    }
}
