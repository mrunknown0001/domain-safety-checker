<?php

declare(strict_types=1);

namespace App\Services;

use App\DTO\DomainCheckResult;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;

final class DomainSafetyService
{
    private const VERDICT_RANK = [
        DomainCheckResult::VERDICT_CLEAN => 0,
        DomainCheckResult::VERDICT_UNKNOWN => 1,
        DomainCheckResult::VERDICT_SUSPICIOUS => 2,
        DomainCheckResult::VERDICT_MALICIOUS => 3,
    ];

    public function __construct(
        private readonly VirusTotalService $virusTotal,
        private readonly GoogleSafeBrowsingService $googleSafeBrowsing,
        private readonly UrlhausService $urlhaus,
        private readonly bool $cacheEnabled,
        private readonly int $cacheTtl,
        private readonly string $cachePrefix,
    ) {}

    /**
     * Run all enabled providers against a single domain and return an aggregated payload.
     */
    public function check(string $input): array
    {
        $domain = $this->normalize($input);

        if ($domain === '') {
            return $this->buildPayload($input, [], $input);
        }

        // Cache key includes path/query so different URLs on the same host
        // don't collide — GSB matches at URL granularity, not host.
        $cacheToken = $this->cacheToken($input);

        if ($this->cacheEnabled) {
            $key = $this->cachePrefix.$cacheToken;

            return Cache::remember(
                $key,
                $this->cacheTtl,
                fn (): array => $this->runProviders($domain, $input),
            );
        }

        return $this->runProviders($domain, $input);
    }

    /**
     * @param  string[]  $domains
     */
    public function checkBatch(array $domains): array
    {
        $results = [];
        foreach ($domains as $domain) {
            $results[] = $this->check($domain);
        }

        return $results;
    }

    /**
     * Reduce arbitrary input (URL, host with scheme, host with path) down to a bare hostname.
     */
    public function normalize(string $input): string
    {
        $trimmed = trim($input);
        if ($trimmed === '') {
            return '';
        }

        // parse_url needs a scheme to reliably extract the host.
        $candidate = preg_match('#^https?://#i', $trimmed) === 1
            ? $trimmed
            : 'http://'.$trimmed;

        $host = parse_url($candidate, PHP_URL_HOST);
        if (! is_string($host) || $host === '') {
            // Fall back to the raw value with any path stripped.
            $host = strtok($trimmed, '/');
        }

        return strtolower(ltrim((string) $host, '.'));
    }

    private function runProviders(string $domain, string $original): array
    {
        $results = [
            // VT's domains endpoint takes a bare hostname.
            $this->virusTotal->check($domain),
            // GSB matches at URL granularity, so pass the original input.
            $this->googleSafeBrowsing->check($original),
            // URLhaus does host-based lookup.
            $this->urlhaus->check($domain),
        ];

        return $this->buildPayload($domain, $results, $original);
    }

    /**
     * Build a stable cache token from the input — host + path + query, lowercased,
     * scheme and trailing slash stripped.
     */
    private function cacheToken(string $input): string
    {
        $trimmed = trim($input);
        $candidate = preg_match('#^https?://#i', $trimmed) === 1
            ? $trimmed
            : 'http://'.$trimmed;

        $parts = parse_url($candidate);
        $host = strtolower(ltrim((string) ($parts['host'] ?? ''), '.'));
        $path = rtrim((string) ($parts['path'] ?? ''), '/');
        $query = isset($parts['query']) ? '?'.$parts['query'] : '';

        return $host.$path.$query;
    }

    /**
     * @param  DomainCheckResult[]  $results
     */
    private function buildPayload(string $domain, array $results, string $original): array
    {
        $verdict = $this->aggregateVerdict($results);
        $summary = $this->summarize($results);

        return [
            'domain' => $domain,
            'input' => $original,
            'safe' => ! in_array(
                $verdict,
                [DomainCheckResult::VERDICT_MALICIOUS, DomainCheckResult::VERDICT_SUSPICIOUS],
                true,
            ),
            'verdict' => $verdict,
            'checked_at' => Carbon::now()->toIso8601String(),
            'summary' => $summary,
            'providers' => array_map(static fn (DomainCheckResult $r): array => $r->toArray(), $results),
        ];
    }

    /**
     * @param  DomainCheckResult[]  $results
     */
    private function aggregateVerdict(array $results): string
    {
        // If every provider was skipped or failed, we can't say anything — return unknown.
        $hasSuccess = false;
        $worst = DomainCheckResult::VERDICT_CLEAN;
        $worstRank = -1;

        foreach ($results as $r) {
            if ($r->status === DomainCheckResult::STATUS_SUCCESS) {
                $hasSuccess = true;
                $rank = self::VERDICT_RANK[$r->verdict] ?? 0;
                if ($rank > $worstRank) {
                    $worstRank = $rank;
                    $worst = $r->verdict;
                }
            }
        }

        if (! $hasSuccess) {
            return DomainCheckResult::VERDICT_UNKNOWN;
        }

        return $worst;
    }

    /**
     * @param  DomainCheckResult[]  $results
     */
    private function summarize(array $results): array
    {
        $isMalware = false;
        $isPhishing = false;
        $isUnwanted = false;
        $totalFlags = 0;
        $providersChecked = 0;
        $providersFlagged = 0;

        foreach ($results as $r) {
            if ($r->status === DomainCheckResult::STATUS_SUCCESS) {
                $providersChecked++;
            }

            if ($r->flagged) {
                $providersFlagged++;
            }

            if ($r->provider === GoogleSafeBrowsingService::NAME) {
                $threats = (array) ($r->details['threat_types'] ?? []);
                if (in_array('MALWARE', $threats, true)) {
                    $isMalware = true;
                }
                if (in_array('SOCIAL_ENGINEERING', $threats, true)) {
                    $isPhishing = true;
                }
                if (in_array('UNWANTED_SOFTWARE', $threats, true)
                    || in_array('POTENTIALLY_HARMFUL_APPLICATION', $threats, true)) {
                    $isUnwanted = true;
                }
                $totalFlags += count($threats);
            }

            if ($r->provider === VirusTotalService::NAME) {
                $totalFlags += (int) ($r->details['malicious'] ?? 0)
                    + (int) ($r->details['suspicious'] ?? 0);
            }

            if ($r->provider === UrlhausService::NAME && $r->flagged) {
                $threats = (array) ($r->details['threats'] ?? []);
                $tags = array_map('strtolower', (array) ($r->details['tags'] ?? []));
                // URLhaus's primary threat label is "malware_download".
                if (in_array('malware_download', $threats, true)) {
                    $isMalware = true;
                }
                // Phishing tags hint at social-engineering campaigns.
                if (in_array('phishing', $tags, true) || in_array('phish', $tags, true)) {
                    $isPhishing = true;
                }
                $totalFlags += (int) ($r->details['url_count'] ?? 0);
            }
        }

        return [
            'total_flags' => $totalFlags,
            'is_malware' => $isMalware,
            'is_phishing' => $isPhishing,
            'is_unwanted' => $isUnwanted,
            'providers_checked' => $providersChecked,
            'providers_flagged' => $providersFlagged,
        ];
    }
}
