<?php

declare(strict_types=1);

namespace App\Services;

use App\DTO\DomainCheckResult;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

final class VirusTotalService
{
    public const NAME = 'virustotal';

    /**
     * @param  string[]  $suspiciousTags
     * @param  string[]  $highRiskTlds
     */
    public function __construct(
        private readonly bool $enabled,
        private readonly ?string $apiKey,
        private readonly string $baseUrl,
        private readonly int $timeout,
        private readonly int $maliciousMin,
        private readonly int $suspiciousMin,
        private readonly int $minHarmlessForClean = 1,
        private readonly int $newDomainDays = 90,
        private readonly array $suspiciousTags = [],
        private readonly array $highRiskTlds = [],
    ) {}

    /**
     * Check a domain against the VirusTotal v3 API.
     */
    public function check(string $domain): DomainCheckResult
    {
        if (! $this->enabled) {
            return DomainCheckResult::skipped(self::NAME, 'Provider disabled');
        }

        if (empty($this->apiKey)) {
            return DomainCheckResult::skipped(self::NAME, 'API key not configured');
        }

        $url = rtrim($this->baseUrl, '/').'/domains/'.rawurlencode($domain);

        try {
            $response = Http::withHeaders(['x-apikey' => $this->apiKey])
                ->timeout($this->timeout)
                ->acceptJson()
                ->get($url);
        } catch (Throwable $e) {
            Log::warning('VirusTotal request failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            return DomainCheckResult::failed(self::NAME, $e->getMessage());
        }

        // 404 = VT has never seen the domain. That's "unknown", not "failed".
        if ($response->status() === 404) {
            return DomainCheckResult::success(
                provider: self::NAME,
                flagged: false,
                verdict: DomainCheckResult::VERDICT_UNKNOWN,
                details: [
                    'message' => 'Domain not found in VirusTotal database',
                    'http_status' => 404,
                ],
            );
        }

        if (! $response->successful()) {
            Log::warning('VirusTotal returned non-2xx', [
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

        $attributes = (array) data_get($response->json(), 'data.attributes', []);
        $stats = (array) ($attributes['last_analysis_stats'] ?? []);
        $results = (array) ($attributes['last_analysis_results'] ?? []);
        $reputation = $attributes['reputation'] ?? null;
        $creationDate = $attributes['creation_date'] ?? null;
        $categories = (array) ($attributes['categories'] ?? []);
        $tags = array_values(array_map('strtolower', (array) ($attributes['tags'] ?? [])));

        $malicious = (int) ($stats['malicious'] ?? 0);
        $suspicious = (int) ($stats['suspicious'] ?? 0);
        $harmless = (int) ($stats['harmless'] ?? 0);
        $undetected = (int) ($stats['undetected'] ?? 0);

        $ageDays = $this->ageInDays($creationDate);
        $isNewDomain = $this->newDomainDays > 0
            && $ageDays !== null
            && $ageDays < $this->newDomainDays;
        $hasNoConfirmation = $harmless < $this->minHarmlessForClean;

        $matchedTags = array_values(array_intersect($tags, array_map('strtolower', $this->suspiciousTags)));
        $tld = $this->extractTld($domain);
        $tldHighRisk = $tld !== null && in_array($tld, $this->highRiskTlds, true);

        $hasEngineDetections = ($malicious + $suspicious) > 0;

        $verdict = match (true) {
            $malicious >= $this->maliciousMin
                => DomainCheckResult::VERDICT_MALICIOUS,
            ($malicious + $suspicious) >= $this->suspiciousMin
                => DomainCheckResult::VERDICT_SUSPICIOUS,
            // Young domain with zero positive confirmations: phishing-pattern.
            $isNewDomain && $hasNoConfirmation
                => DomainCheckResult::VERDICT_SUSPICIOUS,
            // Young domain that engines haven't flagged but carries other red flags
            // (self-signed cert / dynamic-DNS / heavily-abused TLD).
            $isNewDomain && ! $hasEngineDetections && (! empty($matchedTags) || $tldHighRisk)
                => DomainCheckResult::VERDICT_SUSPICIOUS,
            // No engine actively confirmed safe — withhold the "clean" label.
            $hasNoConfirmation
                => DomainCheckResult::VERDICT_UNKNOWN,
            default => DomainCheckResult::VERDICT_CLEAN,
        };

        $flagged = in_array(
            $verdict,
            [DomainCheckResult::VERDICT_MALICIOUS, DomainCheckResult::VERDICT_SUSPICIOUS],
            true,
        );

        $flaggedBy = [];
        foreach ($results as $engine => $result) {
            $category = $result['category'] ?? null;
            if ($category === 'malicious' || $category === 'suspicious') {
                $flaggedBy[] = $engine;
            }
        }

        $reasons = [];
        if ($isNewDomain && $hasNoConfirmation) {
            $reasons[] = "newly registered ({$ageDays} days old) with no engine confirming safety";
        } elseif ($hasNoConfirmation) {
            $reasons[] = 'no engine confirmed the domain as harmless';
        }
        if ($isNewDomain && ! $hasEngineDetections && ! empty($matchedTags)) {
            $reasons[] = sprintf(
                'newly registered (%d days old) with suspicious VT tag(s): %s',
                $ageDays,
                implode(', ', $matchedTags),
            );
        }
        if ($isNewDomain && ! $hasEngineDetections && $tldHighRisk) {
            $reasons[] = sprintf(
                'newly registered (%d days old) on high-abuse TLD .%s',
                $ageDays,
                $tld,
            );
        }

        return DomainCheckResult::success(
            provider: self::NAME,
            flagged: $flagged,
            verdict: $verdict,
            details: [
                'malicious' => $malicious,
                'suspicious' => $suspicious,
                'harmless' => $harmless,
                'undetected' => $undetected,
                'reputation' => $reputation,
                'flagged_by' => $flaggedBy,
                'total_engines' => array_sum($stats),
                'age_days' => $ageDays,
                'creation_date' => $creationDate,
                'categories' => $categories,
                'tags' => $tags,
                'matched_suspicious_tags' => $matchedTags,
                'tld' => $tld,
                'tld_high_risk' => $tldHighRisk,
                'reasons' => $reasons,
            ],
        );
    }

    private function extractTld(string $domain): ?string
    {
        $parts = explode('.', strtolower(trim($domain, '.')));
        if (count($parts) < 2) {
            return null;
        }

        return end($parts) ?: null;
    }

    private function ageInDays(mixed $creationDate): ?int
    {
        if (! is_numeric($creationDate) || (int) $creationDate <= 0) {
            return null;
        }

        $seconds = time() - (int) $creationDate;

        return $seconds < 0 ? 0 : (int) floor($seconds / 86400);
    }
}
