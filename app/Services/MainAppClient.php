<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Throwable;

/**
 * Talks to the main app: pulls the domain list and pushes safety webhooks.
 */
final class MainAppClient
{
    public function __construct(
        private readonly bool $enabled,
        private readonly string $baseUrl,
        private readonly string $domainsEndpoint,
        private readonly string $webhookPathTemplate,
        private readonly ?string $webhookSecret,
        private readonly int $timeout,
        private readonly string $userAgent,
    ) {}

    public function isEnabled(): bool
    {
        return $this->enabled && $this->webhookSecret !== null && $this->webhookSecret !== '';
    }

    /**
     * Fetch the domains the main app wants checked.
     *
     * @return array<int, array{id: int, domain_name: string, type?: string, is_safe?: bool, safety_checked_at?: ?string}>
     */
    public function fetchDomains(): array
    {
        $url = rtrim($this->baseUrl, '/').'/'.ltrim($this->domainsEndpoint, '/');

        $response = $this->client()->get($url);

        if (! $response->successful()) {
            throw new RuntimeException(sprintf(
                'Failed to fetch domains from main app: HTTP %d %s',
                $response->status(),
                $response->body(),
            ));
        }

        $payload = $response->json();
        $data = $payload['data'] ?? [];
        if (! is_array($data)) {
            throw new RuntimeException('Unexpected response shape from main app /domains endpoint');
        }

        return array_values($data);
    }

    /**
     * Push a safety verdict for a single domain back to the main app.
     */
    public function notify(string $domain, bool $isSafe, ?string $threatType = null): Response
    {
        $url = rtrim($this->baseUrl, '/').'/'.ltrim(
            str_replace('{domain}', rawurlencode($domain), $this->webhookPathTemplate),
            '/',
        );

        $body = ['is_safe' => $isSafe];
        if ($threatType !== null && $threatType !== '') {
            $body['threat_type'] = mb_substr($threatType, 0, 255);
        }

        try {
            $response = $this->client()
                ->withHeaders(['X-Webhook-Secret' => (string) $this->webhookSecret])
                ->asJson()
                ->post($url, $body);
        } catch (Throwable $e) {
            Log::warning('Domain safety webhook failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }

        if (! $response->successful()) {
            Log::warning('Domain safety webhook returned non-2xx', [
                'domain' => $domain,
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
        }

        return $response;
    }

    private function client()
    {
        return Http::timeout($this->timeout)
            ->withHeaders([
                'Accept' => 'application/json',
                'User-Agent' => $this->userAgent,
            ]);
    }
}
