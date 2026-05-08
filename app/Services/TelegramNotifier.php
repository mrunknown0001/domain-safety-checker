<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Sends Telegram messages when a domain check returns a flagged verdict.
 *
 * Deduplicates notifications via a separate cache key so the same flagged
 * domain doesn't spam every time the result cache expires.
 */
final class TelegramNotifier
{
    private const API_BASE = 'https://api.telegram.org';

    public function __construct(
        private readonly bool $enabled,
        private readonly ?string $botToken,
        private readonly ?string $chatId,
        private readonly int $dedupTtl,
        private readonly int $timeout,
        private readonly string $cachePrefix,
    ) {}

    public function isEnabled(): bool
    {
        return $this->enabled
            && $this->botToken !== null && $this->botToken !== ''
            && $this->chatId !== null && $this->chatId !== '';
    }

    /**
     * Notify if the check result represents a flagged (unsafe) domain.
     * Idempotent within `dedupTtl` — repeated calls for the same domain are dropped.
     */
    public function notifyFlagged(array $check): void
    {
        if (! $this->isEnabled()) {
            return;
        }

        if (($check['safe'] ?? true) === true) {
            return;
        }

        $domain = (string) ($check['domain'] ?? '');
        if ($domain === '') {
            return;
        }

        $dedupKey = $this->cachePrefix.$domain;
        if (Cache::has($dedupKey)) {
            return;
        }

        try {
            $response = Http::timeout($this->timeout)
                ->asJson()
                ->post(self::API_BASE.'/bot'.$this->botToken.'/sendMessage', [
                    'chat_id' => $this->chatId,
                    'text' => $this->formatMessage($check),
                    'parse_mode' => 'HTML',
                    'disable_web_page_preview' => true,
                ]);

            if (! $response->successful()) {
                Log::warning('Telegram notification non-2xx', [
                    'domain' => $domain,
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);

                return;
            }

            // Only set dedup AFTER a successful send, so transient failures retry.
            if ($this->dedupTtl > 0) {
                Cache::put($dedupKey, true, $this->dedupTtl);
            }
        } catch (Throwable $e) {
            Log::warning('Telegram notification failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
        }
    }

    private function formatMessage(array $check): string
    {
        $domain = $this->escape((string) ($check['domain'] ?? ''));
        $verdict = (string) ($check['verdict'] ?? 'unknown');
        $emoji = $verdict === 'malicious' ? '🚨' : '⚠️';

        $summary = (array) ($check['summary'] ?? []);
        $threatLabels = [];
        if (! empty($summary['is_malware'])) {
            $threatLabels[] = 'malware';
        }
        if (! empty($summary['is_phishing'])) {
            $threatLabels[] = 'phishing';
        }
        if (! empty($summary['is_unwanted'])) {
            $threatLabels[] = 'unwanted software';
        }

        $lines = [
            "{$emoji} <b>Domain flagged: ".strtoupper($verdict).'</b>',
            '',
            "<b>Domain:</b> <code>{$domain}</code>",
        ];

        if ($threatLabels !== []) {
            $lines[] = '<b>Threats:</b> '.$this->escape(implode(', ', $threatLabels));
        }

        $lines[] = '';
        $lines[] = '<b>Provider results:</b>';

        foreach ((array) ($check['providers'] ?? []) as $p) {
            $lines = array_merge($lines, $this->renderProvider($p));
        }

        // VT heuristic reasons (e.g. "newly registered on high-abuse TLD")
        $reasons = (array) data_get($check, 'providers.0.details.reasons', []);
        if ($reasons !== []) {
            $lines[] = '';
            $lines[] = '<b>Reasons:</b>';
            foreach ($reasons as $r) {
                $lines[] = '• '.$this->escape((string) $r);
            }
        }

        $lines[] = '';
        $lines[] = '<i>Checked at '.$this->escape((string) ($check['checked_at'] ?? '')).'</i>';

        return implode("\n", $lines);
    }

    /**
     * @return string[]
     */
    private function renderProvider(array $p): array
    {
        $name = (string) ($p['provider'] ?? '?');
        $verdict = (string) ($p['verdict'] ?? '?');
        $status = (string) ($p['status'] ?? '?');
        $flagged = (bool) ($p['flagged'] ?? false);
        $marker = $flagged ? '🔴' : ($status === 'success' ? '🟢' : '⚪');

        $line = "{$marker} <b>".$this->escape($name).'</b>: '.$this->escape($verdict);
        $out = [$line];

        if (! $flagged) {
            return $out;
        }

        $details = $this->detailsAsArray($p['details'] ?? []);

        if ($name === 'virustotal') {
            $engines = (array) ($details['flagged_by'] ?? []);
            if ($engines !== []) {
                $shown = array_slice($engines, 0, 5);
                $more = count($engines) > 5 ? sprintf(' (+%d more)', count($engines) - 5) : '';
                $out[] = '   ↳ engines: '.$this->escape(implode(', ', $shown).$more);
            }
            $stats = sprintf(
                'malicious=%d, suspicious=%d, harmless=%d',
                (int) ($details['malicious'] ?? 0),
                (int) ($details['suspicious'] ?? 0),
                (int) ($details['harmless'] ?? 0),
            );
            $out[] = '   ↳ '.$stats;
        }

        if ($name === 'google_safe_browsing') {
            $threats = (array) ($details['threat_types'] ?? []);
            if ($threats !== []) {
                $out[] = '   ↳ threat types: '.$this->escape(implode(', ', $threats));
            }
        }

        if ($name === 'urlhaus') {
            $threats = (array) ($details['threats'] ?? []);
            $tags = (array) ($details['tags'] ?? []);
            if ($threats !== []) {
                $out[] = '   ↳ threat: '.$this->escape(implode(', ', $threats));
            }
            if ($tags !== []) {
                $out[] = '   ↳ tags: '.$this->escape(implode(', ', $tags));
            }
            if (! empty($details['urlhaus_reference'])) {
                $ref = $this->escape((string) $details['urlhaus_reference']);
                $out[] = "   ↳ <a href=\"{$ref}\">URLhaus report</a>";
            }
        }

        return $out;
    }

    private function detailsAsArray(mixed $details): array
    {
        if (is_array($details)) {
            return $details;
        }
        if (is_object($details)) {
            return get_object_vars($details);
        }

        return [];
    }

    private function escape(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}
