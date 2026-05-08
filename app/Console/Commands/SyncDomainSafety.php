<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\DTO\DomainCheckResult;
use App\Services\DomainSafetyService;
use App\Services\MainAppClient;
use Illuminate\Console\Command;
use Throwable;

final class SyncDomainSafety extends Command
{
    protected $signature = 'domain-safety:sync
        {--dry-run : Run checks but do not POST webhooks}
        {--domain= : Only check this single domain (skips fetching the list)}
        {--interval= : Override DOMAIN_SAFETY_SYNC_INTERVAL (seconds between cache-miss checks)}';

    protected $description = 'Pull domains from the main app, run safety checks, and POST verdicts to the webhook.';

    public function handle(DomainSafetyService $safety, MainAppClient $main): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $singleDomain = $this->option('domain');

        if (! $dryRun && ! $main->isEnabled()) {
            $this->error('Main app integration is disabled or webhook secret is missing. Use --dry-run to skip the webhook.');

            return self::FAILURE;
        }

        $domains = $singleDomain !== null
            ? [['domain_name' => (string) $singleDomain]]
            : $this->fetchDomains($main);

        if ($domains === null) {
            return self::FAILURE;
        }

        if ($domains === []) {
            $this->info('No domains to check.');

            return self::SUCCESS;
        }

        $notifyOnUnknown = (bool) config('domain-safety.main_app.notify_on_unknown', false);
        $intervalSeconds = $this->option('interval') !== null
            ? max(0, (int) $this->option('interval'))
            : (int) config('domain-safety.sync.interval_seconds', 15);

        $sent = 0;
        $skipped = 0;
        $failed = 0;
        $lastWasCacheMiss = false;

        foreach ($domains as $i => $row) {
            $name = (string) ($row['domain_name'] ?? '');
            if ($name === '') {
                continue;
            }

            // Throttle BEFORE the next upstream call (not after the last one),
            // and only when the previous iteration actually hit the providers.
            if ($i > 0 && $lastWasCacheMiss && $intervalSeconds > 0) {
                $this->line(sprintf('  …sleeping %ds (rate-limit throttle)', $intervalSeconds));
                sleep($intervalSeconds);
            }

            $cached = $safety->isCached($name);
            $lastWasCacheMiss = ! $cached;

            $result = $safety->check($name);
            $verdict = $result['verdict'];
            $payload = $this->derivePayload($result);

            $line = sprintf(
                '[%s] %s → verdict=%s, is_safe=%s, threat_type=%s',
                $verdict === DomainCheckResult::VERDICT_CLEAN ? 'OK' : strtoupper($verdict),
                $name,
                $verdict,
                $payload['is_safe'] ? 'true' : 'false',
                $payload['threat_type'] ?? '—',
            );

            if ($verdict === DomainCheckResult::VERDICT_UNKNOWN && ! $notifyOnUnknown) {
                $this->warn($line.' (skipped — verdict unknown)');
                $skipped++;
                continue;
            }

            if ($dryRun) {
                $this->line($line.' (dry-run)');
                continue;
            }

            try {
                $response = $main->notify($name, $payload['is_safe'], $payload['threat_type']);
                if ($response->successful()) {
                    $this->info($line.' ✓');
                    $sent++;
                } else {
                    $this->error($line.' ✗ webhook HTTP '.$response->status().': '.$response->body());
                    $failed++;
                }
            } catch (Throwable $e) {
                $this->error($line.' ✗ webhook error: '.$e->getMessage());
                $failed++;
            }
        }

        $this->newLine();
        $this->line(sprintf('Done. sent=%d skipped=%d failed=%d', $sent, $skipped, $failed));

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @return array{is_safe: bool, threat_type: ?string}
     */
    private function derivePayload(array $checkResult): array
    {
        $verdict = (string) $checkResult['verdict'];
        $summary = (array) ($checkResult['summary'] ?? []);
        $providers = (array) ($checkResult['providers'] ?? []);

        $isSafe = ! in_array(
            $verdict,
            [DomainCheckResult::VERDICT_MALICIOUS, DomainCheckResult::VERDICT_SUSPICIOUS],
            true,
        );

        if ($isSafe) {
            return ['is_safe' => true, 'threat_type' => null];
        }

        // Prefer GSB's specific threat label; fall back to a derived label.
        $threatType = match (true) {
            ! empty($summary['is_phishing']) => 'SOCIAL_ENGINEERING',
            ! empty($summary['is_malware']) => 'MALWARE',
            ! empty($summary['is_unwanted']) => 'UNWANTED_SOFTWARE',
            default => $this->fallbackThreatType($verdict, $providers),
        };

        return ['is_safe' => false, 'threat_type' => $threatType];
    }

    private function fallbackThreatType(string $verdict, array $providers): string
    {
        // Try to surface the VT engines that flagged it; otherwise just the verdict.
        foreach ($providers as $p) {
            if (($p['provider'] ?? null) === 'virustotal' && ! empty($p['details']->flagged_by ?? null)) {
                $names = (array) $p['details']->flagged_by;
                $label = 'VT_FLAGGED:'.implode(',', array_slice($names, 0, 3));

                return mb_substr($label, 0, 255);
            }
        }

        return strtoupper($verdict);
    }

    /**
     * @return array<int, array<string, mixed>>|null
     */
    private function fetchDomains(MainAppClient $main): ?array
    {
        try {
            $domains = $main->fetchDomains();
        } catch (Throwable $e) {
            $this->error('Failed to fetch domains: '.$e->getMessage());

            return null;
        }

        $this->info(sprintf('Fetched %d domain(s) from main app.', count($domains)));

        return $domains;
    }
}
