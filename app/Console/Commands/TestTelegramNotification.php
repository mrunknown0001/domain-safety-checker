<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\TelegramNotifier;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;

final class TestTelegramNotification extends Command
{
    protected $signature = 'domain-safety:test-telegram {--bypass-dedup : Clear the dedup key for example.test before sending}';

    protected $description = 'Send a fake "domain flagged" alert to verify the Telegram bot setup.';

    public function handle(TelegramNotifier $notifier): int
    {
        if (! $notifier->isEnabled()) {
            $this->error('Telegram is disabled or missing TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID. Check .env and run config:clear.');

            return self::FAILURE;
        }

        if ($this->option('bypass-dedup')) {
            Cache::forget(config('domain-safety.telegram.cache_prefix', 'telegram_notified:').'example.test');
        }

        $fakeCheck = [
            'domain' => 'example.test',
            'input' => 'example.test',
            'safe' => false,
            'verdict' => 'malicious',
            'checked_at' => Carbon::now()->toIso8601String(),
            'summary' => [
                'total_flags' => 7,
                'is_malware' => true,
                'is_phishing' => false,
                'is_unwanted' => false,
                'providers_checked' => 3,
                'providers_flagged' => 2,
            ],
            'providers' => [
                [
                    'provider' => 'virustotal',
                    'status' => 'success',
                    'flagged' => true,
                    'verdict' => 'malicious',
                    'details' => (object) [
                        'malicious' => 5,
                        'suspicious' => 0,
                        'harmless' => 30,
                        'flagged_by' => ['Webroot', 'CyRadar', 'ADMINUSLabs'],
                        'reasons' => ['test alert from domain-safety:test-telegram'],
                    ],
                    'error' => null,
                ],
                [
                    'provider' => 'google_safe_browsing',
                    'status' => 'success',
                    'flagged' => false,
                    'verdict' => 'clean',
                    'details' => (object) ['matches' => [], 'threat_types' => []],
                    'error' => null,
                ],
                [
                    'provider' => 'urlhaus',
                    'status' => 'success',
                    'flagged' => true,
                    'verdict' => 'malicious',
                    'details' => (object) [
                        'threats' => ['malware_download'],
                        'tags' => ['ClearFake', 'TestAlert'],
                        'urlhaus_reference' => 'https://urlhaus.abuse.ch/host/example.test/',
                    ],
                    'error' => null,
                ],
            ],
        ];

        $notifier->notifyFlagged($fakeCheck);

        $this->info('Test alert sent. Check your Telegram chat.');
        $this->line('(If nothing arrives, check storage/logs/laravel.log for "Telegram notification" warnings.)');

        return self::SUCCESS;
    }
}
