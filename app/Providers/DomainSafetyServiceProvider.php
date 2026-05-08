<?php

declare(strict_types=1);

namespace App\Providers;

use App\Services\DomainSafetyService;
use App\Services\GoogleSafeBrowsingService;
use App\Services\MainAppClient;
use App\Services\VirusTotalService;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

final class DomainSafetyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(VirusTotalService::class, function (Application $app): VirusTotalService {
            $cfg = $app['config']->get('domain-safety.providers.virustotal', []);
            $thresholds = $app['config']->get('domain-safety.thresholds', []);
            $heuristics = $app['config']->get('domain-safety.heuristics', []);

            return new VirusTotalService(
                enabled: (bool) ($cfg['enabled'] ?? false),
                apiKey: $cfg['api_key'] ?? null,
                baseUrl: (string) ($cfg['base_url'] ?? 'https://www.virustotal.com/api/v3'),
                timeout: (int) ($cfg['timeout'] ?? 10),
                maliciousMin: (int) ($thresholds['virustotal_malicious_min'] ?? 2),
                suspiciousMin: (int) ($thresholds['virustotal_suspicious_min'] ?? 1),
                minHarmlessForClean: (int) ($thresholds['virustotal_min_harmless_for_clean'] ?? 1),
                newDomainDays: (int) ($thresholds['virustotal_new_domain_days'] ?? 90),
                suspiciousTags: (array) ($heuristics['suspicious_vt_tags'] ?? []),
                highRiskTlds: (array) ($heuristics['high_risk_tlds'] ?? []),
            );
        });

        $this->app->singleton(GoogleSafeBrowsingService::class, function (Application $app): GoogleSafeBrowsingService {
            $cfg = $app['config']->get('domain-safety.providers.google_safe_browsing', []);

            return new GoogleSafeBrowsingService(
                enabled: (bool) ($cfg['enabled'] ?? false),
                apiKey: $cfg['api_key'] ?? null,
                baseUrl: (string) ($cfg['base_url'] ?? 'https://safebrowsing.googleapis.com/v4'),
                timeout: (int) ($cfg['timeout'] ?? 10),
                clientId: (string) ($cfg['client_id'] ?? 'laravel-domain-checker'),
                clientVersion: (string) ($cfg['client_version'] ?? '1.0.0'),
            );
        });

        $this->app->singleton(MainAppClient::class, function (Application $app): MainAppClient {
            $cfg = $app['config']->get('domain-safety.main_app', []);

            return new MainAppClient(
                enabled: (bool) ($cfg['enabled'] ?? false),
                baseUrl: (string) ($cfg['base_url'] ?? ''),
                domainsEndpoint: (string) ($cfg['domains_endpoint'] ?? '/api/domains'),
                webhookPathTemplate: (string) ($cfg['webhook_path_template'] ?? '/api/webhooks/domain-safety/{domain}'),
                webhookSecret: $cfg['webhook_secret'] ?? null,
                timeout: (int) ($cfg['timeout'] ?? 15),
                userAgent: (string) ($cfg['user_agent'] ?? 'Mozilla/5.0 (compatible; DomainSafetyChecker/1.0)'),
            );
        });

        $this->app->singleton(DomainSafetyService::class, function (Application $app): DomainSafetyService {
            $cache = $app['config']->get('domain-safety.cache', []);

            return new DomainSafetyService(
                virusTotal: $app->make(VirusTotalService::class),
                googleSafeBrowsing: $app->make(GoogleSafeBrowsingService::class),
                cacheEnabled: (bool) ($cache['enabled'] ?? true),
                cacheTtl: (int) ($cache['ttl'] ?? 3600),
                cachePrefix: (string) ($cache['prefix'] ?? 'domain_safety:'),
            );
        });
    }
}
