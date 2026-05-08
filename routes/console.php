<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Pull the domain list from the main app, run all enabled providers, and POST
// verdicts back via webhook. Hourly aligns with the default 1h cache TTL and
// stays well under VirusTotal's 500/day free-tier cap (24 runs × ~20 domains).
// withoutOverlapping prevents a slow run from piling up if the main app is
// briefly unreachable; runInBackground keeps the scheduler tick fast.
Schedule::command('domain-safety:sync')
    ->hourly()
    ->withoutOverlapping(10)
    ->runInBackground()
    ->onOneServer()
    ->appendOutputTo(storage_path('logs/domain-safety-sync.log'));
