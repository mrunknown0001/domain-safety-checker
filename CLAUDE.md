# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

This is an unmodified Laravel 12 skeleton (PHP 8.2+, Vite 7, Tailwind v4). No project-specific domain code has been written yet — only the default `User` model, `welcome` view, and the three baseline migrations (users, cache, jobs). The directory name "domain-safety" reflects intent, not current contents. Treat any new feature as greenfield.

## Commands

- `composer run dev` — runs `php artisan serve`, `queue:listen`, `pail` (logs), and `npm run dev` concurrently. This is the standard local dev entrypoint.
- `composer run test` — clears config then runs `php artisan test` (PHPUnit). Equivalent to `php artisan test`, but matches the project script.
- `php artisan test --filter=TestName` — run a single test by method or class name.
- `php artisan test tests/Feature/ExampleTest.php` — run a single file.
- `vendor/bin/pint` — format PHP (Laravel Pint, the project's only linter/formatter).
- `php artisan migrate` / `php artisan migrate:fresh --seed` — apply or rebuild the schema.
- `npm run build` — production asset build via Vite.

Sail (`compose.yaml`) is wired for MySQL + Redis + Mailpit if the user prefers Docker (`./vendor/bin/sail up -d`), but the default `.env` uses SQLite at `database/database.sqlite`.

## Architecture notes

- **Laravel 12 streamlined skeleton.** There is no `app/Http/Kernel.php`, no `app/Console/Kernel.php`, and no `app/Exceptions/Handler.php`. Middleware, exception handling, and routing are all configured in [bootstrap/app.php](bootstrap/app.php) via the `Application::configure()` fluent API. When adding middleware or exception handlers, edit that file — don't recreate the legacy kernels.
- **Console commands** live as closures in [routes/console.php](routes/console.php) (or as `Command` classes auto-discovered from `app/Console/Commands/` once that directory is created).
- **Test bootstrapping** uses PHPUnit directly (not Pest), with env overrides defined in [phpunit.xml](phpunit.xml) — notably `DB_DATABASE=testing` and `QUEUE_CONNECTION=sync`. Tests extend `Tests\TestCase` from [tests/TestCase.php](tests/TestCase.php).
- **Frontend** is Vite + Tailwind v4 (via `@tailwindcss/vite`), not Tailwind v3 — config lives in CSS (`@import "tailwindcss"`), not `tailwind.config.js`.
