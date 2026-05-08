<?php

declare(strict_types=1);

namespace App\DTO;

use JsonSerializable;

/**
 * Shared response shape for a single provider's domain check.
 */
final class DomainCheckResult implements JsonSerializable
{
    public const STATUS_SUCCESS = 'success';
    public const STATUS_FAILED = 'failed';
    public const STATUS_SKIPPED = 'skipped';

    public const VERDICT_CLEAN = 'clean';
    public const VERDICT_SUSPICIOUS = 'suspicious';
    public const VERDICT_MALICIOUS = 'malicious';
    public const VERDICT_UNKNOWN = 'unknown';

    public function __construct(
        public readonly string $provider,
        public readonly string $status,
        public readonly bool $flagged,
        public readonly string $verdict,
        public readonly array $details = [],
        public readonly ?string $error = null,
    ) {}

    public static function success(
        string $provider,
        bool $flagged,
        string $verdict,
        array $details = [],
    ): self {
        return new self(
            provider: $provider,
            status: self::STATUS_SUCCESS,
            flagged: $flagged,
            verdict: $verdict,
            details: $details,
        );
    }

    public static function skipped(string $provider, string $reason): self
    {
        return new self(
            provider: $provider,
            status: self::STATUS_SKIPPED,
            flagged: false,
            verdict: self::VERDICT_UNKNOWN,
            error: $reason,
        );
    }

    public static function failed(string $provider, string $error, array $details = []): self
    {
        return new self(
            provider: $provider,
            status: self::STATUS_FAILED,
            flagged: false,
            verdict: self::VERDICT_UNKNOWN,
            details: $details,
            error: $error,
        );
    }

    public function toArray(): array
    {
        return [
            'provider' => $this->provider,
            'status' => $this->status,
            'flagged' => $this->flagged,
            'verdict' => $this->verdict,
            'details' => (object) $this->details,
            'error' => $this->error,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
