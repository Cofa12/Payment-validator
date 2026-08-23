<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Support;

use Appssquare\PaymentValidator\Exceptions\SignatureMismatchException;

/**
 * Outcome of a single validation attempt.
 *
 * Deliberately never carries the expected signature: results are routinely
 * logged, and logging the value an attacker needs to forge defeats the point of
 * signing at all. `context` is for non-secret diagnostics (which fields were
 * used, which channel matched, the decrypted webhook body, ...).
 */
final class ValidationResult
{
    /**
     * @param array<string, mixed> $context
     */
    private function __construct(
        private readonly bool $valid,
        private readonly string $gateway,
        private readonly ?string $reason,
        private readonly array $context,
    ) {
    }

    /** @param array<string, mixed> $context */
    public static function valid(string $gateway, array $context = []): self
    {
        return new self(true, $gateway, null, $context);
    }

    /** @param array<string, mixed> $context */
    public static function invalid(string $gateway, string $reason, array $context = []): self
    {
        return new self(false, $gateway, $reason, $context);
    }

    public function isValid(): bool
    {
        return $this->valid;
    }

    public function isInvalid(): bool
    {
        return ! $this->valid;
    }

    public function gateway(): string
    {
        return $this->gateway;
    }

    /** Human-readable explanation, present only when the result is invalid. */
    public function reason(): ?string
    {
        return $this->reason;
    }

    /** @return array<string, mixed> */
    public function context(): array
    {
        return $this->context;
    }

    public function contextValue(string $key, mixed $default = null): mixed
    {
        return $this->context[$key] ?? $default;
    }

    /** @param array<string, mixed> $context */
    public function withContext(array $context): self
    {
        return new self($this->valid, $this->gateway, $this->reason, array_merge($this->context, $context));
    }

    /**
     * Fluent guard for callers that would rather branch on exceptions.
     *
     * @throws SignatureMismatchException
     */
    public function throwIfInvalid(): self
    {
        if (! $this->valid) {
            throw new SignatureMismatchException(
                sprintf('[%s] signature validation failed: %s', $this->gateway, $this->reason ?? 'unknown reason'),
                $this,
            );
        }

        return $this;
    }

    /** @return array{valid: bool, gateway: string, reason: string|null, context: array<string, mixed>} */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'gateway' => $this->gateway,
            'reason' => $this->reason,
            'context' => $this->context,
        ];
    }
}
