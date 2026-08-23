<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Contracts;

use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\ValidationResult;

/**
 * The single contract every gateway integration implements.
 *
 * Implementations must never throw for an untrusted payload — a malformed or
 * hostile request is an invalid `ValidationResult`, not an exception. Only
 * programmer/configuration errors (a missing secret, say) may throw.
 */
interface SignatureValidator
{
    /** Machine name this validator is registered under, e.g. `paymob`. */
    public function gateway(): string;

    /**
     * Whether this validator recognises the payload as one of its own.
     *
     * Gateways ship several callback channels with different signing rules
     * (Paymob's transaction webhook vs its card-token webhook, for instance);
     * `supports()` is what lets a composite pick the right one.
     */
    public function supports(Payload $payload): bool;

    public function validate(Payload $payload): ValidationResult;
}
