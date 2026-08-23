<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Contracts;

/**
 * Converts a decoded payload value to its string form for signing.
 *
 * The subtle part of every HMAC integration: `true` must become `"true"` for
 * Paymob but `"1"` elsewhere, and a JSON `null` is usually an empty string.
 * Getting this wrong produces a mismatch that looks like a wrong secret.
 */
interface ValueNormalizer
{
    public function normalize(mixed $value, string $field): string;
}
