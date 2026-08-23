<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Serializers;

use Cofa\PaymentValidator\Contracts\ValueNormalizer;

/**
 * The conventions shared by every HMAC gateway we have met so far.
 *
 * Booleans are the trap: gateways sign the JSON spelling (`true`), while PHP's
 * string cast yields `"1"`/`""`. Swap in your own normalizer if a gateway
 * disagrees — that is exactly why this is an injected contract.
 */
final class DefaultValueNormalizer implements ValueNormalizer
{
    public function __construct(
        private readonly string $trueValue = 'true',
        private readonly string $falseValue = 'false',
        private readonly string $nullValue = '',
    ) {
    }

    /** `1`/`0` booleans, used by gateways that sign the form-encoded shape. */
    public static function numericBooleans(): self
    {
        return new self('1', '0');
    }

    public function normalize(mixed $value, string $field): string
    {
        return match (true) {
            $value === null => $this->nullValue,
            is_bool($value) => $value ? $this->trueValue : $this->falseValue,
            is_string($value) => $value,
            is_int($value) => (string) $value,
            is_float($value) => $this->normalizeFloat($value),
            is_array($value) => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '',
            $value instanceof \Stringable => (string) $value,
            default => '',
        };
    }

    /**
     * PHP's default `serialize_precision = -1` already round-trips floats
     * losslessly (`10.5` => "10.5", `100.0` => "100"). Trailing-zero formats
     * such as "100.00" cannot be recovered once JSON is decoded — sign those
     * gateways from the raw body, or inject a normalizer that re-formats them.
     */
    private function normalizeFloat(float $value): string
    {
        if (is_nan($value) || is_infinite($value)) {
            return '';
        }

        return (string) $value;
    }
}
