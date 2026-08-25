<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Serializers;

use Cofa\PaymentValidator\Contracts\ValueNormalizer;

/**
 * Re-imposes a fixed number of decimals on money fields.
 *
 * This is the fix for the single most common "the signature is wrong but the
 * key is right" bug. A gateway sends `"paymentAmount": 20.00` and signs the
 * text `20.00`; PHP decodes that JSON number to the float `20.0` and renders it
 * back as `"20"`, and the digest never reproduces. Fawry's notification signs
 * two amounts this way and documents the format explicitly ("in two decimal
 * format 10.00").
 *
 * Only the named fields are touched, and only when their value is numeric — a
 * missing amount stays an empty string rather than becoming `0.00`, because
 * those are different signing strings and quietly substituting one for the
 * other would hide a malformed callback.
 *
 * Field names are matched against each alias of a signed field, and against the
 * last segment of a dotted path, so `['amount']` covers a field declared as
 * `['obj.amount', 'amount']`.
 */
final class DecimalAmountNormalizer implements ValueNormalizer
{
    /** @var array<string, true> */
    private readonly array $fields;

    private readonly ValueNormalizer $inner;

    /**
     * @param list<string>   $fields   the field names carrying money
     * @param int            $decimals places to pad or round to
     * @param ValueNormalizer|null $inner handles every other field
     */
    public function __construct(
        array $fields,
        private readonly int $decimals = 2,
        ?ValueNormalizer $inner = null,
    ) {
        $this->fields = array_fill_keys(array_values($fields), true);
        $this->inner = $inner ?? new DefaultValueNormalizer();
    }

    public function normalize(mixed $value, string $field): string
    {
        if (! is_numeric($value) || ! $this->isAmount($field)) {
            return $this->inner->normalize($value, $field);
        }

        return number_format((float) $value, $this->decimals, '.', '');
    }

    /** `ConcatenatedFieldSerializer` labels an aliased field `a|b`, so split before matching. */
    private function isAmount(string $field): bool
    {
        foreach (explode('|', $field) as $candidate) {
            if (isset($this->fields[$candidate])) {
                return true;
            }

            $leaf = strrchr($candidate, '.');

            if ($leaf !== false && isset($this->fields[substr($leaf, 1)])) {
                return true;
            }
        }

        return false;
    }
}
