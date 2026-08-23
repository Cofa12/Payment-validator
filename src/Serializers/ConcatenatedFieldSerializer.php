<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Serializers;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Contracts\ValueNormalizer;
use Cofa\PaymentValidator\Support\Payload;

/**
 * "Take these fields, in this order, glued together" — the shape used by
 * Paymob, EasyKash and most HMAC gateways.
 *
 * A field entry is either a key (dot notation allowed) or a list of aliases,
 * the first present one winning. Aliases matter because gateways rename fields
 * between channels: Paymob's order id is `order.id` on the webhook and plain
 * `order` on the redirect.
 */
final class ConcatenatedFieldSerializer implements PayloadSerializer
{
    private readonly ValueNormalizer $normalizer;

    /** @var list<string|list<string>> */
    private readonly array $fields;

    /**
     * @param list<string|list<string>> $fields
     */
    public function __construct(
        array $fields,
        private readonly string $glue = '',
        ?ValueNormalizer $normalizer = null,
        private readonly bool $caseInsensitive = false,
    ) {
        $this->fields = array_values($fields);
        $this->normalizer = $normalizer ?? new DefaultValueNormalizer();
    }

    public function serialize(Payload $payload): string
    {
        $parts = [];

        foreach ($this->fields as $field) {
            [, $value] = $this->resolve($payload, $field);

            $parts[] = $this->normalizer->normalize($value, $this->label($field));
        }

        return implode($this->glue, $parts);
    }

    /**
     * Fields the payload does not carry at all.
     *
     * A missing field is not automatically fatal — plenty of gateways omit
     * optional fields and sign them as empty — but reporting it turns an opaque
     * "signature mismatch" into an actionable message.
     *
     * @return list<string>
     */
    public function missingFields(Payload $payload): array
    {
        $missing = [];

        foreach ($this->fields as $field) {
            [$found] = $this->resolve($payload, $field);

            if (! $found) {
                $missing[] = $this->label($field);
            }
        }

        return $missing;
    }

    /** @return list<string|list<string>> */
    public function fields(): array
    {
        return $this->fields;
    }

    /**
     * @param string|list<string> $field
     *
     * @return array{0: bool, 1: mixed}
     */
    private function resolve(Payload $payload, string|array $field): array
    {
        foreach ((array) $field as $candidate) {
            if ($payload->has($candidate)) {
                return [true, $payload->get($candidate)];
            }

            if ($this->caseInsensitive) {
                $value = $payload->getInsensitive($candidate, $sentinel = new \stdClass());

                if ($value !== $sentinel) {
                    return [true, $value];
                }
            }
        }

        return [false, null];
    }

    /** @param string|list<string> $field */
    private function label(string|array $field): string
    {
        return is_array($field) ? implode('|', $field) : $field;
    }
}
