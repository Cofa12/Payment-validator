<?php

declare(strict_types=1);

namespace Cofa12\PaymentValidator\Serializers;

use Cofa12\PaymentValidator\Contracts\PayloadSerializer;
use Cofa12\PaymentValidator\Support\Payload;

/**
 * Re-encodes the payload as a URL query string — the shape Kashier signs.
 *
 * The signature field itself (and any parameter the gateway adds after signing)
 * must be excluded, otherwise the string can never reproduce.
 */
final class QueryStringSerializer implements PayloadSerializer
{
    /** @var list<string> */
    private readonly array $exclude;

    /** @var list<string>|null */
    private readonly ?array $only;

    /**
     * @param list<string>      $exclude keys dropped before encoding
     * @param list<string>|null $only    when set, the exact keys to encode, in this order
     */
    public function __construct(
        array $exclude = [],
        ?array $only = null,
        private readonly bool $sortKeys = false,
        private readonly string $prefix = '',
        private readonly int $encoding = PHP_QUERY_RFC1738,
    ) {
        $this->exclude = array_values($exclude);
        $this->only = $only === null ? null : array_values($only);
    }

    public function serialize(Payload $payload): string
    {
        $data = $payload->all();

        if ($this->only !== null) {
            $ordered = [];

            foreach ($this->only as $key) {
                // Absent keys are encoded as empty rather than skipped, so that a
                // removed field changes the string instead of silently shifting it.
                $ordered[$key] = $data[$key] ?? '';
            }

            $data = $ordered;
        } else {
            foreach ($this->exclude as $key) {
                unset($data[$key]);
            }

            if ($this->sortKeys) {
                ksort($data);
            }
        }

        return $this->prefix . http_build_query($this->stringifyBooleans($data), '', '&', $this->encoding);
    }

    /**
     * `http_build_query()` renders booleans as `1`/`0`; gateways that emit JSON
     * booleans sign `true`/`false`. Normalise before encoding.
     *
     * @param  array<array-key, mixed> $data
     * @return array<array-key, mixed>
     */
    private function stringifyBooleans(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_bool($value)) {
                $data[$key] = $value ? 'true' : 'false';
            } elseif (is_array($value)) {
                $data[$key] = $this->stringifyBooleans($value);
            }
        }

        return $data;
    }
}
