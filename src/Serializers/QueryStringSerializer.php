<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Serializers;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Support\Payload;

/**
 * Re-encodes the payload as a URL query string — the shape Kashier and PayTabs
 * sign.
 *
 * The signature field itself (and any parameter the gateway adds after signing)
 * must be excluded, otherwise the string can never reproduce.
 *
 * `dropEmpty` reproduces a bare `array_filter()`, which is what PayTabs' own
 * reference implementation runs before hashing. That drops `""`, `null`,
 * `false`, `0` *and the string `"0"`* — surprising as a general rule, but it is
 * the rule the gateway signs by, so matching it exactly is the point. It
 * applies to top-level keys only, and is ignored in `only` mode, where every
 * requested key must appear so that a removed field changes the string.
 */
final class QueryStringSerializer implements PayloadSerializer
{
    /** @var list<string> */
    private readonly array $exclude;

    /** @var list<string>|null */
    private readonly ?array $only;

    /**
     * @param list<string>      $exclude   keys dropped before encoding
     * @param list<string>|null $only      when set, the exact keys to encode, in this order
     * @param bool              $dropEmpty drop falsy top-level values, PayTabs style; see below
     */
    public function __construct(
        array $exclude = [],
        ?array $only = null,
        private readonly bool $sortKeys = false,
        private readonly string $prefix = '',
        private readonly int $encoding = PHP_QUERY_RFC1738,
        private readonly bool $dropEmpty = false,
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

            if ($this->dropEmpty) {
                $data = array_filter($data);
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
