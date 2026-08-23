<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Gateways\Kashier;

use Appssquare\PaymentValidator\Contracts\PayloadSerializer;
use Appssquare\PaymentValidator\Serializers\DefaultValueNormalizer;
use Appssquare\PaymentValidator\Support\Payload;

/**
 * Kashier webhooks are self-describing: the body carries `data.signatureKeys`,
 * the ordered list of field names that went into the signature. Rebuilding from
 * that list — rather than a hard-coded one — means Kashier can add fields to the
 * webhook without breaking verification.
 */
final class KashierSignatureKeysSerializer implements PayloadSerializer
{
    private readonly DefaultValueNormalizer $normalizer;

    public function __construct(
        private readonly string $dataKey = 'data',
        private readonly string $keysField = 'signatureKeys',
    ) {
        $this->normalizer = new DefaultValueNormalizer();
    }

    public function serialize(Payload $payload): string
    {
        $data = $payload->scope($this->dataKey);
        $keys = $this->signatureKeys($payload);

        $params = [];

        foreach ($keys as $key) {
            $params[$key] = $this->normalizer->normalize($data->get($key), $key);
        }

        return http_build_query($params);
    }

    /**
     * The declared key order, or an empty list when the webhook does not
     * advertise one (in which case the signature can never match, and the
     * validator reports it as such).
     *
     * @return list<string>
     */
    public function signatureKeys(Payload $payload): array
    {
        $keys = $payload->getFirst([
            $this->dataKey . '.' . $this->keysField,
            $this->keysField,
        ]);

        if (! is_array($keys)) {
            return [];
        }

        return array_values(array_filter(
            array_map(static fn (mixed $key): string => is_scalar($key) ? (string) $key : '', $keys),
            static fn (string $key): bool => $key !== '',
        ));
    }
}
