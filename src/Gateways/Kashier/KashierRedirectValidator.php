<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\Kashier;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Serializers\QueryStringSerializer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Validators\AbstractHmacValidator;

/**
 * Kashier browser redirect (`?paymentStatus=SUCCESS&...&signature=...`).
 *
 * Every query parameter except `signature` and `mode` is re-encoded in the order
 * received and HMAC-SHA256'd with the payment API key. `mode` is excluded
 * because Kashier appends it after signing.
 *
 * Parameter order is part of the signed string, so build the payload from the
 * raw query string (`Payload::fromQueryString()`) rather than from a rebuilt
 * associative array whose order you cannot vouch for.
 */
final class KashierRedirectValidator extends AbstractHmacValidator
{
    /** Appended by Kashier after the signature is computed. */
    private const EXCLUDED = ['signature', 'mode'];

    private readonly QueryStringSerializer $serializer;

    /**
     * @param list<string> $additionalExcluded extra parameters your own
     *                                         redirect URL carries (UTM tags,
     *                                         locale, ...) that Kashier did not
     *                                         sign
     */
    public function __construct(#[\SensitiveParameter] string $apiKey, array $additionalExcluded = [])
    {
        $this->serializer = new QueryStringSerializer(
            exclude: array_values(array_unique([...self::EXCLUDED, ...$additionalExcluded])),
        );

        parent::__construct($apiKey, 'sha256');
    }

    public function gateway(): string
    {
        return 'kashier';
    }

    public function supports(Payload $payload): bool
    {
        return parent::supports($payload)
            && ! $payload->has('data.signatureKeys')
            && ! $payload->has('signatureKeys');
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        return $this->serializer;
    }

    protected function signatureLocation(): SignatureLocation
    {
        return SignatureLocation::field('signature');
    }
}
