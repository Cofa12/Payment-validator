<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Validators;

use Appssquare\PaymentValidator\Contracts\PayloadSerializer;
use Appssquare\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\SignatureLocation;

/**
 * A complete HMAC validator with no subclassing required.
 *
 * This is the answer to "how do I add gateway N+1?": most gateways are fully
 * described by a field list, an algorithm and where the signature sits, so they
 * need configuration rather than code.
 *
 *     $registry->register('fawry', new GenericHmacValidator(
 *         gateway: 'fawry',
 *         secret: $secret,
 *         serializer: new ConcatenatedFieldSerializer(['merchantRefNumber', 'orderAmount']),
 *         signatureLocation: SignatureLocation::field('messageSignature'),
 *         algorithm: 'sha256',
 *     ));
 */
class GenericHmacValidator extends AbstractHmacValidator
{
    private readonly string $gateway;

    private readonly PayloadSerializer $serializer;

    private readonly SignatureLocation $signatureLocation;

    public function __construct(
        string $gateway,
        #[\SensitiveParameter] string $secret,
        PayloadSerializer $serializer,
        SignatureLocation $signatureLocation,
        string $algorithm = 'sha256',
    ) {
        $this->gateway = $gateway;
        $this->serializer = $serializer;
        $this->signatureLocation = $signatureLocation;

        parent::__construct($secret, $algorithm);
    }

    /**
     * Shorthand for the overwhelmingly common "concatenate these fields" case.
     *
     * @param list<string|list<string>> $fields
     */
    public static function forFields(
        string $gateway,
        #[\SensitiveParameter] string $secret,
        array $fields,
        string $signatureField = 'signature',
        string $algorithm = 'sha256',
        string $glue = '',
    ): self {
        return new self(
            gateway: $gateway,
            secret: $secret,
            serializer: new ConcatenatedFieldSerializer($fields, $glue),
            signatureLocation: SignatureLocation::field($signatureField),
            algorithm: $algorithm,
        );
    }

    public function gateway(): string
    {
        return $this->gateway;
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        return $this->serializer;
    }

    protected function signatureLocation(): SignatureLocation
    {
        return $this->signatureLocation;
    }
}
