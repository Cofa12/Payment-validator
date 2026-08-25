<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Validators;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SecretPlacement;
use Cofa\PaymentValidator\Support\SignatureLocation;

/**
 * A complete plain-hash validator with no subclassing required — the
 * {@see GenericHmacValidator} of gateways that concatenate the key instead of
 * HMACing it.
 *
 * This is what makes a legacy scheme a configuration entry rather than a fork.
 * Fawry's V1 notification, for instance, is `md5(secureKey . amount . …)`:
 *
 *     $registry->register('fawry-v1', GenericHashValidator::forFields(
 *         gateway: 'fawry-v1',
 *         secret: $secureKey,
 *         fields: ['amount', 'fawryRefNumber', 'merchantRefNumber', 'orderStatus'],
 *         signatureField: 'messageSignature',
 *         algorithm: 'md5',
 *         secretPlacement: SecretPlacement::Prepend,
 *     ));
 */
class GenericHashValidator extends AbstractHashValidator
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
        SecretPlacement $secretPlacement = SecretPlacement::Append,
    ) {
        $this->gateway = $gateway;
        $this->serializer = $serializer;
        $this->signatureLocation = $signatureLocation;

        parent::__construct($secret, $algorithm, $secretPlacement);
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
        SecretPlacement $secretPlacement = SecretPlacement::Append,
    ): self {
        return new self(
            gateway: $gateway,
            secret: $secret,
            serializer: new ConcatenatedFieldSerializer($fields, $glue),
            signatureLocation: SignatureLocation::field($signatureField),
            algorithm: $algorithm,
            secretPlacement: $secretPlacement,
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
