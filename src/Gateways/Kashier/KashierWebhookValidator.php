<?php

declare(strict_types=1);

namespace Cofa12\PaymentValidator\Gateways\Kashier;

use Cofa12\PaymentValidator\Contracts\PayloadSerializer;
use Cofa12\PaymentValidator\Support\Payload;
use Cofa12\PaymentValidator\Support\SignatureLocation;
use Cofa12\PaymentValidator\Support\ValidationResult;
use Cofa12\PaymentValidator\Validators\AbstractHmacValidator;

/**
 * Kashier server-to-server webhook.
 *
 * The fields named by `data.signatureKeys` are URL-encoded in that order and
 * HMAC-SHA256'd with the merchant's payment API key; the result is compared
 * against `data.kashierSignature`.
 */
final class KashierWebhookValidator extends AbstractHmacValidator
{
    private readonly KashierSignatureKeysSerializer $serializer;

    public function __construct(#[\SensitiveParameter] string $apiKey)
    {
        $this->serializer = new KashierSignatureKeysSerializer();

        parent::__construct($apiKey, 'sha256');
    }

    public function gateway(): string
    {
        return 'kashier';
    }

    public function supports(Payload $payload): bool
    {
        return parent::supports($payload)
            && ($payload->has('data.signatureKeys') || $payload->has('signatureKeys'));
    }

    public function validate(Payload $payload): ValidationResult
    {
        if ($this->serializer->signatureKeys($payload) === []) {
            return ValidationResult::invalid(
                $this->gateway(),
                'The webhook does not declare `data.signatureKeys`, so the signed string cannot be rebuilt.',
            );
        }

        return parent::validate($payload);
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        return $this->serializer;
    }

    protected function signatureLocation(): SignatureLocation
    {
        return SignatureLocation::firstOf(
            SignatureLocation::field('data.kashierSignature'),
            SignatureLocation::field('kashierSignature'),
            SignatureLocation::header('x-kashier-signature'),
        );
    }

    /** @return array<string, mixed> */
    protected function mismatchContext(PayloadSerializer $serializer, Payload $payload): array
    {
        return [
            'algorithm' => $this->algorithm,
            'signature_keys' => $this->serializer->signatureKeys($payload),
        ];
    }
}
