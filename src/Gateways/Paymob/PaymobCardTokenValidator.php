<?php

declare(strict_types=1);

namespace Cofa12\PaymentValidator\Gateways\Paymob;

use Cofa12\PaymentValidator\Contracts\PayloadSerializer;
use Cofa12\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa12\PaymentValidator\Support\Payload;
use Cofa12\PaymentValidator\Support\SignatureLocation;
use Cofa12\PaymentValidator\Validators\AbstractHmacValidator;

/**
 * Paymob `TOKEN` callback HMAC — fired when a card is saved for later use.
 *
 * Same recipe as the transaction callback (lexicographical concatenation,
 * HMAC-SHA512, same secret) over a different, much shorter field set. Signing a
 * token callback with the transaction field list silently fails, so the two
 * channels are separate validators rather than one branching class.
 */
final class PaymobCardTokenValidator extends AbstractHmacValidator
{
    /** @var list<list<string>> */
    private const SIGNED_FIELDS = [
        ['obj.card_subtype', 'card_subtype'],
        ['obj.created_at', 'created_at'],
        ['obj.email', 'email'],
        ['obj.id', 'id'],
        ['obj.masked_pan', 'masked_pan'],
        ['obj.merchant_id', 'merchant_id'],
        ['obj.order_id', 'order_id'],
        ['obj.token', 'token'],
    ];

    private readonly ConcatenatedFieldSerializer $serializer;

    public function __construct(#[\SensitiveParameter] string $hmacSecret)
    {
        $this->serializer = new ConcatenatedFieldSerializer(self::SIGNED_FIELDS);

        parent::__construct($hmacSecret, 'sha512');
    }

    public function gateway(): string
    {
        return 'paymob';
    }

    public function supports(Payload $payload): bool
    {
        if (! parent::supports($payload)) {
            return false;
        }

        $type = $payload->get('type');

        if (is_string($type) && $type !== '') {
            return strtoupper($type) === 'TOKEN';
        }

        return ($payload->has('obj.token') || $payload->has('token'))
            && ($payload->has('obj.masked_pan') || $payload->has('masked_pan'));
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        return $this->serializer;
    }

    protected function signatureLocation(): SignatureLocation
    {
        return SignatureLocation::firstOf(
            SignatureLocation::field('hmac'),
            SignatureLocation::field('obj.hmac'),
        );
    }
}
