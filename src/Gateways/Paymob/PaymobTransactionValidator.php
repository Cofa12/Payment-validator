<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Gateways\Paymob;

use Appssquare\PaymentValidator\Contracts\PayloadSerializer;
use Appssquare\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\SignatureLocation;
use Appssquare\PaymentValidator\Validators\AbstractHmacValidator;

/**
 * Paymob `TRANSACTION` processed-callback and response-callback HMAC.
 *
 * Paymob concatenates twenty fields in lexicographical order, with no
 * separator, and HMAC-SHA512s the result with the integration's HMAC secret.
 *
 * The same twenty fields arrive under three different key shapes depending on
 * the channel, which is why every field is declared with aliases:
 *
 *  - processed callback (POST): nested under `obj`, e.g. `obj.source_data.pan`;
 *  - response callback (GET):   flat with literal dots, `source_data.pan`;
 *  - the same GET read through PHP's `$_GET`/`parse_str`, which rewrites dots
 *    in parameter names to underscores: `source_data_pan`.
 */
final class PaymobTransactionValidator extends AbstractHmacValidator
{
    /**
     * Lexicographical order, exactly as Paymob documents it. The order is part
     * of the contract — sorting or reordering this list breaks every signature.
     *
     * @var list<list<string>>
     */
    private const SIGNED_FIELDS = [
        ['obj.amount_cents', 'amount_cents'],
        ['obj.created_at', 'created_at'],
        ['obj.currency', 'currency'],
        ['obj.error_occured', 'error_occured'],
        ['obj.has_parent_transaction', 'has_parent_transaction'],
        ['obj.id', 'id'],
        ['obj.integration_id', 'integration_id'],
        ['obj.is_3d_secure', 'is_3d_secure'],
        ['obj.is_auth', 'is_auth'],
        ['obj.is_capture', 'is_capture'],
        ['obj.is_refunded', 'is_refunded'],
        ['obj.is_standalone_payment', 'is_standalone_payment'],
        ['obj.is_voided', 'is_voided'],
        ['obj.order.id', 'order.id', 'order'],
        ['obj.owner', 'owner'],
        ['obj.pending', 'pending'],
        ['obj.source_data.pan', 'source_data.pan', 'source_data_pan'],
        ['obj.source_data.sub_type', 'source_data.sub_type', 'source_data_sub_type'],
        ['obj.source_data.type', 'source_data.type', 'source_data_type'],
        ['obj.success', 'success'],
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
            return strtoupper($type) === 'TRANSACTION';
        }

        // Response callbacks carry no `type`; recognise them by their shape.
        return $payload->has('obj.amount_cents') || $payload->has('amount_cents');
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
