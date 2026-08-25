<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\Fawry;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa\PaymentValidator\Serializers\DecimalAmountNormalizer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SecretPlacement;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Validators\AbstractHashValidator;

/**
 * FawryPay server-to-server notification V2, and the `chargeResponse` the
 * hosted checkout hands back on the return URL.
 *
 * Fawry does not HMAC. It concatenates seven fields, appends the merchant's
 * secure key, and takes a plain SHA-256 of the result — documented as:
 *
 *     SHA-256(fawryRefNumber + merchantRefNum + paymentAmount(two decimals)
 *             + orderAmount(two decimals) + orderStatus + paymentMethod
 *             + paymentRefrenceNumber + secureKey)
 *
 * Both channels carry the same field names, so the same validator answers for
 * the JSON webhook and for the redirect query string; only the `Payload`
 * constructor differs at the call site.
 *
 * Two details account for nearly every mismatch here:
 *
 *  - **The amounts are two-decimal text.** Fawry signs `20.00`; PHP decodes the
 *    JSON number `20.00` to `20.0` and renders it `"20"`. A
 *    {@see DecimalAmountNormalizer} puts the decimals back.
 *  - **`paymentRefrenceNumber` is spelled that way by Fawry**, and is absent
 *    entirely on order-creation notifications, where it signs as empty. Both
 *    the gateway's spelling and the corrected one are accepted.
 */
final class FawryNotificationValidator extends AbstractHashValidator
{
    public const GATEWAY = 'fawry';

    /**
     * Documented order. It is part of the contract — reordering breaks every
     * signature.
     *
     * @var list<string|list<string>>
     */
    private const SIGNED_FIELDS = [
        'fawryRefNumber',
        ['merchantRefNumber', 'merchantRefNum'],
        'paymentAmount',
        'orderAmount',
        'orderStatus',
        'paymentMethod',
        ['paymentRefrenceNumber', 'paymentReferenceNumber'],
    ];

    /** @var list<string> */
    private const AMOUNT_FIELDS = ['paymentAmount', 'orderAmount'];

    private readonly ConcatenatedFieldSerializer $serializer;

    /**
     * @param string $secureKey the account's secure key, from the FawryPay
     *                          merchant portal (the same key used to sign
     *                          outbound charge requests)
     */
    public function __construct(#[\SensitiveParameter] string $secureKey)
    {
        $this->serializer = new ConcatenatedFieldSerializer(
            fields: self::SIGNED_FIELDS,
            normalizer: new DecimalAmountNormalizer(self::AMOUNT_FIELDS),
        );

        parent::__construct($secureKey, 'sha256', SecretPlacement::Append);
    }

    public function gateway(): string
    {
        return self::GATEWAY;
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        return $this->serializer;
    }

    protected function signatureLocation(): SignatureLocation
    {
        return SignatureLocation::field('messageSignature');
    }
}
