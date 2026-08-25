<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\PayTabs;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Serializers\QueryStringSerializer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Validators\AbstractHmacValidator;

/**
 * PayTabs PT2 browser return — the form POST back to the merchant's return URL.
 *
 * Unlike the callback, this one is signed over the *fields*, following PayTabs'
 * own reference implementation exactly:
 *
 *     unset($post['signature']);
 *     $fields = array_filter($post);   // drop falsy values
 *     ksort($fields);                  // alphabetical
 *     hash_hmac('sha256', http_build_query($fields), $serverKey);
 *
 * The `array_filter()` step is the surprising one — it drops `""`, `"0"` and
 * `0` alike — but PayTabs signs by that rule, so this reproduces it rather than
 * improving on it.
 *
 * The form values arrive as strings, so pass them as received
 * (`Payload::fromArray($_POST)`); re-typing them changes what gets encoded.
 */
final class PayTabsReturnValidator extends AbstractHmacValidator
{
    public const GATEWAY = 'paytabs';

    /** Fields every PT2 return carries, used to tell it from another gateway's redirect. */
    private const IDENTIFYING_FIELDS = ['tranRef', 'tran_ref', 'cartId', 'cart_id'];

    private readonly QueryStringSerializer $serializer;

    /**
     * @param string       $serverKey          the profile Server Key
     * @param list<string> $additionalExcluded parameters your own return URL
     *                                         carries that PayTabs never signed
     */
    public function __construct(
        #[\SensitiveParameter] string $serverKey,
        array $additionalExcluded = [],
    ) {
        $this->serializer = new QueryStringSerializer(
            exclude: array_values(array_unique(['signature', ...$additionalExcluded])),
            sortKeys: true,
            dropEmpty: true,
        );

        parent::__construct($serverKey, 'sha256');
    }

    public function gateway(): string
    {
        return self::GATEWAY;
    }

    /**
     * A bare `signature` field is too weak a fingerprint — Kashier's redirect
     * carries one too — so recognition also requires a field that only a PT2
     * return has. Without this, a single catch-all endpoint would hand PayTabs
     * traffic to whichever gateway happens to be checked first.
     */
    public function supports(Payload $payload): bool
    {
        return parent::supports($payload)
            && $payload->getFirst(self::IDENTIFYING_FIELDS) !== null;
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
