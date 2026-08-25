<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\PayTabs;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Serializers\RawBodySerializer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Validators\AbstractHmacValidator;

/**
 * PayTabs PT2 server-to-server callback (IPN).
 *
 * The simplest scheme of any gateway here: HMAC-SHA256 over the *entire raw
 * request body*, with the result in a `signature` header, keyed by the profile
 * Server Key.
 *
 * Because the body is signed byte for byte, it must reach this validator
 * untouched — `Payload::fromJson($request->getContent(), $headers)`, never a
 * re-encoded array. A framework that decodes and re-encodes JSON will reorder
 * keys or restyle numbers and the digest will not reproduce.
 */
final class PayTabsCallbackValidator extends AbstractHmacValidator
{
    public const GATEWAY = 'paytabs';

    private readonly RawBodySerializer $serializer;

    private readonly SignatureLocation $location;

    /**
     * @param string $serverKey      the profile Server Key — the same key used
     *                               for the outbound PT2 API calls
     * @param string $signatureHeader override only if your profile is configured
     *                                to send the signature under another name
     */
    public function __construct(
        #[\SensitiveParameter] string $serverKey,
        string $signatureHeader = 'signature',
    ) {
        $this->serializer = new RawBodySerializer();
        $this->location = SignatureLocation::header($signatureHeader);

        parent::__construct($serverKey, 'sha256');
    }

    public function gateway(): string
    {
        return self::GATEWAY;
    }

    /**
     * A signature header is not enough on its own — without the raw bytes there
     * is nothing to hash, and claiming the payload would only produce a
     * confusing mismatch instead of an honest "no channel matched".
     */
    public function supports(Payload $payload): bool
    {
        $body = $payload->rawBody();

        return parent::supports($payload) && $body !== null && $body !== '';
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        return $this->serializer;
    }

    protected function signatureLocation(): SignatureLocation
    {
        return $this->location;
    }
}
