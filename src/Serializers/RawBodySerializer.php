<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Serializers;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Support\Payload;

/**
 * Signs the untouched request body — the correct choice whenever a gateway
 * HMACs the bytes it sent, because re-encoding a decoded body will not
 * reproduce its key order, spacing or number formatting.
 */
final class RawBodySerializer implements PayloadSerializer
{
    public function __construct(
        private readonly string $prefix = '',
        private readonly string $suffix = '',
    ) {
    }

    public function serialize(Payload $payload): string
    {
        return $this->prefix . ($payload->rawBody() ?? '') . $this->suffix;
    }
}
