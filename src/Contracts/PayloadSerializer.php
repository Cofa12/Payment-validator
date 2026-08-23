<?php

declare(strict_types=1);

namespace Cofa12\PaymentValidator\Contracts;

use Cofa12\PaymentValidator\Support\Payload;

/**
 * Turns a payload into the exact string a gateway signs.
 *
 * This is where gateways actually differ. Almost every HMAC gateway is
 * "concatenate these fields in this order, hash with this algorithm"; isolating
 * the first half here means a new gateway is usually a serializer choice plus a
 * few constructor arguments, not a new algorithm.
 */
interface PayloadSerializer
{
    public function serialize(Payload $payload): string;
}
