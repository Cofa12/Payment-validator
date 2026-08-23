<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Exceptions;

use InvalidArgumentException;

/** No validator is registered under the requested gateway name. */
final class UnsupportedGatewayException extends InvalidArgumentException implements PaymentValidatorException
{
    /** @param list<string> $registered */
    public static function forGateway(string $gateway, array $registered = []): self
    {
        $message = sprintf('No signature validator is registered for gateway [%s].', $gateway);

        if ($registered !== []) {
            sort($registered);
            $message .= ' Registered gateways: ' . implode(', ', $registered) . '.';
        }

        return new self($message);
    }
}
