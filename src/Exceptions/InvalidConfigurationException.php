<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Exceptions;

use InvalidArgumentException;

/** A validator was built with unusable settings (empty secret, malformed key, ...). */
final class InvalidConfigurationException extends InvalidArgumentException implements PaymentValidatorException
{
    public static function emptySecret(string $gateway): self
    {
        return new self(sprintf('The [%s] validator requires a non-empty secret.', $gateway));
    }

    /** @param list<string>|null $available the algorithms the digest in question accepts */
    public static function unsupportedAlgorithm(string $algorithm, ?array $available = null): self
    {
        return new self(sprintf(
            'Hash algorithm [%s] is not available on this system. Available: %s.',
            $algorithm,
            implode(', ', $available ?? hash_hmac_algos()),
        ));
    }

    public static function missingFields(string $gateway): self
    {
        return new self(sprintf('The [%s] validator requires at least one field to sign.', $gateway));
    }
}
