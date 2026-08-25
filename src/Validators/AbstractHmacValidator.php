<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Validators;

/**
 * Template for every HMAC-signed gateway.
 *
 * The whole flow — locate the claimed signature, rebuild the signing string,
 * digest it, compare in constant time — is inherited from
 * {@see AbstractSignatureValidator}; all this layer decides is that the key
 * enters through HMAC rather than by concatenation.
 *
 * This is the base to reach for unless a gateway's documentation explicitly
 * says otherwise: HMAC is keyed by construction, so it is not vulnerable to the
 * length-extension attack that a plain `hash(secret . message)` invites.
 */
abstract class AbstractHmacValidator extends AbstractSignatureValidator
{
    public function __construct(
        #[\SensitiveParameter] string $secret,
        string $algorithm = 'sha512',
    ) {
        parent::__construct($secret, $algorithm);
    }

    /** @return list<string> */
    protected function availableAlgorithms(): array
    {
        return hash_hmac_algos();
    }

    protected function hash(string $message): string
    {
        return hash_hmac($this->algorithm, $message, $this->secret->reveal());
    }
}
