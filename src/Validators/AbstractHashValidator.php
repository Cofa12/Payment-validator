<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Validators;

use Cofa\PaymentValidator\Support\SecretPlacement;

/**
 * Template for gateways that hash rather than HMAC.
 *
 * A sizeable minority of gateways — Fawry, and most schemes that call the key a
 * "secure key" or "secret hash" — build the signature as
 * `hash(fields… . secureKey)`. That is a weaker construction than HMAC, but it
 * is the gateway's contract, and validating it correctly is strictly better
 * than not validating it at all.
 *
 * Everything except the digest step is inherited from
 * {@see AbstractSignatureValidator}, so a plain-hash gateway costs a field list
 * and a placement, exactly like an HMAC one.
 */
abstract class AbstractHashValidator extends AbstractSignatureValidator
{
    public function __construct(
        #[\SensitiveParameter] string $secret,
        string $algorithm = 'sha256',
        protected readonly SecretPlacement $secretPlacement = SecretPlacement::Append,
    ) {
        parent::__construct($secret, $algorithm);
    }

    public function secretPlacement(): SecretPlacement
    {
        return $this->secretPlacement;
    }

    /**
     * Plain hashes have a wider menu than HMAC — MD5 and CRC variants included,
     * which some older gateways still specify.
     *
     * @return list<string>
     */
    protected function availableAlgorithms(): array
    {
        return hash_algos();
    }

    protected function hash(string $message): string
    {
        return hash($this->algorithm, $this->secretPlacement->apply($message, $this->secret->reveal()));
    }
}
