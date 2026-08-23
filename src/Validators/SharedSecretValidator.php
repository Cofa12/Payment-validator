<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Validators;

use Cofa\PaymentValidator\Contracts\SignatureValidator;
use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\Secret;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Support\ValidationResult;

/**
 * Constant-time comparison of a static shared secret presented in a header or
 * field — the "webhook token" pattern several gateways use instead of, or
 * alongside, a signature.
 *
 * Weaker than an HMAC: it proves the caller knows the secret but says nothing
 * about the body, so a leaked token lets anyone post arbitrary payloads. Treat
 * it as a second factor next to a real signature where one exists, and always
 * behind TLS.
 */
final class SharedSecretValidator implements SignatureValidator
{
    private readonly Secret $secret;

    public function __construct(
        private readonly string $gateway,
        #[\SensitiveParameter] string $secret,
        private readonly SignatureLocation $location,
    ) {
        $secret = trim($secret);

        if ($secret === '') {
            throw InvalidConfigurationException::emptySecret($gateway);
        }

        $this->secret = new Secret($secret);
    }

    public function gateway(): string
    {
        return $this->gateway;
    }

    public function supports(Payload $payload): bool
    {
        return $this->location->locate($payload) !== null;
    }

    public function validate(Payload $payload): ValidationResult
    {
        $provided = $this->location->locate($payload);

        if ($provided === null) {
            return ValidationResult::invalid($this->gateway, sprintf(
                'No shared secret found at [%s].',
                $this->location->description(),
            ));
        }

        if (! hash_equals($this->secret->reveal(), trim($provided))) {
            return ValidationResult::invalid($this->gateway, 'The presented shared secret is incorrect.');
        }

        return ValidationResult::valid($this->gateway, ['method' => 'shared_secret']);
    }
}
