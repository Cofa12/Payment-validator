<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Validators;

use Cofa\PaymentValidator\Contracts\PayloadSerializer;
use Cofa\PaymentValidator\Contracts\SignatureValidator;
use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\Secret;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Support\ValidationResult;

/**
 * Template for every keyed-digest gateway.
 *
 * The flow is always the same — locate the claimed signature, rebuild the
 * signing string, digest it, compare in constant time — so subclasses only
 * declare *what* is signed, *where* the signature lives, and *how* the key
 * enters the digest.
 *
 * That last part is the only reason this class exists separately from
 * {@see AbstractHmacValidator}: most gateways HMAC, but a sizeable minority
 * (Fawry among them) concatenate the key into the message and hash it plainly.
 * Everything else about the two is identical.
 */
abstract class AbstractSignatureValidator implements SignatureValidator
{
    /** Held as a Secret so that dumping a validator cannot leak the key. */
    protected readonly Secret $secret;

    public function __construct(
        #[\SensitiveParameter] string $secret,
        protected readonly string $algorithm,
    ) {
        $secret = trim($secret);

        if ($secret === '') {
            throw InvalidConfigurationException::emptySecret($this->gateway());
        }

        if (! in_array($this->algorithm, $this->availableAlgorithms(), true)) {
            throw InvalidConfigurationException::unsupportedAlgorithm(
                $this->algorithm,
                $this->availableAlgorithms(),
            );
        }

        $this->secret = new Secret($secret);
    }

    /** The string this gateway signs, for the payload at hand. */
    abstract protected function serializer(Payload $payload): PayloadSerializer;

    abstract protected function signatureLocation(): SignatureLocation;

    /**
     * The digest this validator computes, key included.
     *
     * @return list<string> the algorithms the digest supports
     */
    abstract protected function availableAlgorithms(): array;

    abstract protected function hash(string $message): string;

    public function supports(Payload $payload): bool
    {
        return $this->signatureLocation()->locate($payload) !== null;
    }

    public function validate(Payload $payload): ValidationResult
    {
        $provided = $this->signatureLocation()->locate($payload);

        if ($provided === null) {
            return ValidationResult::invalid($this->gateway(), sprintf(
                'No signature found at [%s].',
                $this->signatureLocation()->description(),
            ));
        }

        $serializer = $this->serializer($payload);
        $expected = $this->hash($serializer->serialize($payload));

        if (! hash_equals($expected, $this->canonicalise($provided))) {
            return ValidationResult::invalid(
                $this->gateway(),
                'The provided signature does not match the payload.',
                $this->mismatchContext($serializer, $payload),
            );
        }

        return ValidationResult::valid($this->gateway(), ['algorithm' => $this->algorithm]);
    }

    /**
     * Compute the signature for a payload.
     *
     * Public because it is the only sane way to debug a mismatch, and because
     * the same recipe is often needed to *sign* outbound requests. Never log
     * the return value of this method for an untrusted payload.
     */
    public function sign(Payload $payload): string
    {
        return $this->hash($this->signingString($payload));
    }

    /**
     * The serialized payload, before the key is folded in — the first thing to
     * inspect when a signature will not match.
     *
     * For schemes that concatenate the key into the message, the key is added
     * inside {@see hash()} and deliberately does not appear here, so this stays
     * safe to log and to show a support engineer.
     */
    public function signingString(Payload $payload): string
    {
        return $this->serializer($payload)->serialize($payload);
    }

    /**
     * Gateways are inconsistent about hex casing and stray whitespace, and
     * neither carries meaning. Normalising the *claimed* value is safe; the
     * comparison itself stays constant-time.
     */
    protected function canonicalise(string $signature): string
    {
        return strtolower(trim($signature));
    }

    /**
     * Non-secret diagnostics only. Missing fields are by far the most common
     * cause of a mismatch that is not simply a wrong key.
     *
     * @return array<string, mixed>
     */
    protected function mismatchContext(PayloadSerializer $serializer, Payload $payload): array
    {
        $context = ['algorithm' => $this->algorithm];

        if ($serializer instanceof ConcatenatedFieldSerializer) {
            $missing = $serializer->missingFields($payload);

            if ($missing !== []) {
                $context['missing_fields'] = $missing;
            }
        }

        return $context;
    }
}
