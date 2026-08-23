<?php

declare(strict_types=1);

namespace Cofa12\PaymentValidator;

use Cofa12\PaymentValidator\Contracts\SignatureValidator;
use Cofa12\PaymentValidator\Exceptions\SignatureMismatchException;
use Cofa12\PaymentValidator\Exceptions\UnsupportedGatewayException;
use Cofa12\PaymentValidator\Support\Payload;
use Cofa12\PaymentValidator\Support\ValidationResult;

/**
 * The façade an application talks to.
 *
 *     $validator = PaymentValidator::fromConfig([
 *         'paymob'   => ['hmac' => $_ENV['PAYMOB_HMAC']],
 *         'kashier'  => ['api_key' => $_ENV['KASHIER_API_KEY']],
 *         'easykash' => ['secret' => $_ENV['EASYKASH_SECRET']],
 *         'hyperpay' => ['decryption_key' => $_ENV['HYPERPAY_WEBHOOK_KEY']],
 *     ]);
 *
 *     $result = $validator->validate('paymob', Payload::fromJson($rawBody, $headers));
 *
 *     if ($result->isInvalid()) {
 *         abort(400, $result->reason());
 *     }
 */
final class PaymentValidator
{
    public function __construct(private readonly ValidatorRegistry $registry = new ValidatorRegistry())
    {
    }

    /**
     * Build from a `gateway => settings` map. Every gateway is registered
     * lazily, so a malformed or unused entry only raises when it is used.
     *
     * @param array<string, array<string, mixed>> $config
     */
    public static function fromConfig(array $config, ?GatewayFactory $factory = null): self
    {
        $factory ??= new GatewayFactory();
        $validator = new self();

        foreach ($config as $gateway => $settings) {
            if (! is_array($settings)) {
                continue;
            }

            $validator->registry->register(
                $gateway,
                static fn (): SignatureValidator => $factory->make($gateway, $settings),
            );
        }

        return $validator;
    }

    public function registry(): ValidatorRegistry
    {
        return $this->registry;
    }

    /**
     * Add or replace a gateway at runtime.
     *
     * @param SignatureValidator|callable(): SignatureValidator $validator
     */
    public function register(string $gateway, SignatureValidator|callable $validator): self
    {
        $this->registry->register($gateway, $validator);

        return $this;
    }

    public function has(string $gateway): bool
    {
        return $this->registry->has($gateway);
    }

    /** @return list<string> */
    public function gateways(): array
    {
        return $this->registry->names();
    }

    /** @throws UnsupportedGatewayException */
    public function validator(string $gateway): SignatureValidator
    {
        return $this->registry->get($gateway);
    }

    /**
     * @param Payload|array<array-key, mixed>|string $payload a Payload, a decoded
     *                                                        array, or a raw body;
     *                                                        redirect query strings
     *                                                        need Payload::fromQueryString()
     * @param array<string, mixed>                   $headers ignored when $payload is a Payload
     *
     * @throws UnsupportedGatewayException when the gateway is not registered
     */
    public function validate(string $gateway, Payload|array|string $payload, array $headers = []): ValidationResult
    {
        return $this->registry->get($gateway)->validate(self::toPayload($payload, $headers));
    }

    /**
     * @param Payload|array<array-key, mixed>|string $payload
     * @param array<string, mixed>                   $headers
     */
    public function isValid(string $gateway, Payload|array|string $payload, array $headers = []): bool
    {
        return $this->validate($gateway, $payload, $headers)->isValid();
    }

    /**
     * @param Payload|array<array-key, mixed>|string $payload
     * @param array<string, mixed>                   $headers
     *
     * @throws SignatureMismatchException when the payload does not verify
     */
    public function assertValid(string $gateway, Payload|array|string $payload, array $headers = []): ValidationResult
    {
        return $this->validate($gateway, $payload, $headers)->throwIfInvalid();
    }

    /**
     * Identify which registered gateway a payload belongs to, for a single
     * shared webhook endpoint. Returns null when nothing recognises it.
     *
     * @param Payload|array<array-key, mixed>|string $payload
     * @param array<string, mixed>                   $headers
     */
    public function detect(Payload|array|string $payload, array $headers = []): ?string
    {
        return $this->registry->detect(self::toPayload($payload, $headers));
    }

    /**
     * @param Payload|array<array-key, mixed>|string $payload
     * @param array<string, mixed>                   $headers
     */
    private static function toPayload(Payload|array|string $payload, array $headers): Payload
    {
        return match (true) {
            $payload instanceof Payload => $payload,
            is_array($payload) => Payload::fromArray($payload, $headers),
            default => Payload::fromRawBody($payload, $headers),
        };
    }
}
