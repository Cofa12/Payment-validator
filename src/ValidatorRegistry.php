<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator;

use Appssquare\PaymentValidator\Contracts\SignatureValidator;
use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;
use Appssquare\PaymentValidator\Exceptions\UnsupportedGatewayException;
use Appssquare\PaymentValidator\Support\Payload;

/**
 * Name → validator container.
 *
 * Validators may be registered as instances or as closures. Closures are
 * resolved on first use and memoised, so an application can wire up every
 * gateway it supports at boot without constructing keys it may never touch.
 */
final class ValidatorRegistry
{
    /** @var array<string, SignatureValidator> */
    private array $resolved = [];

    /** @var array<string, \Closure(): SignatureValidator> */
    private array $factories = [];

    /** @var array<string, string> alias => canonical name */
    private array $aliases = [];

    /**
     * @param SignatureValidator|callable(): SignatureValidator $validator
     */
    public function register(string $gateway, SignatureValidator|callable $validator): self
    {
        $name = self::normalise($gateway);

        if ($name === '') {
            throw new InvalidConfigurationException('A gateway name cannot be empty.');
        }

        unset($this->resolved[$name], $this->factories[$name]);

        if ($validator instanceof SignatureValidator) {
            $this->resolved[$name] = $validator;
        } else {
            $this->factories[$name] = $validator(...);
        }

        return $this;
    }

    /** Register a second name for an already-registered gateway (`hyper_pay` → `hyperpay`). */
    public function alias(string $alias, string $gateway): self
    {
        $this->aliases[self::normalise($alias)] = self::normalise($gateway);

        return $this;
    }

    public function has(string $gateway): bool
    {
        $name = $this->canonical($gateway);

        return isset($this->resolved[$name]) || isset($this->factories[$name]);
    }

    /** @throws UnsupportedGatewayException */
    public function get(string $gateway): SignatureValidator
    {
        $name = $this->canonical($gateway);

        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        if (! isset($this->factories[$name])) {
            throw UnsupportedGatewayException::forGateway($gateway, $this->names());
        }

        $validator = ($this->factories[$name])();

        if (! $validator instanceof SignatureValidator) {
            throw new InvalidConfigurationException(sprintf(
                'The factory registered for gateway [%s] must return a %s.',
                $gateway,
                SignatureValidator::class,
            ));
        }

        unset($this->factories[$name]);

        return $this->resolved[$name] = $validator;
    }

    public function forget(string $gateway): self
    {
        $name = $this->canonical($gateway);

        unset($this->resolved[$name], $this->factories[$name]);

        foreach ($this->aliases as $alias => $target) {
            if ($target === $name) {
                unset($this->aliases[$alias]);
            }
        }

        return $this;
    }

    /** @return list<string> */
    public function names(): array
    {
        $names = array_merge(array_keys($this->resolved), array_keys($this->factories));

        sort($names);

        return array_values(array_unique($names));
    }

    /**
     * The first registered gateway that recognises this payload.
     *
     * Convenient for a single catch-all webhook endpoint, but resolving every
     * lazy factory as it goes. Prefer routing per gateway when you can.
     */
    public function detect(Payload $payload): ?string
    {
        foreach ($this->names() as $name) {
            if ($this->get($name)->supports($payload)) {
                return $name;
            }
        }

        return null;
    }

    private function canonical(string $gateway): string
    {
        $name = self::normalise($gateway);

        return $this->aliases[$name] ?? $name;
    }

    /** Names are matched loosely so `Paymob`, `paymob` and `PAYMOB` are one gateway. */
    private static function normalise(string $gateway): string
    {
        return str_replace([' ', '-'], '_', strtolower(trim($gateway)));
    }
}
