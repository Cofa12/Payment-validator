<?php

declare(strict_types=1);

namespace Cofa12\PaymentValidator\Support;

use LogicException;

/**
 * A secret that does not appear in dumps.
 *
 * `#[\SensitiveParameter]` redacts stack traces, but a webhook secret held as
 * an ordinary property is still printed in full by `print_r()`, `var_dump()`,
 * `var_export()` and every framework debug page that renders the service
 * container. Storing the value in a `WeakMap` outside the object keeps it off
 * every one of those paths while it stays reachable through `reveal()`.
 *
 * The entry disappears when the Secret is garbage collected, so nothing leaks
 * or accumulates.
 */
final class Secret
{
    private const REDACTED = '********';

    /** @var \WeakMap<self, string>|null */
    private static ?\WeakMap $vault = null;

    public function __construct(#[\SensitiveParameter] string $value)
    {
        self::vault()[$this] = $value;
    }

    public function reveal(): string
    {
        return self::vault()[$this] ?? '';
    }

    public function isEmpty(): bool
    {
        return $this->reveal() === '';
    }

    public function __toString(): string
    {
        return self::REDACTED;
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['value' => self::REDACTED];
    }

    /**
     * Serialising would either smuggle the secret into a cache file or produce
     * a validator that silently rejects everything. Both are worse than a loud
     * failure, so neither is allowed.
     */
    public function __serialize(): array
    {
        throw new LogicException(
            'A payment gateway secret must not be serialised. Rebuild the validator from configuration instead.',
        );
    }

    public function __unserialize(array $data): void
    {
        throw new LogicException('A payment gateway secret cannot be unserialised.');
    }

    /** @return \WeakMap<self, string> */
    private static function vault(): \WeakMap
    {
        /** @var \WeakMap<self, string> */
        return self::$vault ??= new \WeakMap();
    }
}
