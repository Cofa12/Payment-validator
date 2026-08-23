<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Support;

/**
 * Where in the request the gateway put its signature.
 *
 * Four idioms cover every gateway we have integrated: a body/query field, a
 * header, a header with a scheme prefix (`sha256=abc...`), or "whichever of
 * these is present". Anything stranger goes through `custom()`.
 */
final class SignatureLocation
{
    /** @var \Closure(Payload): ?string */
    private readonly \Closure $resolver;

    /** @param callable(Payload): ?string $resolver */
    private function __construct(callable $resolver, private readonly string $description)
    {
        $this->resolver = $resolver(...);
    }

    /** A key in the decoded body or query string (dot notation allowed). */
    public static function field(string $key): self
    {
        return new self(
            static function (Payload $payload) use ($key): ?string {
                $value = $payload->get($key);

                return is_scalar($value) ? (string) $value : null;
            },
            "field:{$key}",
        );
    }

    /** A request header, matched case-insensitively. */
    public static function header(string $name, string $stripPrefix = ''): self
    {
        return new self(
            static function (Payload $payload) use ($name, $stripPrefix): ?string {
                $value = $payload->header($name);

                if ($value === null) {
                    return null;
                }

                $value = trim($value);

                if ($stripPrefix !== '' && str_starts_with($value, $stripPrefix)) {
                    $value = substr($value, strlen($stripPrefix));
                }

                return $value;
            },
            "header:{$name}",
        );
    }

    /** The first location that yields a non-empty value. */
    public static function firstOf(self ...$locations): self
    {
        return new self(
            static function (Payload $payload) use ($locations): ?string {
                foreach ($locations as $location) {
                    $value = $location->locate($payload);

                    if ($value !== null && $value !== '') {
                        return $value;
                    }
                }

                return null;
            },
            implode('|', array_map(static fn (self $l): string => $l->description(), $locations)),
        );
    }

    /** @param callable(Payload): ?string $resolver */
    public static function custom(callable $resolver, string $description = 'custom'): self
    {
        return new self($resolver, $description);
    }

    public function locate(Payload $payload): ?string
    {
        $value = ($this->resolver)($payload);

        return $value === null || $value === '' ? null : $value;
    }

    public function description(): string
    {
        return $this->description;
    }
}
