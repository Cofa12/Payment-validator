<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Support;

use Cofa\PaymentValidator\Exceptions\InvalidPayloadException;

/**
 * Immutable representation of an inbound gateway callback.
 *
 * A callback can reach the application in three shapes, and gateways mix them
 * freely, so all three are carried side by side:
 *
 *  - `data`    the decoded body or query parameters (dot notation supported);
 *  - `headers` the request headers (looked up case-insensitively);
 *  - `rawBody` the untouched request body, required by gateways that sign or
 *              encrypt the exact bytes they sent (HyperPay, for example).
 */
final class Payload
{
    /** @var array<string, mixed> */
    private array $data;

    /** @var array<string, string> normalised (lower-cased) header name => value */
    private array $headers;

    private ?string $rawBody;

    /**
     * @param array<array-key, mixed>  $data
     * @param array<string, mixed>     $headers
     */
    public function __construct(array $data = [], array $headers = [], ?string $rawBody = null)
    {
        $this->data = $data;
        $this->headers = self::normaliseHeaders($headers);
        $this->rawBody = $rawBody;
    }

    /**
     * @param array<array-key, mixed> $data
     * @param array<string, mixed>    $headers
     */
    public static function fromArray(array $data, array $headers = [], ?string $rawBody = null): self
    {
        return new self($data, $headers, $rawBody);
    }

    /**
     * Build from a raw JSON body. The raw body is preserved verbatim.
     *
     * @param array<string, mixed> $headers
     *
     * @throws InvalidPayloadException when the body is not a JSON object/array
     */
    public static function fromJson(string $json, array $headers = []): self
    {
        try {
            $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidPayloadException('The payload is not valid JSON: ' . $e->getMessage(), 0, $e);
        }

        if (! is_array($decoded)) {
            throw new InvalidPayloadException('The JSON payload must decode to an object or an array.');
        }

        return new self($decoded, $headers, $json);
    }

    /**
     * Build from a URL query string (redirect/response callbacks).
     *
     * @param array<string, mixed> $headers
     */
    public static function fromQueryString(string $queryString, array $headers = []): self
    {
        $queryString = ltrim($queryString, '?');

        parse_str($queryString, $parsed);

        return new self($parsed, $headers, $queryString);
    }

    /**
     * Build from a raw body that may or may not be JSON. Non-JSON bodies still
     * produce a usable payload (with empty `data`) so that gateways which sign
     * the raw bytes keep working.
     *
     * @param array<string, mixed> $headers
     */
    public static function fromRawBody(string $body, array $headers = []): self
    {
        $decoded = json_decode($body, true);

        return new self(is_array($decoded) ? $decoded : [], $headers, $body);
    }

    /**
     * Read a value using dot notation (`obj.source_data.pan`).
     *
     * Gateways are inconsistent: some send nested objects, some send literally
     * dotted keys. Both are resolved here, flat key first.
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if (array_key_exists($key, $this->data)) {
            return $this->data[$key];
        }

        $value = $this->data;

        foreach (explode('.', $key) as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return $default;
            }

            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * Resolve the first key that is present, which lets a validator accept the
     * same field under the several names a gateway uses across its channels
     * (e.g. `order.id` on the webhook vs `order` on the redirect).
     *
     * @param list<string> $keys
     */
    public function getFirst(array $keys, mixed $default = null): mixed
    {
        foreach ($keys as $key) {
            if ($this->has($key)) {
                return $this->get($key);
            }
        }

        return $default;
    }

    /**
     * Case-insensitive key lookup, for gateways that vary the casing of their
     * field names between documentation and production traffic.
     */
    public function getInsensitive(string $key, mixed $default = null): mixed
    {
        if ($this->has($key)) {
            return $this->get($key);
        }

        $needle = strtolower($key);

        foreach ($this->data as $actual => $value) {
            if (is_string($actual) && strtolower($actual) === $needle) {
                return $value;
            }
        }

        return $default;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $sentinel = new \stdClass()) !== $sentinel;
    }

    /** @return array<array-key, mixed> */
    public function all(): array
    {
        return $this->data;
    }

    public function header(string $name, ?string $default = null): ?string
    {
        $value = $this->headers[strtolower($name)] ?? $default;

        return $value === null ? null : (string) $value;
    }

    /** @return array<string, string> */
    public function headers(): array
    {
        return $this->headers;
    }

    public function rawBody(): ?string
    {
        return $this->rawBody;
    }

    /**
     * The sub-tree at `$key` as a new payload, keeping headers and raw body.
     * Used to focus on wrappers such as Paymob's `obj` or Kashier's `data`.
     */
    public function scope(string $key): self
    {
        $scoped = $this->get($key);

        return new self(is_array($scoped) ? $scoped : [], $this->headers, $this->rawBody);
    }

    /** Copy without the given top-level keys (signature fields, mode flags, ...). */
    public function without(string ...$keys): self
    {
        $data = $this->data;

        foreach ($keys as $key) {
            unset($data[$key]);
        }

        return new self($data, $this->headers, $this->rawBody);
    }

    /** Copy keeping only the given top-level keys, in the order requested. */
    public function only(string ...$keys): self
    {
        $data = [];

        foreach ($keys as $key) {
            if (array_key_exists($key, $this->data)) {
                $data[$key] = $this->data[$key];
            }
        }

        return new self($data, $this->headers, $this->rawBody);
    }

    /** @param array<array-key, mixed> $data */
    public function withData(array $data): self
    {
        return new self($data, $this->headers, $this->rawBody);
    }

    /** @param array<string, mixed> $headers */
    public function withHeaders(array $headers): self
    {
        return new self($this->data, array_merge($this->headers, self::normaliseHeaders($headers)), $this->rawBody);
    }

    public function isEmpty(): bool
    {
        return $this->data === [] && ($this->rawBody === null || $this->rawBody === '');
    }

    /**
     * @param array<string, mixed> $headers
     *
     * @return array<string, string>
     */
    private static function normaliseHeaders(array $headers): array
    {
        $normalised = [];

        foreach ($headers as $name => $value) {
            if (is_array($value)) {
                $value = $value[0] ?? '';
            }

            // PSR-7 / $_SERVER style names both collapse to the same key.
            $name = str_replace('_', '-', strtolower((string) $name));
            $name = preg_replace('/^http-/', '', $name) ?? $name;

            $normalised[$name] = is_scalar($value) ? (string) $value : '';
        }

        return $normalised;
    }
}
