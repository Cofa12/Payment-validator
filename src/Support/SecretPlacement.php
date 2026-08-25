<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Support;

/**
 * Where the secret sits in a plain-hash signing string.
 *
 * Gateways that hash rather than HMAC fold the key into the message itself.
 * Fawry appends it, several others prepend it, and the difference is not
 * cosmetic — a prepended key makes the digest vulnerable to a length-extension
 * attack, which is exactly why HMAC exists.
 */
enum SecretPlacement
{
    /** `hash(message . secret)` — Fawry's server notification. */
    case Append;

    /**
     * `hash(secret . message)`.
     *
     * Length-extension territory on Merkle–Damgård digests (MD5, SHA-1,
     * SHA-256): anyone holding one valid signature can produce another for a
     * *longer* message without knowing the key. Whether that is exploitable
     * depends on how the gateway parses the extended string, but prefer a
     * gateway channel that HMACs whenever one is offered.
     */
    case Prepend;

    public function apply(string $message, #[\SensitiveParameter] string $secret): string
    {
        return match ($this) {
            self::Append => $message . $secret,
            self::Prepend => $secret . $message,
        };
    }
}
