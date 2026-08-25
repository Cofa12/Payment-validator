<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Contracts;

/**
 * Turns a certificate URL into PEM text.
 *
 * Gateways that sign with a public key (PayPal) name the certificate in a
 * header of the very request being verified — which means the URL is
 * attacker-controlled until proven otherwise. An implementation is therefore
 * a security boundary, not a download helper: it decides which hosts may be
 * contacted at all.
 *
 * Returning `null` means "not resolvable, do not trust this request". It must
 * never throw for a hostile URL; that would turn a forged webhook into a 500.
 */
interface CertificateResolver
{
    /** @return string|null PEM-encoded certificate or public key, or null when the URL is not trusted or not reachable */
    public function resolve(string $url): ?string;
}
