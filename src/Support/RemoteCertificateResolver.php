<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Support;

use Cofa\PaymentValidator\Contracts\CertificateResolver;
use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;

/**
 * Fetches a signing certificate over HTTPS, from an allow-listed host only.
 *
 * The allow-list is the whole point. PayPal names its certificate in the
 * `PAYPAL-CERT-URL` header of the request you are trying to verify, so an
 * attacker who could choose that URL would simply host their own certificate,
 * sign a forged webhook with the matching private key, and every signature
 * check would pass. Anything not under a configured host is refused before a
 * connection is opened, which also closes the obvious SSRF: without the
 * allow-list, a webhook endpoint becomes a "fetch any URL for me" service
 * pointed at your internal network.
 *
 * Redirects are deliberately not followed — a 302 from an allow-listed host is
 * otherwise a way straight back out of the allow-list.
 *
 * Results are memoised per URL for the lifetime of the resolver, including
 * failures. Certificates rotate rarely; if you keep the resolver alive across
 * requests, give it a lifetime that matches your tolerance for a rotation.
 */
final class RemoteCertificateResolver implements CertificateResolver
{
    /** @var array<string, string|null> */
    private array $cache = [];

    /** @var \Closure(string): ?string */
    private readonly \Closure $fetcher;

    /** @var list<string> */
    private readonly array $allowedHosts;

    /**
     * @param list<string>                  $allowedHosts host names; each also matches its subdomains,
     *                                                    so `paypal.com` covers `api.sandbox.paypal.com`
     * @param (callable(string): ?string)|null $fetcher    replace the transport — inject your HTTP client,
     *                                                     a cache, or a pinned certificate in tests
     */
    public function __construct(
        array $allowedHosts,
        ?callable $fetcher = null,
        private readonly int $timeout = 5,
    ) {
        $hosts = [];

        foreach ($allowedHosts as $host) {
            $host = strtolower(trim(ltrim(trim($host), '.')));

            if ($host !== '') {
                $hosts[] = $host;
            }
        }

        if ($hosts === []) {
            throw new InvalidConfigurationException(
                'A certificate resolver needs at least one allowed host; an empty allow-list would '
                . 'either trust every URL or trust none.',
            );
        }

        $this->allowedHosts = $hosts;
        $this->fetcher = $fetcher === null ? $this->download(...) : $fetcher(...);
    }

    /** @return list<string> */
    public function allowedHosts(): array
    {
        return $this->allowedHosts;
    }

    public function resolve(string $url): ?string
    {
        if (array_key_exists($url, $this->cache)) {
            return $this->cache[$url];
        }

        return $this->cache[$url] = $this->load($url);
    }

    private function load(string $url): ?string
    {
        if (! $this->isAllowed($url)) {
            return null;
        }

        try {
            $pem = ($this->fetcher)($url);
        } catch (\Throwable) {
            // A transport failure is "cannot verify", not a crash in the webhook handler.
            return null;
        }

        if (! is_string($pem) || ! str_contains($pem, '-----BEGIN ')) {
            return null;
        }

        return $pem;
    }

    private function isAllowed(string $url): bool
    {
        $parts = parse_url($url);

        if (! is_array($parts) || ($parts['scheme'] ?? '') !== 'https') {
            return false;
        }

        // `https://api.paypal.com@evil.example/` parses with evil.example as the
        // host, so the check below already catches it; refusing credentials
        // outright keeps the intent obvious.
        if (isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        if (isset($parts['port']) && $parts['port'] !== 443) {
            return false;
        }

        // No explicit empty-host guard: parse_url() fails outright on a hostless
        // URL, and an empty host matches nothing below in any case.
        $host = strtolower($parts['host'] ?? '');

        foreach ($this->allowedHosts as $allowed) {
            if ($host === $allowed || str_ends_with($host, '.' . $allowed)) {
                return true;
            }
        }

        return false;
    }

    private function download(string $url): ?string
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => $this->timeout,
                'follow_location' => 0,
                'header' => "Accept: application/x-pem-file, application/x-x509-ca-cert, */*\r\n",
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
            ],
        ]);

        $pem = @file_get_contents($url, false, $context);

        return $pem === false ? null : $pem;
    }
}
