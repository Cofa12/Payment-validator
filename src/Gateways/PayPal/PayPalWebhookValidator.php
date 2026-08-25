<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\PayPal;

use Cofa\PaymentValidator\Contracts\CertificateResolver;
use Cofa\PaymentValidator\Contracts\SignatureValidator;
use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\RemoteCertificateResolver;
use Cofa\PaymentValidator\Support\ValidationResult;

/**
 * PayPal REST webhook signature, verified locally.
 *
 * PayPal signs asymmetrically rather than with a shared secret: there is no key
 * to keep, only a public certificate to check against. The message it signs is
 * four pipe-joined parts —
 *
 *     PAYPAL-TRANSMISSION-ID | PAYPAL-TRANSMISSION-TIME | webhookId | crc32(rawBody)
 *
 * — and `PAYPAL-TRANSMISSION-SIG` is that string signed with RSA-SHA256 under
 * the certificate at `PAYPAL-CERT-URL`.
 *
 * Two consequences worth stating plainly:
 *
 *  - **The raw body must survive intact.** The checksum is `crc32()` over the
 *    exact bytes PayPal sent. Decoding the JSON and re-encoding it renders
 *    numbers and unicode differently and the checksum will not reproduce.
 *  - **The certificate URL arrives inside the request being verified**, so it
 *    is untrusted input. It is resolved through a {@see CertificateResolver}
 *    that refuses any host outside the allow-list; see
 *    {@see RemoteCertificateResolver} for why that check is load-bearing rather
 *    than defensive habit.
 *
 * Verifying here rather than through PayPal's `verify-webhook-signature` API is
 * the approach PayPal itself recommends: no extra round trip, no API
 * credentials on the webhook path, and no outage in your handler when that
 * endpoint is slow.
 */
final class PayPalWebhookValidator implements SignatureValidator
{
    public const GATEWAY = 'paypal';

    /** Hosts PayPal serves its webhook certificates from, live and sandbox alike. */
    public const CERTIFICATE_HOSTS = ['paypal.com'];

    /** PayPal has only ever sent `SHA256withRSA`; the rest are here so a rotation is not an outage. */
    private const AUTH_ALGORITHMS = [
        'SHA256WITHRSA' => OPENSSL_ALGO_SHA256,
        'SHA512WITHRSA' => OPENSSL_ALGO_SHA512,
    ];

    private const REQUIRED_HEADERS = [
        'paypal-transmission-id',
        'paypal-transmission-time',
        'paypal-transmission-sig',
        'paypal-cert-url',
    ];

    private readonly CertificateResolver $certificates;

    /**
     * @param string $webhookId the ID of the webhook subscription this endpoint
     *                          serves, from the PayPal developer dashboard. Not
     *                          a secret — it is an identifier that binds the
     *                          signature to one subscription — but it must be
     *                          the ID of *this* endpoint, or nothing verifies.
     */
    public function __construct(
        private readonly string $webhookId,
        ?CertificateResolver $certificates = null,
    ) {
        if (trim($this->webhookId) === '') {
            throw new InvalidConfigurationException(
                'The [paypal] validator requires the webhook ID of the subscription this endpoint serves.',
            );
        }

        $this->certificates = $certificates ?? new RemoteCertificateResolver(self::CERTIFICATE_HOSTS);
    }

    public function gateway(): string
    {
        return self::GATEWAY;
    }

    public function supports(Payload $payload): bool
    {
        foreach (self::REQUIRED_HEADERS as $header) {
            if (($payload->header($header) ?? '') === '') {
                return false;
            }
        }

        return true;
    }

    public function validate(Payload $payload): ValidationResult
    {
        $missing = [];

        foreach (self::REQUIRED_HEADERS as $header) {
            if (($payload->header($header) ?? '') === '') {
                $missing[] = $header;
            }
        }

        if ($missing !== []) {
            return ValidationResult::invalid(
                self::GATEWAY,
                'Missing required header(s): ' . implode(', ', $missing) . '.',
            );
        }

        $body = $payload->rawBody();

        if ($body === null || $body === '') {
            return ValidationResult::invalid(
                self::GATEWAY,
                'The request body is empty; the signature covers a checksum of the raw body.',
            );
        }

        $authAlgo = trim($payload->header('paypal-auth-algo') ?? 'SHA256withRSA');
        $algorithm = self::AUTH_ALGORITHMS[strtoupper($authAlgo)] ?? null;

        if ($algorithm === null) {
            return ValidationResult::invalid(
                self::GATEWAY,
                sprintf('Unsupported signature algorithm [%s].', $authAlgo),
                ['supported_algorithms' => array_keys(self::AUTH_ALGORITHMS)],
            );
        }

        $signature = base64_decode(trim((string) $payload->header('paypal-transmission-sig')), true);

        if ($signature === false || $signature === '') {
            return ValidationResult::invalid(self::GATEWAY, 'The transmission signature is not valid base64.');
        }

        $certUrl = (string) $payload->header('paypal-cert-url');
        $certificate = $this->certificates->resolve($certUrl);

        if ($certificate === null) {
            return ValidationResult::invalid(
                self::GATEWAY,
                'The signing certificate could not be retrieved, or its URL is not an allowed PayPal host.',
                ['cert_url' => $certUrl],
            );
        }

        $publicKey = openssl_pkey_get_public($certificate);

        if ($publicKey === false) {
            return ValidationResult::invalid(
                self::GATEWAY,
                'The signing certificate could not be parsed.',
                ['cert_url' => $certUrl],
            );
        }

        $verified = openssl_verify($this->expectedMessage($payload, $body), $signature, $publicKey, $algorithm);

        // openssl_verify() returns 1, 0 or -1; anything but 1 is a failure, and
        // -1 (an OpenSSL error) must not be mistaken for a pass.
        if ($verified !== 1) {
            return ValidationResult::invalid(
                self::GATEWAY,
                'The transmission signature does not match the payload.',
                ['algorithm' => $authAlgo, 'cert_url' => $certUrl],
            );
        }

        return ValidationResult::valid(self::GATEWAY, [
            'algorithm' => $authAlgo,
            'cert_url' => $certUrl,
            'transmission_id' => $payload->header('paypal-transmission-id'),
        ]);
    }

    /**
     * The exact string PayPal signed. Useful when a signature will not verify
     * and you need to see which part differs; it holds no secret.
     */
    public function signingString(Payload $payload): string
    {
        return $this->expectedMessage($payload, $payload->rawBody() ?? '');
    }

    private function expectedMessage(Payload $payload, string $body): string
    {
        return sprintf(
            '%s|%s|%s|%s',
            $payload->header('paypal-transmission-id'),
            $payload->header('paypal-transmission-time'),
            $this->webhookId,
            // crc32() is signed on 32-bit builds; PayPal specifies the unsigned
            // base-10 value, so format rather than cast.
            sprintf('%u', crc32($body)),
        );
    }
}
