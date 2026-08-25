<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Fixtures;

use OpenSSLAsymmetricKey;

/**
 * Signs PayPal webhooks the way PayPal's transmitter does: an RSA key pair, a
 * self-signed certificate to publish it under, and the four-part pipe-joined
 * message signed with RSA-SHA256.
 *
 * The key pair is generated once per process — RSA generation is slow enough
 * that doing it per test noticeably drags the suite.
 */
final class PayPalFixture
{
    public const WEBHOOK_ID = '8JS53894R2224664N';

    public const CERT_URL = 'https://api.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-1d93a270';

    private static ?OpenSSLAsymmetricKey $privateKey = null;

    private static ?string $certificate = null;

    private static ?OpenSSLAsymmetricKey $otherPrivateKey = null;

    private static ?string $otherCertificate = null;

    /** @return array<string, mixed> */
    public static function event(): array
    {
        return [
            'id' => 'WH-2WR32451HC0233532-67976317FL4543714',
            'event_version' => '1.0',
            'create_time' => '2024-05-01T10:15:30.000Z',
            'resource_type' => 'capture',
            'event_type' => 'PAYMENT.CAPTURE.COMPLETED',
            'summary' => 'Payment completed for EGP 250.0 EGP',
            'resource' => [
                'id' => '8MC585209K746392H',
                'status' => 'COMPLETED',
                'amount' => ['currency_code' => 'EGP', 'value' => '250.00'],
                'custom_id' => 'ORD-2024-001',
            ],
            'links' => [
                [
                    'href' => 'https://api.paypal.com/v2/payments/captures/8MC585209K746392H',
                    'rel' => 'self',
                    'method' => 'GET',
                ],
            ],
        ];
    }

    /** PEM certificate carrying the public half of the signing key. */
    public static function certificate(): string
    {
        self::generate();

        return (string) self::$certificate;
    }

    /** A certificate from an unrelated key pair — a valid certificate that must still fail. */
    public static function foreignCertificate(): string
    {
        self::generate();

        return (string) self::$otherCertificate;
    }

    /**
     * A delivered webhook: raw body plus the headers PayPal transmits with it.
     *
     * @param array<string, mixed>|null $event
     *
     * @return array{body: string, headers: array<string, string>}
     */
    public static function webhook(
        ?array $event = null,
        string $webhookId = self::WEBHOOK_ID,
        string $certUrl = self::CERT_URL,
        bool $foreignKey = false,
    ): array {
        // PayPal does not escape the slashes in the URLs it sends, so neither
        // does this — the difference is exactly what a body that has been
        // decoded and re-encoded loses.
        $body = json_encode($event ?? self::event(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $transmissionId = 'e8a3b1c0-0f6c-11ef-9c2d-9f1a2b3c4d5e';
        $transmissionTime = '2024-05-01T10:15:31Z';

        return [
            'body' => $body,
            'headers' => [
                'Content-Type' => 'application/json',
                'PAYPAL-TRANSMISSION-ID' => $transmissionId,
                'PAYPAL-TRANSMISSION-TIME' => $transmissionTime,
                'PAYPAL-CERT-URL' => $certUrl,
                'PAYPAL-AUTH-ALGO' => 'SHA256withRSA',
                'PAYPAL-TRANSMISSION-SIG' => self::sign(
                    self::message($transmissionId, $transmissionTime, $webhookId, $body),
                    $foreignKey,
                ),
            ],
        ];
    }

    /**
     * Reference implementation of the documented signed message:
     * `transmissionId|transmissionTime|webhookId|crc32(rawBody)`.
     */
    public static function message(
        string $transmissionId,
        string $transmissionTime,
        string $webhookId,
        string $body,
    ): string {
        return $transmissionId . '|' . $transmissionTime . '|' . $webhookId . '|' . sprintf('%u', crc32($body));
    }

    /** Base64 RSA-SHA256 signature, as PayPal sends it. */
    public static function sign(string $message, bool $foreignKey = false): string
    {
        self::generate();

        $key = $foreignKey ? self::$otherPrivateKey : self::$privateKey;
        $signature = '';

        if (! openssl_sign($message, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Unable to sign the PayPal fixture.');
        }

        return base64_encode($signature);
    }

    /** A resolver stand-in: hands back the fixture certificate without touching the network. */
    public static function certificateFetcher(bool $foreign = false): callable
    {
        return static fn (string $url): string => $foreign ? self::foreignCertificate() : self::certificate();
    }

    private static function generate(): void
    {
        if (self::$privateKey !== null) {
            return;
        }

        [self::$privateKey, self::$certificate] = self::keyPair('messageverificationcerts.paypal.com');
        [self::$otherPrivateKey, self::$otherCertificate] = self::keyPair('not.paypal.example');
    }

    /** @return array{0: OpenSSLAsymmetricKey, 1: string} */
    private static function keyPair(string $commonName): array
    {
        $options = ['digest_alg' => 'sha256', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];

        $key = openssl_pkey_new($options);

        if ($key === false) {
            throw new \RuntimeException('Unable to generate an RSA key pair for the PayPal fixture.');
        }

        $csr = openssl_csr_new(['commonName' => $commonName], $key, $options);

        if ($csr === false) {
            throw new \RuntimeException('Unable to generate a certificate request for the PayPal fixture.');
        }

        $certificate = openssl_csr_sign($csr, null, $key, 365, $options);

        if ($certificate === false || ! openssl_x509_export($certificate, $pem)) {
            throw new \RuntimeException('Unable to sign a certificate for the PayPal fixture.');
        }

        return [$key, $pem];
    }
}
