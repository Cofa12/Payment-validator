<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Gateways;

use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Gateways\PayPal\PayPal;
use Cofa\PaymentValidator\Gateways\PayPal\PayPalWebhookValidator;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\RemoteCertificateResolver;
use Cofa\PaymentValidator\Tests\Fixtures\PayPalFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PayPalWebhookValidator::class)]
#[CoversClass(PayPal::class)]
#[CoversClass(RemoteCertificateResolver::class)]
final class PayPalTest extends TestCase
{
    private function validator(bool $foreignCertificate = false): PayPalWebhookValidator
    {
        return new PayPalWebhookValidator(
            PayPalFixture::WEBHOOK_ID,
            new RemoteCertificateResolver(
                PayPalWebhookValidator::CERTIFICATE_HOSTS,
                PayPalFixture::certificateFetcher($foreignCertificate),
            ),
        );
    }

    /** @param array<string, string> $headerOverrides */
    private function payload(array $headerOverrides = [], ?string $body = null): Payload
    {
        $webhook = PayPalFixture::webhook();

        return Payload::fromJson(
            $body ?? $webhook['body'],
            array_replace($webhook['headers'], $headerOverrides),
        );
    }

    #[Test]
    public function it_accepts_a_genuine_webhook(): void
    {
        $result = $this->validator()->validate($this->payload());

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('paypal', $result->gateway());
        self::assertSame('SHA256withRSA', $result->contextValue('algorithm'));
        self::assertSame(PayPalFixture::CERT_URL, $result->contextValue('cert_url'));
    }

    #[Test]
    public function the_signed_message_is_the_documented_four_part_string(): void
    {
        $webhook = PayPalFixture::webhook();

        self::assertSame(
            'e8a3b1c0-0f6c-11ef-9c2d-9f1a2b3c4d5e|2024-05-01T10:15:31Z|' . PayPalFixture::WEBHOOK_ID
            . '|' . sprintf('%u', crc32($webhook['body'])),
            $this->validator()->signingString($this->payload()),
        );
    }

    #[Test]
    public function it_rejects_a_body_altered_in_transit(): void
    {
        $webhook = PayPalFixture::webhook();
        $tampered = str_replace('"250.00"', '"1.00"', $webhook['body']);

        self::assertNotSame($webhook['body'], $tampered);

        $result = $this->validator()->validate(Payload::fromJson($tampered, $webhook['headers']));

        self::assertTrue($result->isInvalid());
        self::assertSame('The transmission signature does not match the payload.', $result->reason());
    }

    #[Test]
    public function it_rejects_a_body_that_was_decoded_and_re_encoded(): void
    {
        // crc32 covers the exact bytes. A framework that round-trips the JSON
        // will break verification even when nothing was tampered with, which is
        // why the raw body has to reach the validator.
        $webhook = PayPalFixture::webhook();
        $reEncoded = (string) json_encode(json_decode($webhook['body'], true));

        self::assertNotSame($webhook['body'], $reEncoded);
        self::assertTrue($this->validator()->validate(
            Payload::fromJson($reEncoded, $webhook['headers']),
        )->isInvalid());
    }

    #[Test]
    public function it_rejects_a_webhook_signed_for_another_subscription(): void
    {
        // The webhook ID is inside the signed message, so a signature minted for
        // a different subscription cannot be replayed against this endpoint.
        $webhook = PayPalFixture::webhook(webhookId: 'WH-OTHER-SUBSCRIPTION-ID');

        self::assertTrue($this->validator()->validate(
            Payload::fromJson($webhook['body'], $webhook['headers']),
        )->isInvalid());
    }

    #[Test]
    public function it_rejects_a_signature_from_a_key_that_is_not_paypals(): void
    {
        // Signed with a different private key, but presented under PayPal's
        // certificate: the arrangement an attacker would try first.
        $webhook = PayPalFixture::webhook(foreignKey: true);

        self::assertTrue($this->validator()->validate(
            Payload::fromJson($webhook['body'], $webhook['headers']),
        )->isInvalid());
    }

    #[Test]
    public function it_rejects_a_genuine_signature_checked_against_a_foreign_certificate(): void
    {
        // The resolver hands back a well-formed certificate from an unrelated
        // key pair; a valid certificate is not the same as the right one.
        self::assertTrue($this->validator(foreignCertificate: true)->validate($this->payload())->isInvalid());
    }

    #[Test]
    #[DataProvider('tamperedHeaderProvider')]
    public function it_rejects_a_tampered_transmission_header(string $header, string $value): void
    {
        $result = $this->validator()->validate($this->payload([$header => $value]));

        self::assertTrue($result->isInvalid(), sprintf('Tampering with [%s] went undetected.', $header));
    }

    /** @return iterable<string, array{string, string}> */
    public static function tamperedHeaderProvider(): iterable
    {
        yield 'replayed under a new id' => ['PAYPAL-TRANSMISSION-ID', '00000000-0000-0000-0000-000000000000'];
        yield 'back-dated' => ['PAYPAL-TRANSMISSION-TIME', '2020-01-01T00:00:00Z'];
        yield 'signature swapped' => ['PAYPAL-TRANSMISSION-SIG', base64_encode(str_repeat("\x01", 256))];
    }

    #[Test]
    #[DataProvider('requiredHeaderProvider')]
    public function it_reports_a_missing_transmission_header(string $header): void
    {
        $webhook = PayPalFixture::webhook();

        unset($webhook['headers'][$header]);

        $payload = Payload::fromJson($webhook['body'], $webhook['headers']);
        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString(strtolower($header), (string) $result->reason());
        self::assertFalse($this->validator()->supports($payload));
    }

    /** @return iterable<string, array{string}> */
    public static function requiredHeaderProvider(): iterable
    {
        yield 'transmission id' => ['PAYPAL-TRANSMISSION-ID'];
        yield 'transmission time' => ['PAYPAL-TRANSMISSION-TIME'];
        yield 'transmission signature' => ['PAYPAL-TRANSMISSION-SIG'];
        yield 'certificate url' => ['PAYPAL-CERT-URL'];
    }

    #[Test]
    public function it_rejects_an_empty_body(): void
    {
        $webhook = PayPalFixture::webhook();
        $result = $this->validator()->validate(Payload::fromRawBody('', $webhook['headers']));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('body is empty', (string) $result->reason());
    }

    #[Test]
    public function it_rejects_a_signature_that_is_not_base64(): void
    {
        $result = $this->validator()->validate($this->payload(['PAYPAL-TRANSMISSION-SIG' => 'not base64 ***']));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('base64', (string) $result->reason());
    }

    #[Test]
    public function it_rejects_an_unknown_signature_algorithm(): void
    {
        // Downgrading the algorithm must not be a way past the check.
        $result = $this->validator()->validate($this->payload(['PAYPAL-AUTH-ALGO' => 'MD5withRSA']));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('Unsupported signature algorithm', (string) $result->reason());
        self::assertContains('SHA256WITHRSA', $result->contextValue('supported_algorithms'));
    }

    #[Test]
    public function it_assumes_sha256_when_paypal_sends_no_algorithm_header(): void
    {
        $webhook = PayPalFixture::webhook();

        unset($webhook['headers']['PAYPAL-AUTH-ALGO']);

        self::assertTrue($this->validator()->validate(
            Payload::fromJson($webhook['body'], $webhook['headers']),
        )->isValid());
    }

    #[Test]
    #[DataProvider('hostileCertificateUrlProvider')]
    public function it_refuses_a_certificate_url_that_is_not_paypals(string $label, string $url): void
    {
        // The cert URL arrives inside the request being verified. If an attacker
        // can point it at a host they control, they sign forgeries at will — so
        // this is the check the whole scheme rests on.
        $webhook = PayPalFixture::webhook(certUrl: $url);
        $result = $this->validator()->validate(Payload::fromJson($webhook['body'], $webhook['headers']));

        self::assertTrue($result->isInvalid(), sprintf('A %s certificate URL was accepted.', $label));
        self::assertStringContainsString('not an allowed PayPal host', (string) $result->reason());
    }

    /** @return iterable<string, array{string, string}> */
    public static function hostileCertificateUrlProvider(): iterable
    {
        yield 'attacker-controlled host' => ['foreign', 'https://evil.example/certs/CERT-1'];
        yield 'lookalike domain' => ['lookalike', 'https://paypal.com.evil.example/certs/CERT-1'];
        yield 'suffix without a dot' => ['suffix', 'https://notpaypal.com/certs/CERT-1'];
        yield 'plaintext' => ['http', 'http://api.paypal.com/certs/CERT-1'];
        yield 'credentials in the authority' => ['userinfo', 'https://api.paypal.com@evil.example/certs/CERT-1'];
        yield 'internal metadata service' => ['SSRF', 'https://169.254.169.254/latest/meta-data/'];
        yield 'loopback' => ['loopback', 'https://127.0.0.1/certs/CERT-1'];
        yield 'non-standard port' => ['ported', 'https://api.paypal.com:8443/certs/CERT-1'];
        yield 'file scheme' => ['file', 'file:///etc/passwd'];
        yield 'no host at all' => ['hostless', 'https:///v1/notifications/certs/CERT-1'];
        yield 'not a url' => ['malformed', 'https://'];
    }

    #[Test]
    public function it_accepts_the_sandbox_certificate_host(): void
    {
        $url = 'https://api.sandbox.paypal.com/v1/notifications/certs/CERT-1';
        $webhook = PayPalFixture::webhook(certUrl: $url);

        self::assertTrue($this->validator()->validate(
            Payload::fromJson($webhook['body'], $webhook['headers']),
        )->isValid());
    }

    #[Test]
    public function it_rejects_a_certificate_the_resolver_could_not_fetch(): void
    {
        $validator = new PayPalWebhookValidator(
            PayPalFixture::WEBHOOK_ID,
            new RemoteCertificateResolver(['paypal.com'], static fn (string $url): ?string => null),
        );

        $result = $validator->validate($this->payload());

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('could not be retrieved', (string) $result->reason());
    }

    #[Test]
    public function a_transport_failure_is_an_invalid_result_not_an_exception(): void
    {
        // A webhook handler must not 500 because the certificate host is down.
        $validator = new PayPalWebhookValidator(
            PayPalFixture::WEBHOOK_ID,
            new RemoteCertificateResolver(['paypal.com'], static function (string $url): string {
                throw new \RuntimeException('connection timed out');
            }),
        );

        self::assertTrue($validator->validate($this->payload())->isInvalid());
    }

    #[Test]
    public function it_rejects_a_response_that_is_not_a_certificate_at_all(): void
    {
        // An error page where a PEM was expected: refused before OpenSSL sees it.
        $validator = new PayPalWebhookValidator(
            PayPalFixture::WEBHOOK_ID,
            new RemoteCertificateResolver(['paypal.com'], static fn (string $url): string => '<html>404</html>'),
        );

        $result = $validator->validate($this->payload());

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('could not be retrieved', (string) $result->reason());
    }

    #[Test]
    public function it_rejects_a_certificate_that_openssl_cannot_parse(): void
    {
        // PEM-shaped but corrupt — it gets past the resolver and has to be
        // caught where the key is loaded.
        $validator = new PayPalWebhookValidator(
            PayPalFixture::WEBHOOK_ID,
            new RemoteCertificateResolver(['paypal.com'], static fn (string $url): string =>
                "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"),
        );

        $result = $validator->validate($this->payload());

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('could not be parsed', (string) $result->reason());
    }

    #[Test]
    public function it_names_itself_and_claims_a_fully_headed_webhook(): void
    {
        $validator = $this->validator();

        self::assertSame('paypal', $validator->gateway());
        self::assertTrue($validator->supports($this->payload()));
    }

    #[Test]
    public function the_resolver_fetches_each_certificate_once(): void
    {
        $calls = 0;
        $resolver = new RemoteCertificateResolver(
            ['paypal.com'],
            static function (string $url) use (&$calls): string {
                $calls++;

                return PayPalFixture::certificate();
            },
        );

        $validator = new PayPalWebhookValidator(PayPalFixture::WEBHOOK_ID, $resolver);

        $validator->validate($this->payload());
        $validator->validate($this->payload());

        self::assertSame(1, $calls);
    }

    #[Test]
    public function the_resolver_refuses_an_empty_allow_list(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('at least one allowed host');

        new RemoteCertificateResolver([]);
    }

    #[Test]
    public function the_resolver_normalises_the_hosts_it_was_given(): void
    {
        $resolver = new RemoteCertificateResolver([' .PayPal.com ', ''], PayPalFixture::certificateFetcher());

        self::assertSame(['paypal.com'], $resolver->allowedHosts());
        self::assertNotNull($resolver->resolve('https://API.PayPal.com/certs/CERT-1'));
    }

    #[Test]
    public function it_refuses_to_be_built_without_a_webhook_id(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('webhook ID');

        new PayPalWebhookValidator('  ');
    }

    #[Test]
    public function the_entry_point_builds_a_webhook_validator(): void
    {
        $validator = PayPal::validator(
            PayPalFixture::WEBHOOK_ID,
            new RemoteCertificateResolver(['paypal.com'], PayPalFixture::certificateFetcher()),
        );

        self::assertInstanceOf(PayPalWebhookValidator::class, $validator);
        self::assertTrue($validator->validate($this->payload())->isValid());
    }

    #[Test]
    public function it_defaults_to_a_resolver_locked_to_paypal_hosts(): void
    {
        // No resolver supplied: the default must still refuse a foreign host,
        // and must do so without opening a connection.
        $webhook = PayPalFixture::webhook(certUrl: 'https://evil.example/certs/CERT-1');
        $result = (new PayPalWebhookValidator(PayPalFixture::WEBHOOK_ID))
            ->validate(Payload::fromJson($webhook['body'], $webhook['headers']));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('not an allowed PayPal host', (string) $result->reason());
    }
}
