<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Gateways;

use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Gateways\HyperPay\HyperPay;
use Cofa\PaymentValidator\Gateways\HyperPay\HyperPayWebhookValidator;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Tests\Fixtures\HyperPayFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(HyperPayWebhookValidator::class)]
#[CoversClass(HyperPay::class)]
final class HyperPayTest extends TestCase
{
    private function validator(): HyperPayWebhookValidator
    {
        return HyperPay::validator(HyperPayFixture::KEY);
    }

    private function payload(?array $overrideHeaders = null, ?string $body = null): Payload
    {
        $encrypted = HyperPayFixture::encrypted();

        return Payload::fromRawBody(
            $body ?? $encrypted['body'],
            $overrideHeaders ?? HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']),
        );
    }

    #[Test]
    public function it_accepts_a_webhook_that_decrypts_under_the_merchant_key(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $payload = Payload::fromRawBody($encrypted['body'], HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']));

        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('hyperpay', $result->gateway());
        self::assertSame('aes-256-gcm', $result->contextValue('cipher'));
    }

    #[Test]
    public function it_returns_the_decrypted_notification_on_the_result(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $payload = Payload::fromRawBody($encrypted['body'], HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']));

        $result = $this->validator()->validate($payload);

        self::assertSame(HyperPayFixture::notification(), $result->contextValue('payload'));
        self::assertSame($encrypted['plaintext'], $result->contextValue('plaintext'));
    }

    #[Test]
    public function the_decrypt_helper_returns_the_notification_or_null(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $valid = Payload::fromRawBody($encrypted['body'], HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']));

        self::assertSame(HyperPayFixture::notification(), $this->validator()->decrypt($valid));
        self::assertNull($this->validator()->decrypt(Payload::fromRawBody('deadbeef')));
    }

    #[Test]
    public function it_reads_the_headers_case_insensitively(): void
    {
        $encrypted = HyperPayFixture::encrypted();

        $payload = Payload::fromRawBody($encrypted['body'], [
            'x-initialization-vector' => $encrypted['iv'],
            'x-authentication-tag' => $encrypted['tag'],
        ]);

        self::assertTrue($this->validator()->validate($payload)->isValid());
    }

    #[Test]
    public function it_reads_headers_in_php_server_style(): void
    {
        $encrypted = HyperPayFixture::encrypted();

        $payload = Payload::fromRawBody($encrypted['body'], [
            'HTTP_X_INITIALIZATION_VECTOR' => $encrypted['iv'],
            'HTTP_X_AUTHENTICATION_TAG' => $encrypted['tag'],
        ]);

        self::assertTrue($this->validator()->validate($payload)->isValid());
    }

    #[Test]
    public function it_rejects_a_body_altered_in_transit(): void
    {
        $encrypted = HyperPayFixture::encrypted();

        $body = $encrypted['body'];
        $body[10] = $body[10] === 'a' ? 'b' : 'a';

        $payload = Payload::fromRawBody($body, HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']));
        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('did not authenticate', (string) $result->reason());
    }

    #[Test]
    public function it_rejects_a_webhook_encrypted_under_another_key(): void
    {
        $encrypted = HyperPayFixture::encrypted(hexKey: bin2hex(str_repeat('z', 32)));
        $payload = Payload::fromRawBody($encrypted['body'], HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']));

        self::assertTrue($this->validator()->validate($payload)->isInvalid());
    }

    #[Test]
    public function it_rejects_a_webhook_missing_the_initialisation_vector(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $payload = Payload::fromRawBody($encrypted['body'], ['X-Authentication-Tag' => $encrypted['tag']]);

        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('X-Initialization-Vector', (string) $result->reason());
    }

    #[Test]
    public function it_rejects_a_webhook_missing_the_authentication_tag(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $payload = Payload::fromRawBody($encrypted['body'], ['X-Initialization-Vector' => $encrypted['iv']]);

        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('X-Authentication-Tag', (string) $result->reason());
    }

    #[Test]
    public function it_rejects_an_empty_body(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $payload = Payload::fromRawBody('   ', HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']));

        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('body is empty', (string) $result->reason());
    }

    #[Test]
    public function it_supports_only_requests_carrying_both_headers(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $validator = $this->validator();

        self::assertTrue($validator->supports($this->payload()));
        self::assertFalse($validator->supports(Payload::fromRawBody($encrypted['body'])));
        self::assertFalse($validator->supports(
            Payload::fromRawBody($encrypted['body'], ['X-Initialization-Vector' => $encrypted['iv']]),
        ));
    }

    #[Test]
    public function the_header_names_are_configurable(): void
    {
        $encrypted = HyperPayFixture::encrypted();

        $validator = new HyperPayWebhookValidator(HyperPayFixture::KEY, 'X-Custom-Iv', 'X-Custom-Tag');
        $payload = Payload::fromRawBody($encrypted['body'], [
            'X-Custom-Iv' => $encrypted['iv'],
            'X-Custom-Tag' => $encrypted['tag'],
        ]);

        self::assertTrue($validator->validate($payload)->isValid());
    }

    #[Test]
    public function a_non_json_plaintext_still_authenticates_but_decodes_to_null(): void
    {
        $encrypted = HyperPayFixture::encrypted('plain text notification');
        $payload = Payload::fromRawBody($encrypted['body'], HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']));

        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isValid());
        self::assertNull($result->contextValue('payload'));
        self::assertSame('plain text notification', $result->contextValue('plaintext'));
    }

    #[Test]
    public function it_refuses_a_malformed_decryption_key(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('hyperpay');

        HyperPay::validator('not-hex');
    }

    #[Test]
    public function it_reports_its_gateway_name(): void
    {
        self::assertSame('hyperpay', $this->validator()->gateway());
        self::assertSame('hyperpay', HyperPay::GATEWAY);
    }
}
