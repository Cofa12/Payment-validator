<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Gateways;

use Appssquare\PaymentValidator\Gateways\Kashier\Kashier;
use Appssquare\PaymentValidator\Gateways\Kashier\KashierRedirectValidator;
use Appssquare\PaymentValidator\Gateways\Kashier\KashierSignatureKeysSerializer;
use Appssquare\PaymentValidator\Gateways\Kashier\KashierWebhookValidator;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Tests\Fixtures\KashierFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(KashierWebhookValidator::class)]
#[CoversClass(KashierRedirectValidator::class)]
#[CoversClass(KashierSignatureKeysSerializer::class)]
#[CoversClass(Kashier::class)]
final class KashierTest extends TestCase
{
    private function webhookValidator(): KashierWebhookValidator
    {
        return new KashierWebhookValidator(KashierFixture::API_KEY);
    }

    private function redirectValidator(array $excluded = []): KashierRedirectValidator
    {
        return new KashierRedirectValidator(KashierFixture::API_KEY, $excluded);
    }

    #[Test]
    public function it_accepts_a_genuine_webhook(): void
    {
        $result = $this->webhookValidator()->validate(Payload::fromArray(KashierFixture::webhook()));

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('kashier', $result->gateway());
    }

    #[Test]
    public function it_builds_the_signed_string_from_the_declared_signature_keys(): void
    {
        $payload = Payload::fromArray(KashierFixture::webhook());

        self::assertSame(
            'amount=250&currency=EGP&merchantOrderId=ORD-2024-001'
            . '&orderReference=TEST-ORD-1911&transactionId=TX-9911&status=SUCCESS',
            urldecode($this->webhookValidator()->signingString($payload)),
        );
    }

    #[Test]
    public function it_ignores_fields_the_webhook_did_not_declare_as_signed(): void
    {
        // Kashier adds fields over time; only the declared ones are signed, so
        // an extra field must not invalidate an otherwise genuine webhook.
        $webhook = KashierFixture::webhook();
        $webhook['data']['newFieldAddedLater'] = 'whatever';

        self::assertTrue($this->webhookValidator()->validate(Payload::fromArray($webhook))->isValid());
    }

    #[Test]
    #[DataProvider('tamperedWebhookFieldProvider')]
    public function it_rejects_a_tampered_webhook_field(string $field, mixed $value): void
    {
        $webhook = KashierFixture::webhook();
        $webhook['data'][$field] = $value;

        $result = $this->webhookValidator()->validate(Payload::fromArray($webhook));

        self::assertTrue($result->isInvalid(), sprintf('Tampering with [%s] went undetected.', $field));
    }

    /** @return iterable<string, array{string, mixed}> */
    public static function tamperedWebhookFieldProvider(): iterable
    {
        yield 'amount' => ['amount', 1];
        yield 'currency' => ['currency', 'USD'];
        yield 'merchant order id' => ['merchantOrderId', 'ORD-OTHER'];
        yield 'order reference' => ['orderReference', 'TEST-OTHER'];
        yield 'transaction id' => ['transactionId', 'TX-OTHER'];
        yield 'status' => ['status', 'FAILURE'];
    }

    #[Test]
    public function it_rejects_a_webhook_whose_signature_key_list_was_trimmed(): void
    {
        // Dropping `status` from signatureKeys would otherwise let an attacker
        // exclude the field they tampered with from the signed string.
        $webhook = KashierFixture::webhook();
        $webhook['data']['status'] = 'FAILURE';
        $webhook['data']['signatureKeys'] = ['amount', 'currency'];

        self::assertTrue($this->webhookValidator()->validate(Payload::fromArray($webhook))->isInvalid());
    }

    #[Test]
    public function it_rejects_a_webhook_that_declares_no_signature_keys(): void
    {
        $webhook = KashierFixture::webhook();
        $webhook['data']['signatureKeys'] = [];

        $result = $this->webhookValidator()->validate(Payload::fromArray($webhook));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('signatureKeys', (string) $result->reason());
    }

    #[Test]
    public function it_reports_the_signature_keys_it_used_when_a_webhook_does_not_match(): void
    {
        $webhook = KashierFixture::webhook();
        $webhook['data']['amount'] = 1;

        $result = $this->webhookValidator()->validate(Payload::fromArray($webhook));

        self::assertSame($webhook['data']['signatureKeys'], $result->contextValue('signature_keys'));
    }

    #[Test]
    public function it_reads_the_webhook_signature_from_the_header_when_the_body_omits_it(): void
    {
        $webhook = KashierFixture::webhook();
        $signature = $webhook['data']['kashierSignature'];
        unset($webhook['data']['kashierSignature']);

        $payload = Payload::fromArray($webhook, ['x-kashier-signature' => $signature]);

        self::assertTrue($this->webhookValidator()->validate($payload)->isValid());
    }

    #[Test]
    public function it_accepts_a_genuine_redirect(): void
    {
        $payload = Payload::fromQueryString(KashierFixture::redirectQueryString());
        $result = $this->redirectValidator()->validate($payload);

        self::assertTrue($result->isValid(), (string) $result->reason());
    }

    #[Test]
    public function it_excludes_the_unsigned_mode_parameter(): void
    {
        $payload = Payload::fromQueryString(KashierFixture::redirectQueryString());

        self::assertStringNotContainsString('mode=', $this->redirectValidator()->signingString($payload));
        self::assertStringNotContainsString('signature=', $this->redirectValidator()->signingString($payload));
    }

    #[Test]
    #[DataProvider('tamperedRedirectParamProvider')]
    public function it_rejects_a_tampered_redirect_parameter(string $param, string $value): void
    {
        $payload = Payload::fromQueryString(KashierFixture::tamperedRedirectQueryString($param, $value));

        self::assertTrue($this->redirectValidator()->validate($payload)->isInvalid());
    }

    /** @return iterable<string, array{string, string}> */
    public static function tamperedRedirectParamProvider(): iterable
    {
        yield 'payment status' => ['paymentStatus', 'FAILURE'];
        yield 'amount' => ['amount', '1'];
        yield 'currency' => ['currency', 'USD'];
        yield 'merchant order id' => ['merchantOrderId', 'ORD-OTHER'];
        yield 'transaction id' => ['transactionId', 'TX-OTHER'];
    }

    #[Test]
    public function it_rejects_a_redirect_whose_parameters_were_reordered(): void
    {
        // Kashier signs the query string as sent, so order is part of the contract.
        $params = KashierFixture::redirectParams();
        $signature = KashierFixture::redirectSignature($params);

        $reordered = array_reverse($params, preserve_keys: true);
        $reordered['signature'] = $signature;

        $payload = Payload::fromQueryString(http_build_query($reordered));

        self::assertTrue($this->redirectValidator()->validate($payload)->isInvalid());
    }

    #[Test]
    public function extra_unsigned_parameters_can_be_excluded_by_configuration(): void
    {
        $query = KashierFixture::redirectQueryString(unsignedExtras: ['lang' => 'ar', 'utm_source' => 'email']);
        $payload = Payload::fromQueryString($query);

        self::assertTrue(
            $this->redirectValidator()->validate($payload)->isInvalid(),
            'unknown extra parameters must break the signature by default',
        );

        self::assertTrue($this->redirectValidator(['lang', 'utm_source'])->validate($payload)->isValid());
    }

    #[Test]
    public function it_rejects_a_redirect_with_no_signature(): void
    {
        $payload = Payload::fromQueryString(http_build_query(KashierFixture::redirectParams()));
        $result = $this->redirectValidator()->validate($payload);

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('No signature found', (string) $result->reason());
    }

    #[Test]
    public function the_channels_recognise_only_their_own_payload_shape(): void
    {
        $webhook = Payload::fromArray(KashierFixture::webhook());
        $redirect = Payload::fromQueryString(KashierFixture::redirectQueryString());

        self::assertTrue($this->webhookValidator()->supports($webhook));
        self::assertFalse($this->webhookValidator()->supports($redirect));

        self::assertTrue($this->redirectValidator()->supports($redirect));
        self::assertFalse($this->redirectValidator()->supports($webhook));
    }

    #[Test]
    public function the_composite_routes_both_channels(): void
    {
        $validator = Kashier::validator(KashierFixture::API_KEY);

        $webhook = $validator->validate(Payload::fromArray(KashierFixture::webhook()));
        self::assertTrue($webhook->isValid());
        self::assertSame('webhook', $webhook->contextValue('channel'));

        $redirect = $validator->validate(Payload::fromQueryString(KashierFixture::redirectQueryString()));
        self::assertTrue($redirect->isValid());
        self::assertSame('redirect', $redirect->contextValue('channel'));
    }

    #[Test]
    public function it_rejects_a_webhook_whose_signature_key_list_is_not_a_list(): void
    {
        $webhook = KashierFixture::webhook();
        $webhook['data']['signatureKeys'] = 'amount,currency';

        $result = $this->webhookValidator()->validate(Payload::fromArray($webhook));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('signatureKeys', (string) $result->reason());
    }

    #[Test]
    public function it_ignores_non_scalar_entries_in_the_signature_key_list(): void
    {
        $webhook = KashierFixture::webhook();
        $webhook['data']['signatureKeys'] = array_merge($webhook['data']['signatureKeys'], [['nested'], '']);

        // The junk entries drop out, leaving the genuine key list intact.
        self::assertTrue($this->webhookValidator()->validate(Payload::fromArray($webhook))->isValid());
    }

    #[Test]
    public function it_reads_signature_keys_declared_at_the_root(): void
    {
        $data = KashierFixture::webhookData();
        $signature = KashierFixture::webhookSignature($data);

        $payload = Payload::fromArray($data + ['kashierSignature' => $signature]);

        self::assertTrue($this->webhookValidator()->supports($payload));
    }
}
