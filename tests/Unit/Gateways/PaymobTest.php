<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Gateways;

use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Gateways\Paymob\Paymob;
use Cofa\PaymentValidator\Gateways\Paymob\PaymobCardTokenValidator;
use Cofa\PaymentValidator\Gateways\Paymob\PaymobTransactionValidator;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Tests\Fixtures\PaymobFixture;
use Cofa\PaymentValidator\Validators\AbstractHmacValidator;
use Cofa\PaymentValidator\Validators\CompositeValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PaymobTransactionValidator::class)]
#[CoversClass(PaymobCardTokenValidator::class)]
#[CoversClass(Paymob::class)]
#[CoversClass(AbstractHmacValidator::class)]
final class PaymobTest extends TestCase
{
    private function transactionValidator(): PaymobTransactionValidator
    {
        return new PaymobTransactionValidator(PaymobFixture::SECRET);
    }

    private function tokenValidator(): PaymobCardTokenValidator
    {
        return new PaymobCardTokenValidator(PaymobFixture::SECRET);
    }

    #[Test]
    public function it_accepts_a_genuine_processed_callback(): void
    {
        $payload = Payload::fromArray(PaymobFixture::transactionWebhook());
        $result = $this->transactionValidator()->validate($payload);

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('paymob', $result->gateway());
        self::assertSame('sha512', $result->contextValue('algorithm'));
    }

    #[Test]
    public function it_accepts_the_callback_delivered_as_a_raw_json_body(): void
    {
        $json = json_encode(PaymobFixture::transactionWebhook(), JSON_THROW_ON_ERROR);

        self::assertTrue($this->transactionValidator()->validate(Payload::fromJson($json))->isValid());
    }

    #[Test]
    public function it_produces_the_hmac_the_published_recipe_produces(): void
    {
        $webhook = PaymobFixture::transactionWebhook();

        self::assertSame(
            $webhook['hmac'],
            $this->transactionValidator()->sign(Payload::fromArray($webhook)),
        );
    }

    #[Test]
    public function the_signing_string_is_the_documented_lexicographical_concatenation(): void
    {
        $webhook = PaymobFixture::transactionWebhook();

        self::assertSame(
            '100002024-05-01T10:15:30.123456EGPfalsefalse123456789987654truefalsefalse'
            . 'falsetruefalse555555554242false2346MasterCardcardtrue',
            $this->transactionValidator()->signingString(Payload::fromArray($webhook)),
        );
    }

    #[Test]
    public function it_accepts_the_flat_response_callback_from_a_redirect(): void
    {
        $payload = Payload::fromQueryString(PaymobFixture::redirectQueryString());
        $result = $this->transactionValidator()->validate($payload);

        self::assertTrue($result->isValid(), (string) $result->reason());
    }

    #[Test]
    public function the_webhook_and_the_redirect_yield_the_same_signing_string(): void
    {
        $validator = $this->transactionValidator();

        self::assertSame(
            $validator->signingString(Payload::fromArray(PaymobFixture::transactionWebhook())),
            $validator->signingString(Payload::fromQueryString(PaymobFixture::redirectQueryString())),
        );
    }

    #[Test]
    public function it_accepts_uppercase_hex_from_the_gateway(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        $webhook['hmac'] = strtoupper($webhook['hmac']);

        self::assertTrue($this->transactionValidator()->validate(Payload::fromArray($webhook))->isValid());
    }

    #[Test]
    #[DataProvider('tamperedFieldProvider')]
    public function it_rejects_a_tampered_field(string $field, mixed $value): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        $webhook['obj'][$field] = $value;

        $result = $this->transactionValidator()->validate(Payload::fromArray($webhook));

        self::assertTrue($result->isInvalid(), sprintf('Tampering with [%s] went undetected.', $field));
        self::assertSame('The provided signature does not match the payload.', $result->reason());
    }

    /** @return iterable<string, array{string, mixed}> */
    public static function tamperedFieldProvider(): iterable
    {
        yield 'amount inflated' => ['amount_cents', 1];
        yield 'failure flipped to success' => ['success', false];
        yield 'refund flag flipped' => ['is_refunded', true];
        yield 'different currency' => ['currency', 'USD'];
        yield 'different integration' => ['integration_id', 111];
        yield 'different owner' => ['owner', 1];
        yield 'different transaction id' => ['id', 999];
        yield 'different card' => ['source_data', ['pan' => '1111', 'sub_type' => 'Visa', 'type' => 'card']];
        yield 'different order' => ['order', ['id' => 1]];
    }

    #[Test]
    public function it_rejects_an_hmac_signed_with_another_secret(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        $webhook['hmac'] = PaymobFixture::transactionHmac($webhook['obj'], 'a-different-secret');

        self::assertTrue($this->transactionValidator()->validate(Payload::fromArray($webhook))->isInvalid());
    }

    #[Test]
    public function it_rejects_a_callback_with_no_hmac(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        unset($webhook['hmac']);

        $result = $this->transactionValidator()->validate(Payload::fromArray($webhook));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('No signature found', (string) $result->reason());
    }

    #[Test]
    public function it_reports_which_signed_fields_were_missing(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        unset($webhook['obj']['owner'], $webhook['obj']['source_data']);

        $result = $this->transactionValidator()->validate(Payload::fromArray($webhook));

        self::assertTrue($result->isInvalid());
        self::assertContains('obj.owner|owner', $result->contextValue('missing_fields'));
        self::assertContains(
            'obj.source_data.pan|source_data.pan|source_data_pan',
            $result->contextValue('missing_fields'),
        );
    }

    #[Test]
    public function it_accepts_a_genuine_card_token_callback(): void
    {
        $result = $this->tokenValidator()->validate(Payload::fromArray(PaymobFixture::cardTokenWebhook()));

        self::assertTrue($result->isValid(), (string) $result->reason());
    }

    #[Test]
    public function it_rejects_a_tampered_card_token_callback(): void
    {
        $webhook = PaymobFixture::cardTokenWebhook();
        $webhook['obj']['token'] = 'stolen-token';

        self::assertTrue($this->tokenValidator()->validate(Payload::fromArray($webhook))->isInvalid());
    }

    #[Test]
    public function the_two_channels_do_not_answer_for_each_other(): void
    {
        $transaction = Payload::fromArray(PaymobFixture::transactionWebhook());
        $token = Payload::fromArray(PaymobFixture::cardTokenWebhook());

        self::assertTrue($this->transactionValidator()->supports($transaction));
        self::assertFalse($this->transactionValidator()->supports($token));

        self::assertTrue($this->tokenValidator()->supports($token));
        self::assertFalse($this->tokenValidator()->supports($transaction));
    }

    #[Test]
    public function a_payload_with_no_hmac_is_supported_by_neither_channel(): void
    {
        $payload = Payload::fromArray(['type' => 'TRANSACTION', 'obj' => ['amount_cents' => 1]]);

        self::assertFalse($this->transactionValidator()->supports($payload));
        self::assertFalse($this->tokenValidator()->supports($payload));
    }

    #[Test]
    public function the_composite_routes_each_callback_to_its_channel(): void
    {
        $validator = Paymob::validator(PaymobFixture::SECRET);

        self::assertInstanceOf(CompositeValidator::class, $validator);

        $transaction = $validator->validate(Payload::fromArray(PaymobFixture::transactionWebhook()));
        self::assertTrue($transaction->isValid());
        self::assertSame('transaction', $transaction->contextValue('channel'));

        $token = $validator->validate(Payload::fromArray(PaymobFixture::cardTokenWebhook()));
        self::assertTrue($token->isValid());
        self::assertSame('card_token', $token->contextValue('channel'));
    }

    #[Test]
    public function it_refuses_to_be_built_without_a_secret(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('non-empty secret');

        new PaymobTransactionValidator('   ');
    }

    #[Test]
    public function the_transaction_channel_recognises_a_typeless_callback_by_its_shape(): void
    {
        // The response callback carries no `type`, so recognition falls back to
        // the fields that only a transaction callback has.
        $payload = Payload::fromQueryString(PaymobFixture::redirectQueryString());

        self::assertTrue($this->transactionValidator()->supports($payload));
        self::assertFalse($this->tokenValidator()->supports($payload));
    }

    #[Test]
    public function the_token_channel_recognises_a_typeless_callback_by_its_shape(): void
    {
        $obj = PaymobFixture::cardTokenObject();
        $flat = $obj + ['hmac' => PaymobFixture::cardTokenHmac($obj)];

        $payload = Payload::fromArray($flat);

        self::assertTrue($this->tokenValidator()->supports($payload));
        self::assertFalse($this->transactionValidator()->supports($payload));
        self::assertTrue($this->tokenValidator()->validate($payload)->isValid());
    }

    #[Test]
    public function an_empty_type_string_does_not_short_circuit_shape_detection(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        $webhook['type'] = '';

        self::assertTrue($this->transactionValidator()->supports(Payload::fromArray($webhook)));
    }

    #[Test]
    public function it_reads_an_hmac_nested_beside_the_transaction_object(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        $webhook['obj']['hmac'] = $webhook['hmac'];
        unset($webhook['hmac']);

        self::assertTrue($this->transactionValidator()->validate(Payload::fromArray($webhook))->isValid());
    }
}
