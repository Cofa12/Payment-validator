<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Gateways;

use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Gateways\Fawry\Fawry;
use Cofa\PaymentValidator\Gateways\Fawry\FawryNotificationValidator;
use Cofa\PaymentValidator\Serializers\DecimalAmountNormalizer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SecretPlacement;
use Cofa\PaymentValidator\Tests\Fixtures\FawryFixture;
use Cofa\PaymentValidator\Validators\AbstractHashValidator;
use Cofa\PaymentValidator\Validators\AbstractSignatureValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(FawryNotificationValidator::class)]
#[CoversClass(Fawry::class)]
#[CoversClass(AbstractHashValidator::class)]
#[CoversClass(AbstractSignatureValidator::class)]
#[CoversClass(DecimalAmountNormalizer::class)]
#[CoversClass(SecretPlacement::class)]
final class FawryTest extends TestCase
{
    private function validator(): FawryNotificationValidator
    {
        return new FawryNotificationValidator(FawryFixture::SECURE_KEY);
    }

    #[Test]
    public function it_accepts_a_genuine_v2_notification(): void
    {
        $result = $this->validator()->validate(Payload::fromArray(FawryFixture::notification()));

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('fawry', $result->gateway());
        self::assertSame('sha256', $result->contextValue('algorithm'));
    }

    #[Test]
    public function it_accepts_the_notification_delivered_as_a_raw_json_body(): void
    {
        $json = json_encode(FawryFixture::notification(), JSON_THROW_ON_ERROR);

        self::assertTrue($this->validator()->validate(Payload::fromJson($json))->isValid());
    }

    #[Test]
    public function it_produces_the_signature_the_published_recipe_produces(): void
    {
        $notification = FawryFixture::notification();

        self::assertSame(
            $notification['messageSignature'],
            $this->validator()->sign(Payload::fromArray($notification)),
        );
    }

    #[Test]
    public function the_signing_string_is_the_documented_concatenation(): void
    {
        self::assertSame(
            '970488ORD-2024-001250.00250.00PAIDPAYATFAWRY100155507',
            $this->validator()->signingString(Payload::fromArray(FawryFixture::notification())),
        );
    }

    #[Test]
    public function the_signing_string_never_contains_the_secure_key(): void
    {
        // Fawry folds the key into the hashed message. signingString() is the
        // value an engineer pastes into a support ticket, so it must stop short
        // of the key.
        $signingString = $this->validator()->signingString(Payload::fromArray(FawryFixture::notification()));

        self::assertStringNotContainsString(FawryFixture::SECURE_KEY, $signingString);
    }

    #[Test]
    public function it_restores_the_two_decimal_amounts_json_decoding_destroys(): void
    {
        // json_decode turns 250.00 into the float 250.0, which casts back to
        // "250". Fawry signed "250.00", so without the normalizer nothing that
        // arrives as JSON would ever verify.
        $notification = FawryFixture::notification();

        self::assertSame(250.0, $notification['paymentAmount']);
        self::assertStringContainsString('250.00250.00', $this->validator()->signingString(
            Payload::fromArray($notification),
        ));
    }

    #[Test]
    public function an_integer_amount_is_signed_with_its_decimals(): void
    {
        $body = array_replace(FawryFixture::notificationBody(), ['paymentAmount' => 250, 'orderAmount' => 250]);
        $notification = $body + ['messageSignature' => FawryFixture::signature($body)];

        self::assertTrue($this->validator()->validate(Payload::fromArray($notification))->isValid());
    }

    #[Test]
    public function it_accepts_the_hosted_checkout_redirect(): void
    {
        $payload = Payload::fromQueryString(FawryFixture::redirectQueryString());
        $result = $this->validator()->validate($payload);

        self::assertTrue($result->isValid(), (string) $result->reason());
    }

    #[Test]
    public function the_webhook_and_the_redirect_yield_the_same_signing_string(): void
    {
        $validator = $this->validator();

        self::assertSame(
            $validator->signingString(Payload::fromArray(FawryFixture::notification())),
            $validator->signingString(Payload::fromQueryString(FawryFixture::redirectQueryString())),
        );
    }

    #[Test]
    public function it_accepts_an_order_creation_notification_with_no_payment_reference(): void
    {
        // Fawry signs the absent reference number as an empty string.
        $result = $this->validator()->validate(Payload::fromArray(FawryFixture::unpaidNotification()));

        self::assertTrue($result->isValid(), (string) $result->reason());
    }

    #[Test]
    public function it_accepts_the_corrected_spelling_of_the_payment_reference_field(): void
    {
        $body = FawryFixture::notificationBody();
        $signature = FawryFixture::signature($body);

        $body['paymentReferenceNumber'] = $body['paymentRefrenceNumber'];
        unset($body['paymentRefrenceNumber']);

        self::assertTrue(
            $this->validator()->validate(Payload::fromArray($body + ['messageSignature' => $signature]))->isValid(),
        );
    }

    #[Test]
    public function it_accepts_the_abbreviated_merchant_reference_field(): void
    {
        $body = FawryFixture::notificationBody();
        $signature = FawryFixture::signature($body);

        $body['merchantRefNum'] = $body['merchantRefNumber'];
        unset($body['merchantRefNumber']);

        self::assertTrue(
            $this->validator()->validate(Payload::fromArray($body + ['messageSignature' => $signature]))->isValid(),
        );
    }

    #[Test]
    public function it_accepts_uppercase_hex_from_the_gateway(): void
    {
        $notification = FawryFixture::notification();
        $notification['messageSignature'] = strtoupper($notification['messageSignature']);

        self::assertTrue($this->validator()->validate(Payload::fromArray($notification))->isValid());
    }

    #[Test]
    #[DataProvider('tamperedFieldProvider')]
    public function it_rejects_a_tampered_field(string $field, mixed $value): void
    {
        $notification = FawryFixture::notification();
        $notification[$field] = $value;

        $result = $this->validator()->validate(Payload::fromArray($notification));

        self::assertTrue($result->isInvalid(), sprintf('Tampering with [%s] went undetected.', $field));
        self::assertSame('The provided signature does not match the payload.', $result->reason());
    }

    /** @return iterable<string, array{string, mixed}> */
    public static function tamperedFieldProvider(): iterable
    {
        yield 'amount reduced' => ['paymentAmount', 1.00];
        yield 'order amount inflated' => ['orderAmount', 99999.00];
        yield 'unpaid promoted to paid' => ['orderStatus', 'EXPIRED'];
        yield 'different order' => ['merchantRefNumber', 'ORD-2024-999'];
        yield 'different fawry reference' => ['fawryRefNumber', '111111'];
        yield 'different method' => ['paymentMethod', 'CARD'];
        yield 'different payment reference' => ['paymentRefrenceNumber', '999999999'];
    }

    #[Test]
    public function it_rejects_an_amount_whose_decimals_were_shifted(): void
    {
        // 250.00 vs 2500.0 — the classic decimal attack.
        $notification = FawryFixture::notification();
        $notification['paymentAmount'] = 2500.0;

        self::assertTrue($this->validator()->validate(Payload::fromArray($notification))->isInvalid());
    }

    #[Test]
    public function it_rejects_a_signature_from_another_merchants_key(): void
    {
        $body = FawryFixture::notificationBody();
        $notification = $body + ['messageSignature' => FawryFixture::signature($body, 'another-merchants-key')];

        self::assertTrue($this->validator()->validate(Payload::fromArray($notification))->isInvalid());
    }

    #[Test]
    public function it_rejects_an_hmac_of_the_same_string(): void
    {
        // A plausible mis-implementation: HMACing the fields instead of hashing
        // them with the key appended. It must not be mistaken for the real one.
        $notification = FawryFixture::notification();
        $notification['messageSignature'] = hash_hmac(
            'sha256',
            '970488ORD-2024-001250.00250.00PAIDPAYATFAWRY100155507',
            FawryFixture::SECURE_KEY,
        );

        self::assertTrue($this->validator()->validate(Payload::fromArray($notification))->isInvalid());
    }

    #[Test]
    public function it_rejects_a_notification_with_no_signature(): void
    {
        $result = $this->validator()->validate(Payload::fromArray(FawryFixture::notificationBody()));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('No signature found', (string) $result->reason());
    }

    #[Test]
    public function it_reports_which_signed_fields_were_missing(): void
    {
        $notification = FawryFixture::notification();
        unset($notification['orderStatus'], $notification['paymentMethod']);

        $result = $this->validator()->validate(Payload::fromArray($notification));

        self::assertTrue($result->isInvalid());
        self::assertContains('orderStatus', $result->contextValue('missing_fields'));
        self::assertContains('paymentMethod', $result->contextValue('missing_fields'));
    }

    #[Test]
    public function it_only_claims_payloads_carrying_a_message_signature(): void
    {
        self::assertTrue($this->validator()->supports(Payload::fromArray(FawryFixture::notification())));
        self::assertFalse($this->validator()->supports(Payload::fromArray(FawryFixture::notificationBody())));

        // A bare `signature` field belongs to some other gateway.
        self::assertFalse($this->validator()->supports(Payload::fromArray(['signature' => 'abc'])));
    }

    #[Test]
    public function it_refuses_to_be_built_without_a_secure_key(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('non-empty secret');

        new FawryNotificationValidator('   ');
    }

    #[Test]
    public function the_entry_point_builds_the_notification_validator(): void
    {
        $validator = Fawry::validator(FawryFixture::SECURE_KEY);

        self::assertInstanceOf(FawryNotificationValidator::class, $validator);
        self::assertSame(SecretPlacement::Append, $validator->secretPlacement());
        self::assertTrue($validator->validate(Payload::fromArray(FawryFixture::notification()))->isValid());
    }
}
