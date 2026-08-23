<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Gateways;

use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;
use Appssquare\PaymentValidator\Gateways\EasyKash\EasyKash;
use Appssquare\PaymentValidator\Gateways\EasyKash\EasyKashWebhookValidator;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Tests\Fixtures\EasyKashFixture;
use Appssquare\PaymentValidator\Validators\SharedSecretValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(EasyKashWebhookValidator::class)]
#[CoversClass(EasyKash::class)]
#[CoversClass(SharedSecretValidator::class)]
#[CoversClass(InvalidConfigurationException::class)]
final class EasyKashTest extends TestCase
{
    private function validator(?array $fields = null): EasyKashWebhookValidator
    {
        return new EasyKashWebhookValidator(EasyKashFixture::SECRET, $fields);
    }

    #[Test]
    public function it_accepts_a_genuine_webhook(): void
    {
        $result = $this->validator()->validate(Payload::fromArray(EasyKashFixture::payload()));

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('easykash', $result->gateway());
        self::assertSame('sha256', $result->contextValue('algorithm'));
    }

    #[Test]
    public function it_concatenates_the_default_field_set_in_order(): void
    {
        $payload = Payload::fromArray(EasyKashFixture::payload());

        self::assertSame(
            'EK-77213250.00EGPFawryPRD-9001PAID',
            $this->validator()->signingString($payload),
        );
    }

    #[Test]
    #[DataProvider('tamperedFieldProvider')]
    public function it_rejects_a_tampered_field(string $field, mixed $value): void
    {
        $payload = EasyKashFixture::payload();
        $payload[$field] = $value;

        $result = $this->validator()->validate(Payload::fromArray($payload));

        self::assertTrue($result->isInvalid(), sprintf('Tampering with [%s] went undetected.', $field));
    }

    /** @return iterable<string, array{string, mixed}> */
    public static function tamperedFieldProvider(): iterable
    {
        yield 'reference' => ['easykashRef', 'EK-00000'];
        yield 'amount' => ['Amount', '1.00'];
        yield 'currency' => ['Currency', 'USD'];
        yield 'payment method' => ['PaymentMethod', 'Card'];
        yield 'product' => ['productCode', 'PRD-0000'];
        yield 'status' => ['status', 'PENDING'];
    }

    #[Test]
    public function an_unsigned_field_does_not_affect_the_signature(): void
    {
        // customerEmail is outside the default signed set; the package must not
        // silently pretend it is protected.
        $payload = EasyKashFixture::payload();
        $payload['customerEmail'] = 'someone.else@example.com';

        self::assertTrue($this->validator()->validate(Payload::fromArray($payload))->isValid());
    }

    #[Test]
    public function it_matches_fields_whatever_their_casing(): void
    {
        $payload = EasyKashFixture::payload();
        $signature = $payload['signature'];

        $lowerCased = ['signature' => $signature];

        foreach ($payload as $key => $value) {
            if ($key !== 'signature') {
                $lowerCased[strtolower($key)] = $value;
            }
        }

        self::assertTrue($this->validator()->validate(Payload::fromArray($lowerCased))->isValid());
    }

    #[Test]
    public function the_signed_field_set_can_be_overridden_per_merchant(): void
    {
        $fields = ['easykashRef', 'Amount', 'status'];

        $data = [
            'easykashRef' => 'EK-77213',
            'Amount' => '250.00',
            'Currency' => 'EGP',
            'PaymentMethod' => 'Fawry',
            'productCode' => 'PRD-9001',
            'status' => 'PAID',
        ];
        $data['signature'] = hash_hmac('sha256', 'EK-77213250.00PAID', EasyKashFixture::SECRET);

        $payload = Payload::fromArray($data);

        self::assertTrue($this->validator($fields)->validate($payload)->isValid());
        self::assertTrue($this->validator()->validate($payload)->isInvalid(), 'the default set must not match');
        self::assertSame($fields, $this->validator($fields)->signedFields());
    }

    #[Test]
    public function the_algorithm_glue_and_signature_field_are_configurable(): void
    {
        $validator = new EasyKashWebhookValidator(
            secret: EasyKashFixture::SECRET,
            signedFields: ['ref', 'amount'],
            algorithm: 'sha512',
            signatureField: 'hash',
            glue: '|',
        );

        $payload = Payload::fromArray([
            'ref' => 'EK-1',
            'amount' => '10',
            'hash' => hash_hmac('sha512', 'EK-1|10', EasyKashFixture::SECRET),
        ]);

        self::assertTrue($validator->validate($payload)->isValid());
    }

    #[Test]
    public function it_finds_the_signature_nested_under_data(): void
    {
        $payload = EasyKashFixture::payload();
        $signature = $payload['signature'];
        unset($payload['signature']);

        $wrapped = Payload::fromArray($payload + ['data' => ['signature' => $signature]]);

        self::assertTrue($this->validator()->validate($wrapped)->isValid());
    }

    #[Test]
    public function it_rejects_a_webhook_with_no_signature(): void
    {
        $payload = EasyKashFixture::payload();
        unset($payload['signature']);

        $result = $this->validator()->validate(Payload::fromArray($payload));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('No signature found', (string) $result->reason());
    }

    #[Test]
    public function it_rejects_an_empty_field_list(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('at least one field');

        new EasyKashWebhookValidator(EasyKashFixture::SECRET, []);
    }

    #[Test]
    public function it_rejects_an_unavailable_algorithm(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('not available');

        new EasyKashWebhookValidator(EasyKashFixture::SECRET, null, 'not-a-real-algorithm');
    }

    #[Test]
    public function the_api_key_channel_accepts_the_configured_token(): void
    {
        $validator = EasyKash::withApiKeyHeader(EasyKashFixture::SECRET, 'the-api-key');

        $payload = Payload::fromArray(['status' => 'PAID'], ['X-Api-Key' => 'the-api-key']);
        $result = $validator->validate($payload);

        self::assertTrue($result->isValid());
        self::assertSame('api_key', $result->contextValue('channel'));
    }

    #[Test]
    public function the_api_key_channel_rejects_a_wrong_token(): void
    {
        $validator = EasyKash::withApiKeyHeader(EasyKashFixture::SECRET, 'the-api-key');

        $payload = Payload::fromArray(['status' => 'PAID'], ['X-Api-Key' => 'guessed']);

        self::assertTrue($validator->validate($payload)->isInvalid());
    }

    #[Test]
    public function the_signature_channel_wins_when_both_are_present(): void
    {
        $validator = EasyKash::withApiKeyHeader(EasyKashFixture::SECRET, 'the-api-key');

        $payload = Payload::fromArray(EasyKashFixture::payload(), ['X-Api-Key' => 'the-api-key']);
        $result = $validator->validate($payload);

        self::assertTrue($result->isValid());
        self::assertSame('signature', $result->contextValue('channel'));
    }

    #[Test]
    public function a_shared_secret_validator_needs_a_non_empty_secret(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        EasyKash::withApiKeyHeader(EasyKashFixture::SECRET, '');
    }

    #[Test]
    public function the_static_factory_builds_a_working_validator(): void
    {
        self::assertTrue(
            EasyKash::validator(EasyKashFixture::SECRET)
                ->validate(Payload::fromArray(EasyKashFixture::payload()))
                ->isValid(),
        );

        self::assertSame(
            ['easykashRef', 'Amount', 'status'],
            EasyKash::validator(EasyKashFixture::SECRET, ['easykashRef', 'Amount', 'status'])->signedFields(),
        );
    }
}
