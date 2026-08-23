<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Registry;

use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;
use Appssquare\PaymentValidator\Exceptions\SignatureMismatchException;
use Appssquare\PaymentValidator\Exceptions\UnsupportedGatewayException;
use Appssquare\PaymentValidator\GatewayFactory;
use Appssquare\PaymentValidator\PaymentValidator;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Tests\Fixtures\EasyKashFixture;
use Appssquare\PaymentValidator\Tests\Fixtures\HyperPayFixture;
use Appssquare\PaymentValidator\Tests\Fixtures\KashierFixture;
use Appssquare\PaymentValidator\Tests\Fixtures\PaymobFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PaymentValidator::class)]
#[CoversClass(GatewayFactory::class)]
final class PaymentValidatorTest extends TestCase
{
    private function validator(): PaymentValidator
    {
        return PaymentValidator::fromConfig([
            'paymob' => ['hmac' => PaymobFixture::SECRET],
            'kashier' => ['api_key' => KashierFixture::API_KEY],
            'easykash' => ['secret' => EasyKashFixture::SECRET],
            'hyperpay' => ['decryption_key' => HyperPayFixture::KEY],
        ]);
    }

    #[Test]
    public function it_registers_every_configured_gateway(): void
    {
        self::assertSame(['easykash', 'hyperpay', 'kashier', 'paymob'], $this->validator()->gateways());
    }

    #[Test]
    public function it_validates_a_paymob_callback_end_to_end(): void
    {
        $json = json_encode(PaymobFixture::transactionWebhook(), JSON_THROW_ON_ERROR);

        self::assertTrue($this->validator()->validate('paymob', Payload::fromJson($json))->isValid());
    }

    #[Test]
    public function it_validates_a_kashier_webhook_end_to_end(): void
    {
        self::assertTrue($this->validator()->isValid('kashier', KashierFixture::webhook()));
    }

    #[Test]
    public function it_validates_an_easykash_webhook_end_to_end(): void
    {
        self::assertTrue($this->validator()->isValid('easykash', EasyKashFixture::payload()));
    }

    #[Test]
    public function it_validates_a_hyperpay_webhook_end_to_end(): void
    {
        $encrypted = HyperPayFixture::encrypted();

        $result = $this->validator()->validate(
            'hyperpay',
            $encrypted['body'],
            HyperPayFixture::headers($encrypted['iv'], $encrypted['tag']),
        );

        self::assertTrue($result->isValid(), (string) $result->reason());
    }

    #[Test]
    public function a_raw_string_payload_is_decoded_as_a_body(): void
    {
        $json = json_encode(PaymobFixture::transactionWebhook(), JSON_THROW_ON_ERROR);

        self::assertTrue($this->validator()->isValid('paymob', $json));
    }

    #[Test]
    public function an_array_payload_is_accepted_with_headers(): void
    {
        $webhook = KashierFixture::webhook();
        $signature = $webhook['data']['kashierSignature'];
        unset($webhook['data']['kashierSignature']);

        self::assertTrue($this->validator()->isValid('kashier', $webhook, ['x-kashier-signature' => $signature]));
    }

    #[Test]
    public function assert_valid_throws_on_a_forged_payload(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        $webhook['obj']['amount_cents'] = 1;

        $this->expectException(SignatureMismatchException::class);
        $this->expectExceptionMessage('[paymob]');

        $this->validator()->assertValid('paymob', $webhook);
    }

    #[Test]
    public function assert_valid_returns_the_result_on_success(): void
    {
        $result = $this->validator()->assertValid('paymob', PaymobFixture::transactionWebhook());

        self::assertTrue($result->isValid());
    }

    #[Test]
    public function an_unknown_gateway_raises_rather_than_returning_false(): void
    {
        // Silently returning "invalid" for a typo'd gateway name would hide a
        // configuration bug behind what looks like a rejected payment.
        $this->expectException(UnsupportedGatewayException::class);

        $this->validator()->validate('paypal', []);
    }

    #[Test]
    public function configuration_errors_surface_only_when_the_gateway_is_used(): void
    {
        $validator = PaymentValidator::fromConfig([
            'paymob' => ['hmac' => PaymobFixture::SECRET],
            'kashier' => ['nothing_useful' => true],
        ]);

        self::assertTrue($validator->isValid('paymob', PaymobFixture::transactionWebhook()));

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('api_key');

        $validator->validator('kashier');
    }

    #[Test]
    public function non_array_configuration_entries_are_skipped(): void
    {
        $validator = PaymentValidator::fromConfig([
            'paymob' => ['hmac' => PaymobFixture::SECRET],
            'kashier' => 'oops-a-string',
        ]);

        self::assertSame(['paymob'], $validator->gateways());
    }

    #[Test]
    public function it_detects_the_gateway_a_payload_came_from(): void
    {
        $validator = $this->validator();
        $encrypted = HyperPayFixture::encrypted();

        self::assertSame('paymob', $validator->detect(PaymobFixture::transactionWebhook()));
        self::assertSame('kashier', $validator->detect(KashierFixture::webhook()));
        self::assertSame(
            'hyperpay',
            $validator->detect($encrypted['body'], HyperPayFixture::headers($encrypted['iv'], $encrypted['tag'])),
        );
        self::assertNull($validator->detect(['nothing' => 'recognisable']));
    }

    #[Test]
    public function config_keys_have_forgiving_aliases(): void
    {
        $validator = PaymentValidator::fromConfig([
            'paymob' => ['hmac_secret' => PaymobFixture::SECRET],
            'kashier' => ['payment_api_key' => KashierFixture::API_KEY],
            'easykash' => ['secret_key' => EasyKashFixture::SECRET],
            'hyperpay' => ['webhook_key' => HyperPayFixture::KEY],
        ]);

        self::assertTrue($validator->isValid('paymob', PaymobFixture::transactionWebhook()));
        self::assertTrue($validator->isValid('kashier', KashierFixture::webhook()));
        self::assertTrue($validator->isValid('easykash', EasyKashFixture::payload()));
    }

    #[Test]
    public function kashier_redirect_exclusions_can_be_configured(): void
    {
        $validator = PaymentValidator::fromConfig([
            'kashier' => ['api_key' => KashierFixture::API_KEY, 'exclude' => ['lang']],
        ]);

        $query = KashierFixture::redirectQueryString(unsignedExtras: ['lang' => 'ar']);

        self::assertTrue($validator->isValid('kashier', Payload::fromQueryString($query)));
    }

    #[Test]
    public function easykash_signed_fields_can_be_configured(): void
    {
        $validator = PaymentValidator::fromConfig([
            'easykash' => [
                'secret' => EasyKashFixture::SECRET,
                'fields' => ['easykashRef', 'Amount', 'status'],
            ],
        ]);

        $data = [
            'easykashRef' => 'EK-1',
            'Amount' => '10.00',
            'status' => 'PAID',
            'signature' => hash_hmac('sha256', 'EK-110.00PAID', EasyKashFixture::SECRET),
        ];

        self::assertTrue($validator->isValid('easykash', $data));
    }

    #[Test]
    public function easykash_can_be_configured_with_both_channels(): void
    {
        $validator = PaymentValidator::fromConfig([
            'easykash' => [
                'secret' => EasyKashFixture::SECRET,
                'api_key' => 'header-token',
                'api_key_header' => 'X-EasyKash-Token',
            ],
        ]);

        self::assertTrue($validator->isValid('easykash', EasyKashFixture::payload()));
        self::assertTrue($validator->isValid('easykash', ['status' => 'PAID'], ['X-EasyKash-Token' => 'header-token']));
        self::assertFalse($validator->isValid('easykash', ['status' => 'PAID'], ['X-EasyKash-Token' => 'wrong']));
    }

    #[Test]
    public function the_gateway_factory_lists_what_it_can_build(): void
    {
        self::assertSame(['easykash', 'hyperpay', 'kashier', 'paymob'], (new GatewayFactory())->supported());
        self::assertTrue((new GatewayFactory())->supports('PAYMOB'));
        self::assertFalse((new GatewayFactory())->supports('stripe'));
    }

    #[Test]
    public function the_factory_rejects_an_unknown_gateway(): void
    {
        $this->expectException(UnsupportedGatewayException::class);

        (new GatewayFactory())->make('stripe', ['secret' => 'x']);
    }

    #[Test]
    public function it_answers_which_gateways_it_knows(): void
    {
        $validator = $this->validator();

        self::assertTrue($validator->has('paymob'));
        self::assertTrue($validator->has('PAYMOB'));
        self::assertFalse($validator->has('stripe'));
    }

    #[Test]
    public function it_exposes_the_underlying_registry_for_advanced_wiring(): void
    {
        $validator = $this->validator();

        self::assertSame($validator->gateways(), $validator->registry()->names());

        $validator->registry()->alias('paymob-eg', 'paymob');

        self::assertTrue($validator->has('paymob-eg'));
        self::assertTrue($validator->isValid('paymob-eg', PaymobFixture::transactionWebhook()));
    }

    #[Test]
    public function it_hands_back_the_validator_instance_for_a_gateway(): void
    {
        $validator = $this->validator();

        self::assertSame('paymob', $validator->validator('paymob')->gateway());
        self::assertSame('hyperpay', $validator->validator('hyperpay')->gateway());
    }
}
