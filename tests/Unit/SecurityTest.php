<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit;

use Cofa\PaymentValidator\Contracts\SignatureValidator;
use Cofa\PaymentValidator\Gateways\EasyKash\EasyKashWebhookValidator;
use Cofa\PaymentValidator\Gateways\Fawry\FawryNotificationValidator;
use Cofa\PaymentValidator\Gateways\Kashier\KashierWebhookValidator;
use Cofa\PaymentValidator\Gateways\Paymob\PaymobTransactionValidator;
use Cofa\PaymentValidator\Gateways\PayTabs\PayTabsReturnValidator;
use Cofa\PaymentValidator\PaymentValidator;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Tests\Fixtures\EasyKashFixture;
use Cofa\PaymentValidator\Tests\Fixtures\FawryFixture;
use Cofa\PaymentValidator\Tests\Fixtures\HyperPayFixture;
use Cofa\PaymentValidator\Tests\Fixtures\KashierFixture;
use Cofa\PaymentValidator\Tests\Fixtures\PayPalFixture;
use Cofa\PaymentValidator\Tests\Fixtures\PaymobFixture;
use Cofa\PaymentValidator\Tests\Fixtures\PayTabsFixture;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Properties that must hold for every gateway, whatever its scheme.
 *
 * These are the failure modes that turn a signature check into decoration:
 * loose comparison, secrets in logs, a forged payload accepted because a field
 * was absent rather than wrong.
 */
#[CoversNothing]
final class SecurityTest extends TestCase
{
    private function validator(): PaymentValidator
    {
        return PaymentValidator::fromConfig([
            'paymob' => ['hmac' => PaymobFixture::SECRET],
            'kashier' => ['api_key' => KashierFixture::API_KEY],
            'easykash' => ['secret' => EasyKashFixture::SECRET],
            'hyperpay' => ['decryption_key' => HyperPayFixture::KEY],
            'fawry' => ['secure_key' => FawryFixture::SECURE_KEY],
            'paytabs' => ['server_key' => PayTabsFixture::SERVER_KEY],
            'paypal' => ['webhook_id' => PayPalFixture::WEBHOOK_ID],
        ]);
    }

    /** @return iterable<string, array{string, callable(string): array{0: SignatureValidator|string, 1: Payload}}> */
    public static function hmacGatewayProvider(): iterable
    {
        yield 'paymob' => ['paymob'];
        yield 'kashier' => ['kashier'];
        yield 'easykash' => ['easykash'];
        yield 'fawry' => ['fawry'];
        yield 'paytabs' => ['paytabs'];
    }

    /** A genuine, valid payload for the named gateway. */
    private static function genuinePayload(string $gateway): Payload
    {
        return match ($gateway) {
            'paymob' => Payload::fromArray(PaymobFixture::transactionWebhook()),
            'kashier' => Payload::fromArray(KashierFixture::webhook()),
            'easykash' => Payload::fromArray(EasyKashFixture::payload()),
            'fawry' => Payload::fromArray(FawryFixture::notification()),
            'paytabs' => Payload::fromArray(PayTabsFixture::returnPost()),
        };
    }

    /** The same payload with its signature replaced by `$signature`. */
    private static function payloadWithSignature(string $gateway, mixed $signature): Payload
    {
        return match ($gateway) {
            'paymob' => Payload::fromArray(
                array_replace(PaymobFixture::transactionWebhook(), ['hmac' => $signature]),
            ),
            'kashier' => (static function () use ($signature): Payload {
                $webhook = KashierFixture::webhook();
                $webhook['data']['kashierSignature'] = $signature;

                return Payload::fromArray($webhook);
            })(),
            'easykash' => Payload::fromArray(
                array_replace(EasyKashFixture::payload(), ['signature' => $signature]),
            ),
            'fawry' => Payload::fromArray(
                array_replace(FawryFixture::notification(), ['messageSignature' => $signature]),
            ),
            'paytabs' => Payload::fromArray(
                array_replace(PayTabsFixture::returnPost(), ['signature' => $signature]),
            ),
        };
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function the_control_payload_is_genuinely_valid(string $gateway): void
    {
        // Guards the negative tests below: if this ever fails, they prove nothing.
        self::assertTrue($this->validator()->validate($gateway, self::genuinePayload($gateway))->isValid());
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function it_rejects_an_empty_or_whitespace_signature(string $gateway): void
    {
        foreach (['', '   ', "\n", "\0"] as $signature) {
            self::assertTrue(
                $this->validator()->validate($gateway, self::payloadWithSignature($gateway, $signature))->isInvalid(),
                sprintf('[%s] accepted a blank signature.', $gateway),
            );
        }
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function it_rejects_a_signature_that_is_a_prefix_of_the_real_one(string $gateway): void
    {
        $genuine = self::genuinePayload($gateway);
        $real = (string) $this->realSignature($gateway, $genuine);

        foreach ([substr($real, 0, 8), substr($real, 0, -1), $real . '0'] as $signature) {
            self::assertTrue(
                $this->validator()->validate($gateway, self::payloadWithSignature($gateway, $signature))->isInvalid(),
                sprintf('[%s] accepted a truncated or extended signature.', $gateway),
            );
        }
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function it_does_not_fall_for_php_loose_comparison(string $gateway): void
    {
        // `'0e1234' == '0e5678'` is true under `==`. Anything comparing with ==
        // instead of hash_equals() would accept these.
        foreach (['0', '0e0', '0e12345678901234567890', 'true', '1'] as $signature) {
            self::assertTrue(
                $this->validator()->validate($gateway, self::payloadWithSignature($gateway, $signature))->isInvalid(),
                sprintf('[%s] accepted a type-juggling signature.', $gateway),
            );
        }
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function it_rejects_a_non_string_signature_without_erroring(string $gateway): void
    {
        foreach ([null, [], ['nested' => 'x'], new \stdClass()] as $signature) {
            $result = $this->validator()->validate($gateway, self::payloadWithSignature($gateway, $signature));

            self::assertTrue($result->isInvalid(), sprintf('[%s] accepted a non-string signature.', $gateway));
        }
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function it_rejects_an_absurdly_long_signature_without_erroring(string $gateway): void
    {
        $result = $this->validator()->validate($gateway, self::payloadWithSignature($gateway, str_repeat('a', 100_000)));

        self::assertTrue($result->isInvalid());
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function a_result_never_carries_the_secret_or_the_expected_signature(string $gateway): void
    {
        // Results get logged. Anything that would let a reader forge the next
        // callback must not be in them.
        $genuine = self::genuinePayload($gateway);
        $expected = (string) $this->realSignature($gateway, $genuine);

        foreach ([$this->validator()->validate($gateway, $genuine),
                  $this->validator()->validate($gateway, self::payloadWithSignature($gateway, 'forged'))] as $result) {
            $serialised = json_encode($result->toArray(), JSON_THROW_ON_ERROR);

            self::assertStringNotContainsString($expected, $serialised);
            self::assertStringNotContainsString(PaymobFixture::SECRET, $serialised);
            self::assertStringNotContainsString(KashierFixture::API_KEY, $serialised);
            self::assertStringNotContainsString(EasyKashFixture::SECRET, $serialised);
        }
    }

    /**
     * Every key the suite configures, so a new gateway cannot quietly opt out
     * of the leak assertions.
     *
     * @return list<string>
     */
    private static function everySecret(): array
    {
        return [
            PaymobFixture::SECRET,
            KashierFixture::API_KEY,
            EasyKashFixture::SECRET,
            FawryFixture::SECURE_KEY,
            PayTabsFixture::SERVER_KEY,
        ];
    }

    #[Test]
    public function an_exception_message_never_carries_the_secret(): void
    {
        $webhook = PaymobFixture::transactionWebhook();
        $webhook['obj']['amount_cents'] = 1;

        try {
            $this->validator()->assertValid('paymob', $webhook);
            self::fail('Expected the forged payload to be rejected.');
        } catch (\Throwable $e) {
            self::assertStringNotContainsString(PaymobFixture::SECRET, $e->getMessage());
        }
    }

    #[Test]
    #[DataProvider('dumpFunctionProvider')]
    public function no_dump_of_a_configured_validator_exposes_its_secret(string $label, callable $dump): void
    {
        // Dumping a container-resolved service onto an error page is the most
        // common way a webhook secret escapes into a log.
        $validator = $this->validator();

        foreach ($validator->gateways() as $gateway) {
            $dumped = (string) $dump($validator->validator($gateway));

            foreach (self::everySecret() as $secret) {
                self::assertStringNotContainsString(
                    $secret,
                    $dumped,
                    sprintf('%s() of the [%s] validator leaked a secret.', $label, $gateway),
                );
            }

            // HyperPay's key is hex, and is decoded to raw bytes internally.
            self::assertStringNotContainsString(HyperPayFixture::KEY, $dumped);
            self::assertStringNotContainsString((string) hex2bin(HyperPayFixture::KEY), $dumped);
        }
    }

    /** @return iterable<string, array{string, callable}> */
    public static function dumpFunctionProvider(): iterable
    {
        yield 'print_r' => ['print_r', static fn (object $o): string => print_r($o, true)];
        yield 'var_export' => ['var_export', static fn (object $o): string => var_export($o, true)];
        yield 'json_encode' => ['json_encode', static fn (object $o): string => (string) json_encode($o)];
        yield 'var_dump' => ['var_dump', static function (object $o): string {
            ob_start();
            var_dump($o);

            return (string) ob_get_clean();
        }];
    }

    #[Test]
    public function a_stack_trace_does_not_expose_a_secret(): void
    {
        // #[\SensitiveParameter] on every constructor keeps the key out of the
        // argument list PHP renders in a trace.
        try {
            new PaymobTransactionValidator('');
            self::fail('Expected the empty secret to be rejected.');
        } catch (\Throwable $e) {
            self::assertStringNotContainsString(PaymobFixture::SECRET, $e->getTraceAsString());
        }

        $trace = (new \Exception())->getTraceAsString();

        self::assertStringNotContainsString(PaymobFixture::SECRET, $trace);
    }

    #[Test]
    #[DataProvider('hmacGatewayProvider')]
    public function it_rejects_a_payload_signed_with_a_different_merchant_secret(string $gateway): void
    {
        $foreign = PaymentValidator::fromConfig([
            'paymob' => ['hmac' => 'another-merchants-secret'],
            'kashier' => ['api_key' => 'another-merchants-secret'],
            'easykash' => ['secret' => 'another-merchants-secret'],
            'fawry' => ['secure_key' => 'another-merchants-secret'],
            'paytabs' => ['server_key' => 'another-merchants-secret'],
        ]);

        self::assertTrue($foreign->validate($gateway, self::genuinePayload($gateway))->isInvalid());
    }

    #[Test]
    public function stripping_a_signed_field_does_not_make_a_payload_valid(): void
    {
        // Removing a field must change the signed string, never be treated as
        // "nothing to check here".
        $webhook = PaymobFixture::transactionWebhook();
        unset($webhook['obj']['success'], $webhook['obj']['amount_cents']);

        self::assertTrue($this->validator()->validate('paymob', $webhook)->isInvalid());
    }

    #[Test]
    public function an_entirely_empty_payload_is_rejected_by_every_gateway(): void
    {
        $validator = $this->validator();

        foreach ($validator->gateways() as $gateway) {
            self::assertTrue(
                $validator->validate($gateway, [])->isInvalid(),
                sprintf('[%s] accepted an empty payload.', $gateway),
            );
        }
    }

    #[Test]
    public function every_built_in_validator_uses_a_modern_hash(): void
    {
        $algorithms = [
            (new PaymobTransactionValidator('secret'))->validate(self::genuinePayload('paymob')),
            (new KashierWebhookValidator('secret'))->validate(self::genuinePayload('kashier')),
            (new EasyKashWebhookValidator('secret'))->validate(self::genuinePayload('easykash')),
            (new FawryNotificationValidator('secret'))->validate(self::genuinePayload('fawry')),
            (new PayTabsReturnValidator('secret'))->validate(self::genuinePayload('paytabs')),
        ];

        foreach ($algorithms as $result) {
            self::assertContains($result->contextValue('algorithm'), ['sha256', 'sha512']);
        }
    }

    #[Test]
    public function hyperpay_rejects_a_replayed_body_under_a_stale_nonce(): void
    {
        $first = HyperPayFixture::encrypted();
        $second = HyperPayFixture::encrypted();

        // Pair one message's ciphertext with the other's nonce and tag.
        $result = $this->validator()->validate(
            'hyperpay',
            $first['body'],
            HyperPayFixture::headers($second['iv'], $second['tag']),
        );

        self::assertTrue($result->isInvalid());
    }

    private function realSignature(string $gateway, Payload $payload): string
    {
        return match ($gateway) {
            'paymob' => (string) $payload->get('hmac'),
            'kashier' => (string) $payload->get('data.kashierSignature'),
            'easykash' => (string) $payload->get('signature'),
            'fawry' => (string) $payload->get('messageSignature'),
            'paytabs' => (string) $payload->get('signature'),
        };
    }
}
