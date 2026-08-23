<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Registry;

use Appssquare\PaymentValidator\Contracts\SignatureValidator;
use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;
use Appssquare\PaymentValidator\Exceptions\UnsupportedGatewayException;
use Appssquare\PaymentValidator\Gateways\Paymob\Paymob;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\ValidationResult;
use Appssquare\PaymentValidator\Tests\Fixtures\PaymobFixture;
use Appssquare\PaymentValidator\ValidatorRegistry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ValidatorRegistry::class)]
#[CoversClass(UnsupportedGatewayException::class)]
#[CoversClass(InvalidConfigurationException::class)]
final class ValidatorRegistryTest extends TestCase
{
    private function stub(string $gateway, bool $supports = true): SignatureValidator
    {
        return new class($gateway, $supports) implements SignatureValidator {
            public function __construct(private string $name, private bool $supports)
            {
            }

            public function gateway(): string
            {
                return $this->name;
            }

            public function supports(Payload $payload): bool
            {
                return $this->supports;
            }

            public function validate(Payload $payload): ValidationResult
            {
                return ValidationResult::valid($this->name);
            }
        };
    }

    #[Test]
    public function it_stores_and_returns_a_validator(): void
    {
        $registry = new ValidatorRegistry();
        $validator = $this->stub('paymob');

        $registry->register('paymob', $validator);

        self::assertTrue($registry->has('paymob'));
        self::assertSame($validator, $registry->get('paymob'));
        self::assertSame(['paymob'], $registry->names());
    }

    #[Test]
    #[DataProvider('gatewayNameProvider')]
    public function gateway_names_are_matched_loosely(string $registered, string $requested): void
    {
        $registry = new ValidatorRegistry();
        $registry->register($registered, $this->stub('x'));

        self::assertTrue($registry->has($requested));
    }

    /** @return iterable<string, array{string, string}> */
    public static function gatewayNameProvider(): iterable
    {
        yield 'exact' => ['paymob', 'paymob'];
        yield 'different case' => ['PayMob', 'paymob'];
        yield 'upper case request' => ['paymob', 'PAYMOB'];
        yield 'padded' => ['paymob', '  paymob  '];
        yield 'hyphenated' => ['hyper-pay', 'hyper_pay'];
        yield 'spaced' => ['hyper pay', 'hyper_pay'];
    }

    #[Test]
    public function it_resolves_a_factory_lazily_and_only_once(): void
    {
        $registry = new ValidatorRegistry();
        $calls = 0;

        $registry->register('paymob', function () use (&$calls): SignatureValidator {
            $calls++;

            return $this->stub('paymob');
        });

        self::assertSame(0, $calls, 'registration alone must not build the validator');

        $first = $registry->get('paymob');
        $second = $registry->get('paymob');

        self::assertSame(1, $calls);
        self::assertSame($first, $second);
    }

    #[Test]
    public function a_lazy_gateway_counts_as_registered_before_it_is_resolved(): void
    {
        $registry = new ValidatorRegistry();
        $registry->register('paymob', fn (): SignatureValidator => $this->stub('paymob'));

        self::assertTrue($registry->has('paymob'));
        self::assertSame(['paymob'], $registry->names());
    }

    #[Test]
    public function re_registering_replaces_the_previous_validator(): void
    {
        $registry = new ValidatorRegistry();
        $replacement = $this->stub('replacement');

        $registry->register('paymob', $this->stub('original'));
        $registry->register('paymob', $replacement);

        self::assertSame($replacement, $registry->get('paymob'));
        self::assertSame(['paymob'], $registry->names());
    }

    #[Test]
    public function an_alias_points_at_the_canonical_gateway(): void
    {
        $registry = new ValidatorRegistry();
        $validator = $this->stub('hyperpay');

        $registry->register('hyperpay', $validator)->alias('hyper-pay', 'hyperpay');

        self::assertTrue($registry->has('hyper-pay'));
        self::assertSame($validator, $registry->get('hyper-pay'));
        self::assertSame(['hyperpay'], $registry->names(), 'aliases are not separate gateways');
    }

    #[Test]
    public function forgetting_a_gateway_removes_it_and_its_aliases(): void
    {
        $registry = new ValidatorRegistry();
        $registry->register('hyperpay', $this->stub('hyperpay'))->alias('hyper-pay', 'hyperpay');

        $registry->forget('hyperpay');

        self::assertFalse($registry->has('hyperpay'));
        self::assertFalse($registry->has('hyper-pay'));
        self::assertSame([], $registry->names());
    }

    #[Test]
    public function it_lists_gateways_alphabetically(): void
    {
        $registry = new ValidatorRegistry();
        $registry->register('paymob', $this->stub('paymob'));
        $registry->register('easykash', fn (): SignatureValidator => $this->stub('easykash'));
        $registry->register('kashier', $this->stub('kashier'));

        self::assertSame(['easykash', 'kashier', 'paymob'], $registry->names());
    }

    #[Test]
    public function requesting_an_unregistered_gateway_names_the_ones_that_exist(): void
    {
        $registry = new ValidatorRegistry();
        $registry->register('paymob', $this->stub('paymob'));

        try {
            $registry->get('stripe');
            self::fail('Expected an UnsupportedGatewayException.');
        } catch (UnsupportedGatewayException $e) {
            self::assertStringContainsString('[stripe]', $e->getMessage());
            self::assertStringContainsString('paymob', $e->getMessage());
        }
    }

    #[Test]
    public function an_empty_gateway_name_is_rejected(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        (new ValidatorRegistry())->register('  ', $this->stub('x'));
    }

    #[Test]
    public function a_factory_returning_the_wrong_type_is_rejected(): void
    {
        $registry = new ValidatorRegistry();
        $registry->register('broken', static fn (): string => 'not a validator');

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('must return');

        $registry->get('broken');
    }

    #[Test]
    public function it_detects_which_gateway_a_payload_belongs_to(): void
    {
        $registry = new ValidatorRegistry();
        $registry->register('paymob', Paymob::validator(PaymobFixture::SECRET));
        $registry->register('nothing', $this->stub('nothing', supports: false));

        $payload = Payload::fromArray(PaymobFixture::transactionWebhook());

        self::assertSame('paymob', $registry->detect($payload));
    }

    #[Test]
    public function detection_returns_null_when_nothing_recognises_the_payload(): void
    {
        $registry = new ValidatorRegistry();
        $registry->register('paymob', Paymob::validator(PaymobFixture::SECRET));

        self::assertNull($registry->detect(Payload::fromArray(['unrelated' => true])));
    }
}
