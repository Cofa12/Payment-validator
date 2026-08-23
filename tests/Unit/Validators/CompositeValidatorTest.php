<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Validators;

use Appssquare\PaymentValidator\Contracts\SignatureValidator;
use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\ValidationResult;
use Appssquare\PaymentValidator\Validators\CompositeValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(CompositeValidator::class)]
final class CompositeValidatorTest extends TestCase
{
    private function channel(string $name, bool $supports, bool $valid): SignatureValidator
    {
        return new class($name, $supports, $valid) implements SignatureValidator {
            public function __construct(
                private string $name,
                private bool $supports,
                private bool $valid,
            ) {
            }

            public function gateway(): string
            {
                return 'demo';
            }

            public function supports(Payload $payload): bool
            {
                return $this->supports;
            }

            public function validate(Payload $payload): ValidationResult
            {
                return $this->valid
                    ? ValidationResult::valid('demo', ['from' => $this->name])
                    : ValidationResult::invalid('demo', $this->name . ' says no');
            }
        };
    }

    #[Test]
    public function it_returns_the_result_of_the_channel_that_validates(): void
    {
        $composite = new CompositeValidator('demo', [
            'a' => $this->channel('a', supports: true, valid: false),
            'b' => $this->channel('b', supports: true, valid: true),
        ]);

        $result = $composite->validate(Payload::fromArray([]));

        self::assertTrue($result->isValid());
        self::assertSame('b', $result->contextValue('channel'));
        self::assertSame('demo', $result->contextValue('gateway'));
    }

    #[Test]
    public function it_skips_channels_that_do_not_recognise_the_payload(): void
    {
        $composite = new CompositeValidator('demo', [
            'wrong_shape' => $this->channel('wrong_shape', supports: false, valid: true),
            'right_shape' => $this->channel('right_shape', supports: true, valid: true),
        ]);

        self::assertSame('right_shape', $composite->validate(Payload::fromArray([]))->contextValue('channel'));
    }

    #[Test]
    public function it_reports_every_channel_it_tried_when_all_of_them_fail(): void
    {
        $composite = new CompositeValidator('demo', [
            'a' => $this->channel('a', supports: true, valid: false),
            'b' => $this->channel('b', supports: true, valid: false),
        ]);

        $result = $composite->validate(Payload::fromArray([]));

        self::assertTrue($result->isInvalid());
        self::assertSame(['a', 'b'], $result->contextValue('attempted_channels'));
        self::assertSame(['a' => 'a says no', 'b' => 'b says no'], $result->contextValue('channel_reasons'));
    }

    #[Test]
    public function it_says_so_when_no_channel_recognises_the_payload(): void
    {
        $composite = new CompositeValidator('demo', [
            'a' => $this->channel('a', supports: false, valid: true),
        ]);

        $result = $composite->validate(Payload::fromArray([]));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('did not match any known [demo] callback channel', (string) $result->reason());
        self::assertSame(['a'], $result->contextValue('channels'));
    }

    #[Test]
    public function it_supports_a_payload_when_any_channel_does(): void
    {
        $none = new CompositeValidator('demo', ['a' => $this->channel('a', supports: false, valid: true)]);
        $some = new CompositeValidator('demo', [
            'a' => $this->channel('a', supports: false, valid: true),
            'b' => $this->channel('b', supports: true, valid: true),
        ]);

        self::assertFalse($none->supports(Payload::fromArray([])));
        self::assertTrue($some->supports(Payload::fromArray([])));
    }

    #[Test]
    public function individual_channels_can_be_addressed_by_name(): void
    {
        $channel = $this->channel('a', supports: true, valid: true);
        $composite = new CompositeValidator('demo', ['a' => $channel]);

        self::assertSame('demo', $composite->gateway());
        self::assertSame(['a' => $channel], $composite->channels());
        self::assertSame($channel, $composite->channel('a'));
    }

    #[Test]
    public function addressing_an_unknown_channel_lists_the_real_ones(): void
    {
        $composite = new CompositeValidator('demo', ['a' => $this->channel('a', true, true)]);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Available: a.');

        $composite->channel('nope');
    }

    #[Test]
    public function a_composite_needs_at_least_one_channel(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        new CompositeValidator('demo', []);
    }
}
