<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Support;

use Cofa\PaymentValidator\Exceptions\SignatureMismatchException;
use Cofa\PaymentValidator\Support\ValidationResult;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ValidationResult::class)]
#[CoversClass(SignatureMismatchException::class)]
final class ValidationResultTest extends TestCase
{
    #[Test]
    public function a_valid_result_carries_no_reason(): void
    {
        $result = ValidationResult::valid('paymob', ['algorithm' => 'sha512']);

        self::assertTrue($result->isValid());
        self::assertFalse($result->isInvalid());
        self::assertSame('paymob', $result->gateway());
        self::assertNull($result->reason());
        self::assertSame('sha512', $result->contextValue('algorithm'));
        self::assertNull($result->contextValue('absent'));
    }

    #[Test]
    public function an_invalid_result_explains_itself(): void
    {
        $result = ValidationResult::invalid('kashier', 'nope', ['signature_keys' => ['amount']]);

        self::assertTrue($result->isInvalid());
        self::assertSame('nope', $result->reason());
        self::assertSame(['signature_keys' => ['amount']], $result->context());
    }

    #[Test]
    public function throw_if_invalid_is_a_no_op_on_success(): void
    {
        $result = ValidationResult::valid('paymob');

        self::assertSame($result, $result->throwIfInvalid());
    }

    #[Test]
    public function throw_if_invalid_raises_with_the_result_attached(): void
    {
        $result = ValidationResult::invalid('paymob', 'signature mismatch');

        try {
            $result->throwIfInvalid();
            self::fail('Expected a SignatureMismatchException.');
        } catch (SignatureMismatchException $e) {
            self::assertSame($result, $e->result());
            self::assertSame('paymob', $e->gateway());
            self::assertSame('signature mismatch', $e->reason());
            self::assertStringContainsString('[paymob]', $e->getMessage());
            self::assertStringContainsString('signature mismatch', $e->getMessage());
        }
    }

    #[Test]
    public function context_can_be_extended_without_mutating_the_original(): void
    {
        $result = ValidationResult::valid('paymob', ['a' => 1]);
        $extended = $result->withContext(['b' => 2]);

        self::assertSame(['a' => 1], $result->context());
        self::assertSame(['a' => 1, 'b' => 2], $extended->context());
        self::assertTrue($extended->isValid());
    }

    #[Test]
    public function it_converts_to_an_array_for_logging(): void
    {
        self::assertSame([
            'valid' => false,
            'gateway' => 'easykash',
            'reason' => 'bad',
            'context' => [],
        ], ValidationResult::invalid('easykash', 'bad')->toArray());
    }
}
