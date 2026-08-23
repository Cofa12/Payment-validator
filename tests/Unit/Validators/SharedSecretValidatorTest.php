<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Validators;

use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\SignatureLocation;
use Cofa\PaymentValidator\Validators\SharedSecretValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(SharedSecretValidator::class)]
final class SharedSecretValidatorTest extends TestCase
{
    private function validator(): SharedSecretValidator
    {
        return new SharedSecretValidator('demo', 'the-token', SignatureLocation::header('X-Token'));
    }

    #[Test]
    public function it_accepts_the_configured_token(): void
    {
        $result = $this->validator()->validate(Payload::fromArray([], ['X-Token' => 'the-token']));

        self::assertTrue($result->isValid());
        self::assertSame('demo', $result->gateway());
        self::assertSame('demo', $this->validator()->gateway());
        self::assertSame('shared_secret', $result->contextValue('method'));
    }

    #[Test]
    public function it_tolerates_surrounding_whitespace(): void
    {
        self::assertTrue($this->validator()->validate(Payload::fromArray([], ['X-Token' => ' the-token ']))->isValid());
    }

    #[Test]
    public function it_rejects_a_wrong_token(): void
    {
        $result = $this->validator()->validate(Payload::fromArray([], ['X-Token' => 'guessed']));

        self::assertTrue($result->isInvalid());
        self::assertSame('The presented shared secret is incorrect.', $result->reason());
    }

    #[Test]
    public function it_rejects_a_token_that_merely_starts_correctly(): void
    {
        self::assertTrue($this->validator()->validate(Payload::fromArray([], ['X-Token' => 'the-tok']))->isInvalid());
        self::assertTrue($this->validator()->validate(Payload::fromArray([], ['X-Token' => 'the-token2']))->isInvalid());
    }

    #[Test]
    public function it_reports_where_it_looked_when_nothing_was_presented(): void
    {
        $result = $this->validator()->validate(Payload::fromArray([]));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('header:X-Token', (string) $result->reason());
    }

    #[Test]
    public function it_supports_only_requests_that_present_something(): void
    {
        self::assertTrue($this->validator()->supports(Payload::fromArray([], ['X-Token' => 'anything'])));
        self::assertFalse($this->validator()->supports(Payload::fromArray([])));
    }

    #[Test]
    public function it_can_read_the_token_from_a_body_field(): void
    {
        $validator = new SharedSecretValidator('demo', 'the-token', SignatureLocation::field('auth.token'));

        self::assertTrue($validator->validate(Payload::fromArray(['auth' => ['token' => 'the-token']]))->isValid());
    }

    #[Test]
    public function it_needs_a_non_empty_secret(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('non-empty secret');

        new SharedSecretValidator('demo', '  ', SignatureLocation::header('X-Token'));
    }
}
