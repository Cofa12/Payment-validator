<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Support;

use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\SignatureLocation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(SignatureLocation::class)]
final class SignatureLocationTest extends TestCase
{
    #[Test]
    public function it_finds_a_signature_in_a_nested_field(): void
    {
        $payload = Payload::fromArray(['data' => ['kashierSignature' => 'abc']]);

        self::assertSame('abc', SignatureLocation::field('data.kashierSignature')->locate($payload));
    }

    #[Test]
    public function it_ignores_non_scalar_fields(): void
    {
        $payload = Payload::fromArray(['signature' => ['nested' => 'abc']]);

        self::assertNull(SignatureLocation::field('signature')->locate($payload));
    }

    #[Test]
    public function it_treats_an_empty_value_as_absent(): void
    {
        self::assertNull(SignatureLocation::field('signature')->locate(Payload::fromArray(['signature' => ''])));
    }

    #[Test]
    public function it_finds_and_trims_a_header(): void
    {
        $payload = Payload::fromArray([], ['X-Signature' => "  abc  "]);

        self::assertSame('abc', SignatureLocation::header('x-signature')->locate($payload));
    }

    #[Test]
    public function it_strips_a_scheme_prefix_from_a_header(): void
    {
        $payload = Payload::fromArray([], ['X-Signature' => 'sha256=abc']);

        self::assertSame('abc', SignatureLocation::header('X-Signature', 'sha256=')->locate($payload));
    }

    #[Test]
    public function it_leaves_the_value_alone_when_the_prefix_is_absent(): void
    {
        $payload = Payload::fromArray([], ['X-Signature' => 'abc']);

        self::assertSame('abc', SignatureLocation::header('X-Signature', 'sha256=')->locate($payload));
    }

    #[Test]
    public function first_of_falls_through_to_the_first_non_empty_location(): void
    {
        $location = SignatureLocation::firstOf(
            SignatureLocation::field('signature'),
            SignatureLocation::field('data.signature'),
            SignatureLocation::header('X-Signature'),
        );

        self::assertSame('body', $location->locate(Payload::fromArray(['signature' => 'body'])));
        self::assertSame('nested', $location->locate(Payload::fromArray(['data' => ['signature' => 'nested']])));
        self::assertSame('header', $location->locate(Payload::fromArray([], ['X-Signature' => 'header'])));
        self::assertNull($location->locate(Payload::fromArray([])));
    }

    #[Test]
    public function a_custom_resolver_can_reach_anywhere(): void
    {
        $location = SignatureLocation::custom(
            static fn (Payload $p): ?string => strrev((string) $p->get('reversed')),
            'reversed field',
        );

        self::assertSame('cba', $location->locate(Payload::fromArray(['reversed' => 'abc'])));
        self::assertSame('reversed field', $location->description());
    }

    #[Test]
    public function descriptions_identify_the_location_in_error_messages(): void
    {
        self::assertSame('field:hmac', SignatureLocation::field('hmac')->description());
        self::assertSame('header:X-Sig', SignatureLocation::header('X-Sig')->description());
        self::assertSame(
            'field:a|header:B',
            SignatureLocation::firstOf(SignatureLocation::field('a'), SignatureLocation::header('B'))->description(),
        );
    }
}
