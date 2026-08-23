<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Serializers;

use Appssquare\PaymentValidator\Serializers\RawBodySerializer;
use Appssquare\PaymentValidator\Serializers\TemplateSerializer;
use Appssquare\PaymentValidator\Support\Payload;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(TemplateSerializer::class)]
#[CoversClass(RawBodySerializer::class)]
final class TemplateSerializerTest extends TestCase
{
    #[Test]
    public function it_fills_placeholders_from_the_payload(): void
    {
        $serializer = new TemplateSerializer('/?payment={merchantId}.{orderId}.{amount}.{currency}');
        $payload = Payload::fromArray([
            'merchantId' => 'MID-99',
            'orderId' => 'ORD-1',
            'amount' => '250.00',
            'currency' => 'EGP',
        ]);

        self::assertSame('/?payment=MID-99.ORD-1.250.00.EGP', $serializer->serialize($payload));
    }

    #[Test]
    public function placeholders_support_dot_notation(): void
    {
        $serializer = new TemplateSerializer('{obj.order.id}-{obj.currency}');
        $payload = Payload::fromArray(['obj' => ['order' => ['id' => 7], 'currency' => 'EGP']]);

        self::assertSame('7-EGP', $serializer->serialize($payload));
    }

    #[Test]
    public function missing_placeholders_become_empty_strings(): void
    {
        $serializer = new TemplateSerializer('a={a}&b={b}');

        self::assertSame('a=1&b=', $serializer->serialize(Payload::fromArray(['a' => 1])));
    }

    #[Test]
    public function text_that_is_not_a_placeholder_is_left_alone(): void
    {
        $serializer = new TemplateSerializer('literal {not a placeholder} {a}');

        self::assertSame('literal {not a placeholder} 1', $serializer->serialize(Payload::fromArray(['a' => 1])));
    }

    #[Test]
    public function it_lists_its_placeholders(): void
    {
        $serializer = new TemplateSerializer('{a}{b}{a}');

        self::assertSame(['a', 'b'], $serializer->placeholders());
    }

    #[Test]
    public function the_raw_body_serializer_returns_the_body_verbatim(): void
    {
        $json = '{"b":2,"a":1}';

        self::assertSame($json, (new RawBodySerializer())->serialize(Payload::fromJson($json)));
    }

    #[Test]
    public function the_raw_body_serializer_can_wrap_the_body(): void
    {
        $serializer = new RawBodySerializer(prefix: 'v1:', suffix: ':end');

        self::assertSame('v1:body:end', $serializer->serialize(Payload::fromRawBody('body')));
    }

    #[Test]
    public function the_raw_body_serializer_tolerates_an_absent_body(): void
    {
        self::assertSame('', (new RawBodySerializer())->serialize(Payload::fromArray(['a' => 1])));
    }
}
