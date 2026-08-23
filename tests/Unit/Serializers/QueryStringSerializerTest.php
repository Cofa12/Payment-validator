<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Serializers;

use Appssquare\PaymentValidator\Serializers\QueryStringSerializer;
use Appssquare\PaymentValidator\Support\Payload;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(QueryStringSerializer::class)]
final class QueryStringSerializerTest extends TestCase
{
    #[Test]
    public function it_preserves_the_order_parameters_arrived_in(): void
    {
        $serializer = new QueryStringSerializer();

        self::assertSame(
            'b=2&a=1',
            $serializer->serialize(Payload::fromQueryString('b=2&a=1')),
        );
    }

    #[Test]
    public function it_drops_excluded_parameters(): void
    {
        $serializer = new QueryStringSerializer(exclude: ['signature', 'mode']);
        $payload = Payload::fromQueryString('a=1&mode=test&b=2&signature=deadbeef');

        self::assertSame('a=1&b=2', $serializer->serialize($payload));
    }

    #[Test]
    public function it_can_sort_keys_for_gateways_that_sign_alphabetically(): void
    {
        $serializer = new QueryStringSerializer(sortKeys: true);

        self::assertSame('a=1&b=2&c=3', $serializer->serialize(Payload::fromQueryString('c=3&a=1&b=2')));
    }

    #[Test]
    public function only_mode_pins_both_the_key_set_and_the_order(): void
    {
        $serializer = new QueryStringSerializer(only: ['amount', 'currency']);
        $payload = Payload::fromQueryString('currency=EGP&extra=ignored&amount=250');

        self::assertSame('amount=250&currency=EGP', $serializer->serialize($payload));
    }

    #[Test]
    public function only_mode_encodes_absent_keys_as_empty(): void
    {
        $serializer = new QueryStringSerializer(only: ['amount', 'missing']);

        self::assertSame('amount=250&missing=', $serializer->serialize(Payload::fromArray(['amount' => '250'])));
    }

    #[Test]
    public function it_url_encodes_values(): void
    {
        $serializer = new QueryStringSerializer();
        $payload = Payload::fromArray(['email' => 'a b@example.com', 'ref' => 'A/B']);

        self::assertSame('email=a+b%40example.com&ref=A%2FB', $serializer->serialize($payload));
    }

    #[Test]
    public function it_can_use_rfc3986_encoding(): void
    {
        $serializer = new QueryStringSerializer(encoding: PHP_QUERY_RFC3986);

        self::assertSame('name=a%20b', $serializer->serialize(Payload::fromArray(['name' => 'a b'])));
    }

    #[Test]
    public function it_spells_booleans_the_json_way_rather_than_as_one_and_zero(): void
    {
        $serializer = new QueryStringSerializer();
        $payload = Payload::fromArray(['ok' => true, 'failed' => false, 'nested' => ['x' => true]]);

        self::assertSame('ok=true&failed=false&nested%5Bx%5D=true', $serializer->serialize($payload));
    }

    #[Test]
    public function it_can_prefix_the_encoded_string(): void
    {
        $serializer = new QueryStringSerializer(prefix: '/?');

        self::assertSame('/?a=1', $serializer->serialize(Payload::fromArray(['a' => 1])));
    }
}
