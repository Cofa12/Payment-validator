<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Serializers;

use Cofa\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa\PaymentValidator\Serializers\DefaultValueNormalizer;
use Cofa\PaymentValidator\Support\Payload;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(ConcatenatedFieldSerializer::class)]
#[CoversClass(DefaultValueNormalizer::class)]
final class ConcatenatedFieldSerializerTest extends TestCase
{
    #[Test]
    public function it_concatenates_fields_in_the_declared_order(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['b', 'a', 'c']);

        self::assertSame('213', $serializer->serialize(Payload::fromArray(['a' => 1, 'b' => 2, 'c' => 3])));
    }

    #[Test]
    public function it_honours_a_glue_string(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['a', 'b'], '|');

        self::assertSame('1|2', $serializer->serialize(Payload::fromArray(['a' => 1, 'b' => 2])));
    }

    #[Test]
    public function it_resolves_aliases_in_priority_order(): void
    {
        $serializer = new ConcatenatedFieldSerializer([['obj.order.id', 'order.id', 'order']]);

        self::assertSame('1', $serializer->serialize(Payload::fromArray(['obj' => ['order' => ['id' => 1]]])));
        self::assertSame('2', $serializer->serialize(Payload::fromArray(['order' => ['id' => 2]])));
        self::assertSame('3', $serializer->serialize(Payload::fromArray(['order' => 3])));
    }

    #[Test]
    public function it_renders_booleans_the_way_json_spells_them(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['yes', 'no']);

        self::assertSame('truefalse', $serializer->serialize(Payload::fromArray(['yes' => true, 'no' => false])));
    }

    #[Test]
    public function it_renders_null_and_missing_fields_as_empty(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['a', 'missing', 'b']);

        self::assertSame('xy', $serializer->serialize(Payload::fromArray(['a' => 'x', 'missing' => null, 'b' => 'y'])));
    }

    #[Test]
    public function it_accepts_an_alternative_normalizer(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['flag'], '', DefaultValueNormalizer::numericBooleans());

        self::assertSame('1', $serializer->serialize(Payload::fromArray(['flag' => true])));
    }

    #[Test]
    public function it_reports_fields_the_payload_does_not_carry(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['present', 'absent', ['x', 'y']]);

        self::assertSame(
            ['absent', 'x|y'],
            $serializer->missingFields(Payload::fromArray(['present' => 1])),
        );
    }

    #[Test]
    public function a_present_null_does_not_count_as_missing(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['owner']);

        self::assertSame([], $serializer->missingFields(Payload::fromArray(['owner' => null])));
    }

    #[Test]
    public function case_insensitive_mode_matches_differently_cased_keys(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['Amount', 'Status'], '', null, caseInsensitive: true);
        $payload = Payload::fromArray(['amount' => '250.00', 'STATUS' => 'PAID']);

        self::assertSame('250.00PAID', $serializer->serialize($payload));
        self::assertSame([], $serializer->missingFields($payload));
    }

    #[Test]
    public function case_sensitive_mode_is_the_default(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['Amount']);

        self::assertSame(['Amount'], $serializer->missingFields(Payload::fromArray(['amount' => '250.00'])));
    }

    #[Test]
    public function it_exposes_its_field_list(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['a', ['b', 'c']]);

        self::assertSame(['a', ['b', 'c']], $serializer->fields());
    }

    #[Test]
    public function it_json_encodes_array_values_deterministically(): void
    {
        $serializer = new ConcatenatedFieldSerializer(['meta']);

        self::assertSame(
            '{"a":1}',
            $serializer->serialize(Payload::fromArray(['meta' => ['a' => 1]])),
        );
    }
}
