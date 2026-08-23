<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Serializers;

use Cofa\PaymentValidator\Serializers\DefaultValueNormalizer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DefaultValueNormalizer::class)]
final class DefaultValueNormalizerTest extends TestCase
{
    #[Test]
    #[DataProvider('valueProvider')]
    public function it_renders_values_the_way_gateways_sign_them(mixed $value, string $expected): void
    {
        self::assertSame($expected, (new DefaultValueNormalizer())->normalize($value, 'field'));
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function valueProvider(): iterable
    {
        yield 'null becomes empty' => [null, ''];
        yield 'true' => [true, 'true'];
        yield 'false' => [false, 'false'];
        yield 'string passes through' => ['EGP', 'EGP'];
        yield 'empty string' => ['', ''];
        yield 'integer' => [10000, '10000'];
        yield 'negative integer' => [-1, '-1'];
        yield 'zero' => [0, '0'];
        yield 'float with decimals' => [10.5, '10.5'];
        yield 'integral float loses its point' => [100.0, '100'];
        yield 'small float' => [0.01, '0.01'];
        yield 'nan is empty' => [NAN, ''];
        yield 'infinity is empty' => [INF, ''];
        yield 'list' => [[1, 2], '[1,2]'];
        yield 'map' => [['a' => 1], '{"a":1}'];
        yield 'slashes are not escaped' => [['url' => 'a/b'], '{"url":"a/b"}'];
        yield 'resources become empty' => [STDIN, ''];
    }

    #[Test]
    public function it_stringifies_stringable_objects(): void
    {
        $value = new class implements \Stringable {
            public function __toString(): string
            {
                return 'ORD-1';
            }
        };

        self::assertSame('ORD-1', (new DefaultValueNormalizer())->normalize($value, 'order'));
    }

    #[Test]
    public function plain_objects_render_as_empty_rather_than_throwing(): void
    {
        self::assertSame('', (new DefaultValueNormalizer())->normalize(new \stdClass(), 'field'));
    }

    #[Test]
    public function numeric_boolean_mode_matches_form_encoded_gateways(): void
    {
        $normalizer = DefaultValueNormalizer::numericBooleans();

        self::assertSame('1', $normalizer->normalize(true, 'flag'));
        self::assertSame('0', $normalizer->normalize(false, 'flag'));
    }

    #[Test]
    public function every_rendering_is_configurable(): void
    {
        $normalizer = new DefaultValueNormalizer(trueValue: 'Y', falseValue: 'N', nullValue: 'NULL');

        self::assertSame('Y', $normalizer->normalize(true, 'f'));
        self::assertSame('N', $normalizer->normalize(false, 'f'));
        self::assertSame('NULL', $normalizer->normalize(null, 'f'));
    }
}
