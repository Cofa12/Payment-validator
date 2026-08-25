<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Serializers;

use Cofa\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Cofa\PaymentValidator\Serializers\DecimalAmountNormalizer;
use Cofa\PaymentValidator\Serializers\DefaultValueNormalizer;
use Cofa\PaymentValidator\Support\Payload;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DecimalAmountNormalizer::class)]
final class DecimalAmountNormalizerTest extends TestCase
{
    private function normalizer(): DecimalAmountNormalizer
    {
        return new DecimalAmountNormalizer(['amount', 'paymentAmount']);
    }

    #[Test]
    #[DataProvider('amountProvider')]
    public function it_restores_two_decimals_on_a_money_field(mixed $value, string $expected): void
    {
        self::assertSame($expected, $this->normalizer()->normalize($value, 'amount'));
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function amountProvider(): iterable
    {
        // The whole reason this class exists: json_decode('250.00') is 250.0,
        // and (string) 250.0 is "250".
        yield 'float that lost its decimals' => [250.0, '250.00'];
        yield 'integer' => [250, '250.00'];
        yield 'numeric string already formatted' => ['250.00', '250.00'];
        yield 'numeric string without decimals' => ['250', '250.00'];
        yield 'one decimal place' => [250.5, '250.50'];
        yield 'zero' => [0.0, '0.00'];
        yield 'negative refund' => [-12.5, '-12.50'];
        yield 'rounded up' => [10.005, '10.01'];
        yield 'thousands get no separator' => [1234567.0, '1234567.00'];
    }

    #[Test]
    public function it_leaves_fields_it_was_not_told_about_alone(): void
    {
        self::assertSame('250', $this->normalizer()->normalize(250.0, 'fawryFees'));
    }

    #[Test]
    public function a_missing_amount_stays_empty_rather_than_becoming_zero(): void
    {
        // "" and "0.00" are different signing strings. Substituting one for the
        // other would let a malformed callback verify against the wrong total.
        self::assertSame('', $this->normalizer()->normalize(null, 'amount'));
        self::assertSame('', $this->normalizer()->normalize('', 'amount'));
    }

    #[Test]
    public function a_non_numeric_amount_falls_through_untouched(): void
    {
        self::assertSame('N/A', $this->normalizer()->normalize('N/A', 'amount'));
        self::assertSame('true', $this->normalizer()->normalize(true, 'amount'));
    }

    #[Test]
    public function it_matches_a_field_declared_with_aliases(): void
    {
        // ConcatenatedFieldSerializer labels an aliased field `a|b`.
        self::assertSame('250.00', $this->normalizer()->normalize(250.0, 'obj.amount|amount'));
    }

    #[Test]
    public function it_matches_the_leaf_of_a_dotted_path(): void
    {
        self::assertSame('250.00', $this->normalizer()->normalize(250.0, 'order.totals.amount'));
    }

    #[Test]
    public function the_number_of_decimals_is_configurable(): void
    {
        $threeDecimals = new DecimalAmountNormalizer(['amount'], 3);

        self::assertSame('250.000', $threeDecimals->normalize(250.0, 'amount'));

        $whole = new DecimalAmountNormalizer(['amount'], 0);

        self::assertSame('251', $whole->normalize(250.5, 'amount'));
    }

    #[Test]
    public function it_delegates_every_other_field_to_the_normalizer_it_wraps(): void
    {
        $numericBooleans = new DecimalAmountNormalizer(['amount'], 2, DefaultValueNormalizer::numericBooleans());

        self::assertSame('1', $numericBooleans->normalize(true, 'success'));
        self::assertSame('250.00', $numericBooleans->normalize(250.0, 'amount'));
    }

    #[Test]
    public function it_slots_into_a_concatenated_field_serializer(): void
    {
        $serializer = new ConcatenatedFieldSerializer(
            fields: ['ref', 'amount', 'status'],
            normalizer: new DecimalAmountNormalizer(['amount']),
        );

        self::assertSame(
            'R-1250.00PAID',
            $serializer->serialize(Payload::fromArray(['ref' => 'R-1', 'amount' => 250.0, 'status' => 'PAID'])),
        );
    }
}
