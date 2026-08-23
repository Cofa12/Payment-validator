<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Support;

use Cofa\PaymentValidator\Exceptions\InvalidPayloadException;
use Cofa\PaymentValidator\Support\Payload;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Payload::class)]
final class PayloadTest extends TestCase
{
    #[Test]
    public function it_reads_nested_values_with_dot_notation(): void
    {
        $payload = Payload::fromArray(['obj' => ['source_data' => ['pan' => '2346']]]);

        self::assertSame('2346', $payload->get('obj.source_data.pan'));
        self::assertTrue($payload->has('obj.source_data.pan'));
    }

    #[Test]
    public function it_prefers_a_literal_dotted_key_over_traversal(): void
    {
        // Gateways that flatten their callbacks send keys that contain dots.
        $payload = Payload::fromArray([
            'source_data.pan' => 'literal',
            'source_data' => ['pan' => 'nested'],
        ]);

        self::assertSame('literal', $payload->get('source_data.pan'));
    }

    #[Test]
    public function it_returns_the_default_for_missing_keys(): void
    {
        $payload = Payload::fromArray(['a' => ['b' => 1]]);

        self::assertNull($payload->get('a.b.c.d'));
        self::assertSame('fallback', $payload->get('missing', 'fallback'));
        self::assertFalse($payload->has('missing'));
    }

    #[Test]
    public function it_treats_a_present_null_as_existing(): void
    {
        $payload = Payload::fromArray(['owner' => null]);

        self::assertTrue($payload->has('owner'));
        self::assertNull($payload->get('owner'));
    }

    #[Test]
    public function it_resolves_the_first_present_key_from_a_list(): void
    {
        $payload = Payload::fromArray(['order' => '99']);

        self::assertSame('99', $payload->getFirst(['obj.order.id', 'order.id', 'order']));
        self::assertSame('none', $payload->getFirst(['x', 'y'], 'none'));
    }

    #[Test]
    public function it_can_look_keys_up_case_insensitively(): void
    {
        $payload = Payload::fromArray(['Amount' => '250.00']);

        self::assertSame('250.00', $payload->getInsensitive('amount'));
        self::assertSame('250.00', $payload->getInsensitive('Amount'));
        self::assertNull($payload->getInsensitive('total'));
    }

    #[Test]
    #[DataProvider('headerNameProvider')]
    public function it_matches_headers_regardless_of_style(string $sent, string $requested): void
    {
        $payload = Payload::fromArray([], [$sent => 'value']);

        self::assertSame('value', $payload->header($requested));
    }

    /** @return iterable<string, array{string, string}> */
    public static function headerNameProvider(): iterable
    {
        yield 'exact' => ['X-Authentication-Tag', 'X-Authentication-Tag'];
        yield 'lower cased' => ['x-authentication-tag', 'X-Authentication-Tag'];
        yield 'upper cased' => ['X-AUTHENTICATION-TAG', 'x-authentication-tag'];
        yield 'server style' => ['HTTP_X_AUTHENTICATION_TAG', 'X-Authentication-Tag'];
        yield 'underscored' => ['X_Authentication_Tag', 'x-authentication-tag'];
    }

    #[Test]
    public function it_takes_the_first_value_of_a_repeated_header(): void
    {
        $payload = Payload::fromArray([], ['X-Signature' => ['first', 'second']]);

        self::assertSame('first', $payload->header('X-Signature'));
    }

    #[Test]
    public function it_returns_null_for_an_absent_header(): void
    {
        self::assertNull(Payload::fromArray([])->header('X-Missing'));
        self::assertSame('d', Payload::fromArray([])->header('X-Missing', 'd'));
    }

    #[Test]
    public function it_preserves_the_raw_body_when_decoding_json(): void
    {
        $json = '{"type":"TRANSACTION","obj":{"id":1}}';
        $payload = Payload::fromJson($json);

        self::assertSame($json, $payload->rawBody());
        self::assertSame('TRANSACTION', $payload->get('type'));
        self::assertSame(1, $payload->get('obj.id'));
    }

    #[Test]
    public function it_rejects_malformed_json(): void
    {
        $this->expectException(InvalidPayloadException::class);

        Payload::fromJson('{not json');
    }

    #[Test]
    public function it_rejects_json_that_is_not_an_object_or_array(): void
    {
        $this->expectException(InvalidPayloadException::class);

        Payload::fromJson('"just a string"');
    }

    #[Test]
    public function it_parses_query_strings_and_tolerates_a_leading_question_mark(): void
    {
        $payload = Payload::fromQueryString('?success=true&amount_cents=10000');

        self::assertSame('true', $payload->get('success'));
        self::assertSame('10000', $payload->get('amount_cents'));
    }

    #[Test]
    public function it_reflects_php_rewriting_dots_in_query_parameter_names(): void
    {
        // parse_str() turns `source_data.pan` into `source_data_pan`; validators
        // must alias both spellings, so this behaviour is pinned here.
        $payload = Payload::fromQueryString('source_data.pan=2346');

        self::assertSame('2346', $payload->get('source_data_pan'));
        self::assertFalse($payload->has('source_data.pan'));
    }

    #[Test]
    public function it_builds_from_a_raw_body_that_is_not_json(): void
    {
        $payload = Payload::fromRawBody('deadbeef', ['X-Iv' => 'aa']);

        self::assertSame([], $payload->all());
        self::assertSame('deadbeef', $payload->rawBody());
        self::assertSame('aa', $payload->header('X-Iv'));
    }

    #[Test]
    public function it_scopes_into_a_sub_tree_while_keeping_headers_and_raw_body(): void
    {
        $payload = Payload::fromJson('{"data":{"amount":250}}', ['X-Test' => '1']);
        $scoped = $payload->scope('data');

        self::assertSame(250, $scoped->get('amount'));
        self::assertSame('1', $scoped->header('X-Test'));
        self::assertSame('{"data":{"amount":250}}', $scoped->rawBody());
    }

    #[Test]
    public function scoping_a_missing_or_scalar_key_yields_an_empty_payload(): void
    {
        $payload = Payload::fromArray(['data' => 'scalar']);

        self::assertSame([], $payload->scope('data')->all());
        self::assertSame([], $payload->scope('nope')->all());
    }

    #[Test]
    public function it_copies_without_and_only_selected_keys(): void
    {
        $payload = Payload::fromArray(['a' => 1, 'b' => 2, 'c' => 3]);

        self::assertSame(['a' => 1, 'c' => 3], $payload->without('b')->all());
        self::assertSame(['c' => 3, 'a' => 1], $payload->only('c', 'a')->all());
        self::assertSame(['a' => 1, 'b' => 2, 'c' => 3], $payload->all(), 'the original must not change');
    }

    #[Test]
    public function it_merges_headers_immutably(): void
    {
        $payload = Payload::fromArray([], ['X-One' => '1']);
        $extended = $payload->withHeaders(['X-Two' => '2']);

        self::assertNull($payload->header('X-Two'));
        self::assertSame('1', $extended->header('X-One'));
        self::assertSame('2', $extended->header('X-Two'));
    }

    #[Test]
    public function it_reports_emptiness(): void
    {
        self::assertTrue(Payload::fromArray([])->isEmpty());
        self::assertFalse(Payload::fromArray(['a' => 1])->isEmpty());
        self::assertFalse(Payload::fromRawBody('body')->isEmpty());
    }

    #[Test]
    public function it_exposes_all_headers_normalised(): void
    {
        $payload = Payload::fromArray([], ['HTTP_X_ONE' => '1', 'X-Two' => '2']);

        self::assertSame(['x-one' => '1', 'x-two' => '2'], $payload->headers());
    }

    #[Test]
    public function it_swaps_the_data_while_keeping_headers_and_raw_body(): void
    {
        $payload = Payload::fromJson('{"a":1}', ['X-One' => '1']);
        $swapped = $payload->withData(['b' => 2]);

        self::assertSame(['b' => 2], $swapped->all());
        self::assertSame('1', $swapped->header('X-One'));
        self::assertSame('{"a":1}', $swapped->rawBody());
        self::assertSame(['a' => 1], $payload->all(), 'the original must not change');
    }

    #[Test]
    public function non_scalar_header_values_collapse_to_empty(): void
    {
        $payload = Payload::fromArray([], ['X-Weird' => new \stdClass()]);

        self::assertSame('', $payload->header('X-Weird'));
    }
}
