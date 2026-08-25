<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Gateways;

use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Gateways\PayTabs\PayTabs;
use Cofa\PaymentValidator\Gateways\PayTabs\PayTabsCallbackValidator;
use Cofa\PaymentValidator\Gateways\PayTabs\PayTabsReturnValidator;
use Cofa\PaymentValidator\Serializers\QueryStringSerializer;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Tests\Fixtures\PayTabsFixture;
use Cofa\PaymentValidator\Validators\AbstractHmacValidator;
use Cofa\PaymentValidator\Validators\CompositeValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(PayTabsCallbackValidator::class)]
#[CoversClass(PayTabsReturnValidator::class)]
#[CoversClass(PayTabs::class)]
#[CoversClass(AbstractHmacValidator::class)]
#[CoversClass(QueryStringSerializer::class)]
final class PayTabsTest extends TestCase
{
    private function callbackValidator(): PayTabsCallbackValidator
    {
        return new PayTabsCallbackValidator(PayTabsFixture::SERVER_KEY);
    }

    private function returnValidator(): PayTabsReturnValidator
    {
        return new PayTabsReturnValidator(PayTabsFixture::SERVER_KEY);
    }

    private function callbackPayload(?string $body = null, array $headerOverrides = []): Payload
    {
        $callback = PayTabsFixture::callback($body);

        return Payload::fromJson($callback['body'], array_replace($callback['headers'], $headerOverrides));
    }

    #[Test]
    public function it_accepts_a_genuine_callback(): void
    {
        $result = $this->callbackValidator()->validate($this->callbackPayload());

        self::assertTrue($result->isValid(), (string) $result->reason());
        self::assertSame('paytabs', $result->gateway());
        self::assertSame('sha256', $result->contextValue('algorithm'));
    }

    #[Test]
    public function the_callback_signature_covers_the_raw_body_verbatim(): void
    {
        $callback = PayTabsFixture::callback();

        self::assertSame(
            $callback['headers']['signature'],
            $this->callbackValidator()->sign(Payload::fromJson($callback['body'], $callback['headers'])),
        );
    }

    #[Test]
    public function a_re_encoded_body_no_longer_verifies(): void
    {
        // The point of RawBodySerializer: decoding and re-encoding reorders keys
        // and restyles numbers, and PayTabs signed the bytes it sent.
        $callback = PayTabsFixture::callback();
        $reordered = json_encode(
            array_reverse(json_decode($callback['body'], true), true),
            JSON_THROW_ON_ERROR,
        );

        $result = $this->callbackValidator()->validate(Payload::fromJson($reordered, $callback['headers']));

        self::assertTrue($result->isInvalid());
    }

    #[Test]
    public function it_rejects_a_callback_body_that_was_altered_in_transit(): void
    {
        // Signed genuine, then rewritten on the wire — what a proxy or a
        // man-in-the-middle actually produces.
        $callback = PayTabsFixture::callback();
        $tampered = str_replace('"250.00"', '"1.00"', $callback['body']);

        self::assertNotSame($callback['body'], $tampered);

        $result = $this->callbackValidator()->validate(Payload::fromJson($tampered, $callback['headers']));

        self::assertTrue($result->isInvalid());
    }

    #[Test]
    public function it_rejects_a_callback_signed_with_another_server_key(): void
    {
        $body = (string) json_encode(PayTabsFixture::callbackBody());
        $payload = Payload::fromJson($body, [
            'signature' => PayTabsFixture::bodySignature($body, 'another-merchants-server-key'),
        ]);

        self::assertTrue($this->callbackValidator()->validate($payload)->isInvalid());
    }

    #[Test]
    public function it_rejects_a_callback_with_no_signature_header(): void
    {
        $body = (string) json_encode(PayTabsFixture::callbackBody());
        $result = $this->callbackValidator()->validate(Payload::fromJson($body));

        self::assertTrue($result->isInvalid());
        self::assertStringContainsString('No signature found', (string) $result->reason());
    }

    #[Test]
    public function it_reads_the_signature_header_whatever_its_casing(): void
    {
        $callback = PayTabsFixture::callback();

        foreach (['Signature', 'SIGNATURE', 'HTTP_SIGNATURE'] as $name) {
            $payload = Payload::fromJson($callback['body'], [$name => $callback['headers']['signature']]);

            self::assertTrue(
                $this->callbackValidator()->validate($payload)->isValid(),
                sprintf('The [%s] header was not recognised.', $name),
            );
        }
    }

    #[Test]
    public function a_signature_header_without_a_body_is_not_claimed(): void
    {
        // Nothing to hash: reporting "no channel matched" beats a mismatch that
        // sends the reader hunting for a key problem.
        $payload = Payload::fromArray(['tran_ref' => 'X'], ['signature' => str_repeat('a', 64)]);

        self::assertFalse($this->callbackValidator()->supports($payload));
    }

    #[Test]
    public function it_accepts_a_genuine_browser_return(): void
    {
        $result = $this->returnValidator()->validate(Payload::fromArray(PayTabsFixture::returnPost()));

        self::assertTrue($result->isValid(), (string) $result->reason());
    }

    #[Test]
    public function the_return_signing_string_is_sorted_filtered_and_url_encoded(): void
    {
        // Transcribed from PayTabs' own sample: signature dropped, falsy values
        // dropped (respCode "0" and the empty token among them), keys sorted.
        self::assertSame(
            'cartAmount=250.00&cartCurrency=SAR&cartDesc=Order+ORD-2024-001&cartId=ORD-2024-001'
            . '&customerEmail=customer%40example.com&respMessage=Authorised&respStatus=A'
            . '&tranRef=TST2405012345678&tranType=Sale',
            $this->returnValidator()->signingString(Payload::fromArray(PayTabsFixture::returnPost())),
        );
    }

    #[Test]
    public function it_accepts_the_return_delivered_as_a_query_string(): void
    {
        $query = http_build_query(PayTabsFixture::returnPost());

        self::assertTrue($this->returnValidator()->validate(Payload::fromQueryString($query))->isValid());
    }

    #[Test]
    #[DataProvider('tamperedReturnFieldProvider')]
    public function it_rejects_a_tampered_return_field(string $field, string $value): void
    {
        $post = PayTabsFixture::returnPost();
        $post[$field] = $value;

        $result = $this->returnValidator()->validate(Payload::fromArray($post));

        self::assertTrue($result->isInvalid(), sprintf('Tampering with [%s] went undetected.', $field));
    }

    /** @return iterable<string, array{string, string}> */
    public static function tamperedReturnFieldProvider(): iterable
    {
        yield 'amount reduced' => ['cartAmount', '1.00'];
        yield 'declined promoted to authorised' => ['respStatus', 'D'];
        yield 'different cart' => ['cartId', 'ORD-2024-999'];
        yield 'different transaction' => ['tranRef', 'TST0000000000000'];
        yield 'different currency' => ['cartCurrency', 'USD'];
    }

    #[Test]
    public function adding_an_unsigned_field_to_the_return_is_caught(): void
    {
        // http_build_query would include it, so the string changes — unless the
        // merchant declares it excluded.
        $post = PayTabsFixture::returnPost(unsignedExtras: ['utm_source' => 'newsletter']);

        self::assertTrue($this->returnValidator()->validate(Payload::fromArray($post))->isInvalid());

        $tolerant = new PayTabsReturnValidator(PayTabsFixture::SERVER_KEY, ['utm_source']);

        self::assertTrue($tolerant->validate(Payload::fromArray($post))->isValid());
    }

    #[Test]
    public function a_field_whose_value_is_string_zero_is_dropped_before_signing(): void
    {
        // array_filter() drops "0" as well as "". Surprising, but it is the rule
        // PayTabs signs by, so changing respCode from "0" to "00" must change
        // the signature.
        $post = PayTabsFixture::returnPost();

        self::assertStringNotContainsString('respCode', $this->returnValidator()->signingString(
            Payload::fromArray($post),
        ));

        $changed = PayTabsFixture::returnPost(['respCode' => '00']);

        self::assertStringContainsString('respCode=00', $this->returnValidator()->signingString(
            Payload::fromArray($changed),
        ));
        self::assertTrue($this->returnValidator()->validate(Payload::fromArray($changed))->isValid());
    }

    #[Test]
    public function the_return_channel_does_not_claim_another_gateways_redirect(): void
    {
        // A bare `signature` field is not enough; without it, a shared endpoint
        // would hand Kashier's redirect to PayTabs or the reverse.
        $foreign = Payload::fromArray(['paymentStatus' => 'SUCCESS', 'signature' => str_repeat('b', 64)]);

        self::assertFalse($this->returnValidator()->supports($foreign));
        self::assertTrue($this->returnValidator()->supports(Payload::fromArray(PayTabsFixture::returnPost())));
    }

    #[Test]
    public function the_two_channels_do_not_answer_for_each_other(): void
    {
        $callback = $this->callbackPayload();
        $return = Payload::fromArray(PayTabsFixture::returnPost());

        self::assertTrue($this->callbackValidator()->supports($callback));
        self::assertFalse($this->callbackValidator()->supports($return));

        self::assertTrue($this->returnValidator()->supports($return));
        self::assertFalse($this->returnValidator()->supports($callback));
    }

    #[Test]
    public function the_composite_routes_each_callback_to_its_channel(): void
    {
        $validator = PayTabs::validator(PayTabsFixture::SERVER_KEY);

        self::assertInstanceOf(CompositeValidator::class, $validator);

        $callback = $validator->validate($this->callbackPayload());
        self::assertTrue($callback->isValid(), (string) $callback->reason());
        self::assertSame('callback', $callback->contextValue('channel'));

        $return = $validator->validate(Payload::fromArray(PayTabsFixture::returnPost()));
        self::assertTrue($return->isValid(), (string) $return->reason());
        self::assertSame('return', $return->contextValue('channel'));
    }

    #[Test]
    public function it_refuses_to_be_built_without_a_server_key(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('non-empty secret');

        new PayTabsCallbackValidator('   ');
    }
}
