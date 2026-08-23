<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Unit\Support;

use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;
use Appssquare\PaymentValidator\Support\AesGcmDecryptor;
use Appssquare\PaymentValidator\Tests\Fixtures\HyperPayFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AesGcmDecryptor::class)]
final class AesGcmDecryptorTest extends TestCase
{
    #[Test]
    public function it_round_trips_a_payload(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $decryptor = new AesGcmDecryptor(HyperPayFixture::KEY);

        self::assertSame(
            $encrypted['plaintext'],
            $decryptor->decrypt($encrypted['body'], $encrypted['iv'], $encrypted['tag']),
        );
    }

    #[Test]
    #[DataProvider('keySizeProvider')]
    public function it_selects_the_cipher_from_the_key_length(int $bytes, string $cipher): void
    {
        $decryptor = new AesGcmDecryptor(bin2hex(str_repeat('k', $bytes)));

        self::assertSame($cipher, $decryptor->cipher());
    }

    /** @return iterable<string, array{int, string}> */
    public static function keySizeProvider(): iterable
    {
        yield 'aes-128' => [16, 'aes-128-gcm'];
        yield 'aes-192' => [24, 'aes-192-gcm'];
        yield 'aes-256' => [32, 'aes-256-gcm'];
    }

    #[Test]
    public function it_rejects_a_non_hex_key(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('hex-encoded');

        new AesGcmDecryptor('not-hex-at-all!!');
    }

    #[Test]
    public function it_rejects_a_key_of_the_wrong_size(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('16, 24 or 32 bytes');

        new AesGcmDecryptor(bin2hex('too short'));
    }

    #[Test]
    public function it_refuses_a_tampered_ciphertext(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $decryptor = new AesGcmDecryptor(HyperPayFixture::KEY);

        // Flip one hex nibble: GCM's tag must catch it.
        $body = $encrypted['body'];
        $body[0] = $body[0] === 'a' ? 'b' : 'a';

        self::assertNull($decryptor->decrypt($body, $encrypted['iv'], $encrypted['tag']));
    }

    #[Test]
    public function it_refuses_a_tampered_authentication_tag(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $decryptor = new AesGcmDecryptor(HyperPayFixture::KEY);

        $tag = $encrypted['tag'];
        $tag[0] = $tag[0] === 'a' ? 'b' : 'a';

        self::assertNull($decryptor->decrypt($encrypted['body'], $encrypted['iv'], $tag));
    }

    #[Test]
    public function it_refuses_the_wrong_key(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $decryptor = new AesGcmDecryptor(bin2hex(str_repeat('x', 32)));

        self::assertNull($decryptor->decrypt($encrypted['body'], $encrypted['iv'], $encrypted['tag']));
    }

    #[Test]
    public function it_refuses_a_replayed_payload_under_a_different_nonce(): void
    {
        $encrypted = HyperPayFixture::encrypted();
        $decryptor = new AesGcmDecryptor(HyperPayFixture::KEY);

        self::assertNull($decryptor->decrypt($encrypted['body'], bin2hex(random_bytes(12)), $encrypted['tag']));
    }

    #[Test]
    #[DataProvider('malformedInputProvider')]
    public function it_returns_null_for_malformed_hex_rather_than_erroring(string $body, string $iv, string $tag): void
    {
        $decryptor = new AesGcmDecryptor(HyperPayFixture::KEY);

        self::assertNull($decryptor->decrypt($body, $iv, $tag));
    }

    /** @return iterable<string, array{string, string, string}> */
    public static function malformedInputProvider(): iterable
    {
        $valid = HyperPayFixture::encrypted();

        yield 'odd length body' => ['abc', $valid['iv'], $valid['tag']];
        yield 'non hex body' => ['zzzz', $valid['iv'], $valid['tag']];
        yield 'non hex iv' => [$valid['body'], 'zzzz', $valid['tag']];
        yield 'non hex tag' => [$valid['body'], $valid['iv'], 'zzzz'];
        yield 'empty iv' => [$valid['body'], '', $valid['tag']];
        yield 'tag too short' => [$valid['body'], $valid['iv'], 'aabb'];
        yield 'tag too long' => [$valid['body'], $valid['iv'], str_repeat('ab', 20)];
    }
}
