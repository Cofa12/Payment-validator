<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Support;

use Cofa\PaymentValidator\Support\Secret;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Secret::class)]
final class SecretTest extends TestCase
{
    private const VALUE = 'PLAINTEXT-WEBHOOK-SECRET-9f3a';

    #[Test]
    public function it_gives_the_value_back_to_code_that_asks(): void
    {
        self::assertSame(self::VALUE, (new Secret(self::VALUE))->reveal());
    }

    #[Test]
    public function two_secrets_do_not_share_a_slot(): void
    {
        $a = new Secret('secret-a');
        $b = new Secret('secret-b');

        self::assertSame('secret-a', $a->reveal());
        self::assertSame('secret-b', $b->reveal());
    }

    #[Test]
    public function it_reports_emptiness(): void
    {
        self::assertTrue((new Secret(''))->isEmpty());
        self::assertFalse((new Secret(self::VALUE))->isEmpty());
    }

    #[Test]
    public function casting_to_string_yields_a_redaction(): void
    {
        $secret = new Secret(self::VALUE);

        self::assertSame('********', (string) $secret);
        self::assertStringNotContainsString(self::VALUE, sprintf('%s', $secret));
        self::assertStringNotContainsString(self::VALUE, 'interpolated: ' . $secret);
    }

    #[Test]
    public function print_r_does_not_reveal_it(): void
    {
        self::assertStringNotContainsString(self::VALUE, print_r(new Secret(self::VALUE), true));
    }

    #[Test]
    public function var_export_does_not_reveal_it(): void
    {
        self::assertStringNotContainsString(self::VALUE, var_export(new Secret(self::VALUE), true));
    }

    #[Test]
    public function var_dump_does_not_reveal_it(): void
    {
        ob_start();
        var_dump(new Secret(self::VALUE));
        $dumped = (string) ob_get_clean();

        self::assertStringNotContainsString(self::VALUE, $dumped);
        self::assertStringContainsString('********', $dumped);
    }

    #[Test]
    public function json_encoding_does_not_reveal_it(): void
    {
        self::assertStringNotContainsString(self::VALUE, (string) json_encode(new Secret(self::VALUE)));
        self::assertStringNotContainsString(self::VALUE, (string) json_encode(['key' => new Secret(self::VALUE)]));
    }

    #[Test]
    public function reflection_over_properties_finds_nothing_to_leak(): void
    {
        // Dumpers walk instance properties; a Secret has none to walk.
        $reflection = new \ReflectionObject(new Secret(self::VALUE));

        $instanceProperties = array_filter(
            $reflection->getProperties(),
            static fn (\ReflectionProperty $p): bool => ! $p->isStatic(),
        );

        self::assertSame([], $instanceProperties);
    }

    #[Test]
    public function it_refuses_to_be_serialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('must not be serialised');

        serialize(new Secret(self::VALUE));
    }

    #[Test]
    public function it_refuses_to_be_unserialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('cannot be unserialised');

        $class = Secret::class;

        unserialize(sprintf('O:%d:"%s":0:{}', strlen($class), $class));
    }

    #[Test]
    public function it_survives_garbage_collection_pressure(): void
    {
        // The value lives in a WeakMap keyed by the Secret; as long as the
        // Secret is reachable, so is its value.
        $secret = new Secret(self::VALUE);

        for ($i = 0; $i < 100; $i++) {
            $throwaway = new Secret('throwaway-' . $i);
            unset($throwaway);
        }

        gc_collect_cycles();

        self::assertSame(self::VALUE, $secret->reveal());
    }
}
