<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Unit\Support;

use Cofa\PaymentValidator\Support\RemoteCertificateResolver;
use Cofa\PaymentValidator\Tests\Fixtures\HttpsStreamWrapperStub;
use Cofa\PaymentValidator\Tests\Fixtures\PayPalFixture;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The default transport, exercised with the `https://` stream wrapper swapped
 * out — the same `file_get_contents()` call and stream context a merchant runs,
 * without a network.
 */
#[CoversClass(RemoteCertificateResolver::class)]
final class RemoteCertificateResolverTest extends TestCase
{
    protected function tearDown(): void
    {
        HttpsStreamWrapperStub::uninstall();

        parent::tearDown();
    }

    #[Test]
    public function it_fetches_a_certificate_from_an_allowed_host(): void
    {
        HttpsStreamWrapperStub::install(PayPalFixture::certificate());

        $resolver = new RemoteCertificateResolver(['paypal.com']);
        $url = 'https://api.paypal.com/v1/notifications/certs/CERT-1';

        self::assertSame(PayPalFixture::certificate(), $resolver->resolve($url));
        self::assertSame([$url], HttpsStreamWrapperStub::$requested);
    }

    #[Test]
    public function it_verifies_the_peer_and_refuses_to_follow_redirects(): void
    {
        // A redirect from an allow-listed host would otherwise be a way straight
        // back out of the allow-list.
        HttpsStreamWrapperStub::install(PayPalFixture::certificate());

        (new RemoteCertificateResolver(['paypal.com'], timeout: 3))
            ->resolve('https://api.paypal.com/v1/notifications/certs/CERT-1');

        $options = HttpsStreamWrapperStub::$contextOptions;

        self::assertSame(0, $options['http']['follow_location']);
        self::assertSame(3, $options['http']['timeout']);
        self::assertTrue($options['ssl']['verify_peer']);
        self::assertTrue($options['ssl']['verify_peer_name']);
        self::assertFalse($options['ssl']['allow_self_signed']);
    }

    #[Test]
    public function a_failed_fetch_resolves_to_null_rather_than_a_warning(): void
    {
        HttpsStreamWrapperStub::install(null);

        $resolver = new RemoteCertificateResolver(['paypal.com']);

        self::assertNull($resolver->resolve('https://api.paypal.com/v1/notifications/certs/CERT-1'));
    }

    #[Test]
    public function a_response_that_is_not_pem_resolves_to_null(): void
    {
        HttpsStreamWrapperStub::install('<html><body>Not found</body></html>');

        $resolver = new RemoteCertificateResolver(['paypal.com']);

        self::assertNull($resolver->resolve('https://api.paypal.com/v1/notifications/certs/CERT-1'));
    }

    #[Test]
    public function a_disallowed_host_is_never_contacted(): void
    {
        // The allow-list has to short-circuit before the request, or the endpoint
        // becomes a fetch-any-URL service pointed at the internal network.
        HttpsStreamWrapperStub::install(PayPalFixture::certificate());

        $resolver = new RemoteCertificateResolver(['paypal.com']);

        self::assertNull($resolver->resolve('https://evil.example/certs/CERT-1'));
        self::assertSame([], HttpsStreamWrapperStub::$requested);
    }

    #[Test]
    public function a_failure_is_memoised_so_a_bad_url_is_not_retried_per_request(): void
    {
        HttpsStreamWrapperStub::install(null);

        $resolver = new RemoteCertificateResolver(['paypal.com']);
        $url = 'https://api.paypal.com/v1/notifications/certs/CERT-1';

        self::assertNull($resolver->resolve($url));
        self::assertNull($resolver->resolve($url));
        self::assertCount(1, HttpsStreamWrapperStub::$requested);
    }
}
