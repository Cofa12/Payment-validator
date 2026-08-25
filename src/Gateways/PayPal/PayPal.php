<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\PayPal;

use Cofa\PaymentValidator\Contracts\CertificateResolver;

/** Entry point for PayPal REST webhooks. */
final class PayPal
{
    public const GATEWAY = 'paypal';

    /**
     * @param string                  $webhookId    the subscription ID this endpoint serves
     * @param CertificateResolver|null $certificates supply your own to add caching, use your
     *                                               HTTP client, or pin a certificate offline;
     *                                               the default fetches from PayPal hosts only
     */
    public static function validator(
        string $webhookId,
        ?CertificateResolver $certificates = null,
    ): PayPalWebhookValidator {
        return new PayPalWebhookValidator($webhookId, $certificates);
    }
}
