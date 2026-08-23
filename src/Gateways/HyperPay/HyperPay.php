<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Gateways\HyperPay;

/** Entry point for HyperPay. */
final class HyperPay
{
    public const GATEWAY = 'hyperpay';

    public static function validator(#[\SensitiveParameter] string $decryptionKey): HyperPayWebhookValidator
    {
        return new HyperPayWebhookValidator($decryptionKey);
    }
}
