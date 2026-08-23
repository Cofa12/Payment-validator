<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\Paymob;

use Cofa\PaymentValidator\Validators\CompositeValidator;

/** Entry point for Paymob: one secret, both callback channels. */
final class Paymob
{
    public const GATEWAY = 'paymob';

    /**
     * @param string $hmacSecret the HMAC value from Paymob dashboard →
     *                           Settings → Account Info (not the API key)
     */
    public static function validator(#[\SensitiveParameter] string $hmacSecret): CompositeValidator
    {
        return new CompositeValidator(self::GATEWAY, [
            'transaction' => new PaymobTransactionValidator($hmacSecret),
            'card_token' => new PaymobCardTokenValidator($hmacSecret),
        ]);
    }
}
