<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Gateways\Paymob;

use Appssquare\PaymentValidator\Validators\CompositeValidator;

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
