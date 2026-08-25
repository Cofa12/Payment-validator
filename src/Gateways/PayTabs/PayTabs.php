<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\PayTabs;

use Cofa\PaymentValidator\Validators\CompositeValidator;

/** Entry point for PayTabs PT2: one Server Key, both callback channels. */
final class PayTabs
{
    public const GATEWAY = 'paytabs';

    /**
     * @param string       $serverKey          the profile Server Key from the
     *                                         PayTabs dashboard (the same key
     *                                         the PT2 API calls authenticate
     *                                         with, not the Client Key)
     * @param list<string> $additionalExcluded parameters your own return URL
     *                                         appends and PayTabs never signed
     */
    public static function validator(
        #[\SensitiveParameter] string $serverKey,
        array $additionalExcluded = [],
    ): CompositeValidator {
        return new CompositeValidator(self::GATEWAY, [
            'callback' => new PayTabsCallbackValidator($serverKey),
            'return' => new PayTabsReturnValidator($serverKey, $additionalExcluded),
        ]);
    }
}
