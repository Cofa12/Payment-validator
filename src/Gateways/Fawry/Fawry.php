<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\Fawry;

/** Entry point for FawryPay. */
final class Fawry
{
    public const GATEWAY = 'fawry';

    /**
     * The V2 server notification and the hosted-checkout `chargeResponse`, both
     * of which carry `messageSignature` over the same seven fields.
     *
     * V1 notifications are deliberately not shipped: they are
     * `md5(secureKey . …)`, which is both a broken digest and the
     * length-extension-prone key placement. If your account is still on V1, wire
     * it up explicitly rather than silently — see the README.
     */
    public static function validator(#[\SensitiveParameter] string $secureKey): FawryNotificationValidator
    {
        return new FawryNotificationValidator($secureKey);
    }
}
