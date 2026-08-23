<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Gateways\Kashier;

use Cofa\PaymentValidator\Validators\CompositeValidator;

/** Entry point for Kashier: one API key, both callback channels. */
final class Kashier
{
    public const GATEWAY = 'kashier';

    /**
     * @param string       $apiKey             the payment API key from Kashier
     *                                         dashboard → Settings → API keys
     * @param list<string> $additionalExcluded redirect parameters you appended
     *                                         yourself and Kashier never signed
     */
    public static function validator(
        #[\SensitiveParameter] string $apiKey,
        array $additionalExcluded = [],
    ): CompositeValidator {
        return new CompositeValidator(self::GATEWAY, [
            'webhook' => new KashierWebhookValidator($apiKey),
            'redirect' => new KashierRedirectValidator($apiKey, $additionalExcluded),
        ]);
    }
}
