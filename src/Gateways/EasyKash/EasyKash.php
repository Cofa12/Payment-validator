<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Gateways\EasyKash;

use Appssquare\PaymentValidator\Contracts\SignatureValidator;
use Appssquare\PaymentValidator\Support\SignatureLocation;
use Appssquare\PaymentValidator\Validators\CompositeValidator;
use Appssquare\PaymentValidator\Validators\SharedSecretValidator;

/** Entry point for EasyKash. */
final class EasyKash
{
    public const GATEWAY = 'easykash';

    /**
     * @param list<string|list<string>>|null $signedFields override when your
     *                                                     merchant contract
     *                                                     signs a different set
     */
    public static function validator(
        #[\SensitiveParameter] string $secret,
        ?array $signedFields = null,
    ): EasyKashWebhookValidator {
        return new EasyKashWebhookValidator($secret, $signedFields);
    }

    /**
     * HMAC signature *plus* the static token EasyKash presents in a header, for
     * accounts configured with both. The HMAC channel is tried first so a
     * request carrying a signature is judged on the strong check.
     *
     * @param list<string|list<string>>|null $signedFields
     */
    public static function withApiKeyHeader(
        #[\SensitiveParameter] string $secret,
        #[\SensitiveParameter] string $apiKey,
        string $header = 'X-Api-Key',
        ?array $signedFields = null,
    ): SignatureValidator {
        return new CompositeValidator(self::GATEWAY, [
            'signature' => new EasyKashWebhookValidator($secret, $signedFields),
            'api_key' => new SharedSecretValidator(
                self::GATEWAY,
                $apiKey,
                SignatureLocation::header($header),
            ),
        ]);
    }
}
