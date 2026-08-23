<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Gateways\EasyKash;

use Appssquare\PaymentValidator\Contracts\PayloadSerializer;
use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;
use Appssquare\PaymentValidator\Serializers\ConcatenatedFieldSerializer;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\SignatureLocation;
use Appssquare\PaymentValidator\Validators\AbstractHmacValidator;

/**
 * EasyKash Direct Pay webhook: HMAC-SHA256 over an ordered concatenation of
 * transaction fields, compared against the `signature` field.
 *
 * ⚠ Confirm the field list against your own EasyKash account documentation.
 * EasyKash issues per-merchant integration contracts and the signed field set
 * differs between Direct Pay versions and product profiles — unlike Paymob or
 * Kashier, there is no single published list that holds for every merchant.
 * The default below is the common Direct Pay v2 set; when yours differs, pass
 * your own rather than editing this class:
 *
 *     new EasyKashWebhookValidator($secret, ['easykashRef', 'Amount', 'status']);
 *
 * Field lookup is case-insensitive, because EasyKash mixes `Amount` and
 * `amount` across channels.
 */
final class EasyKashWebhookValidator extends AbstractHmacValidator
{
    /** @var list<string> */
    public const DEFAULT_SIGNED_FIELDS = [
        'easykashRef',
        'Amount',
        'Currency',
        'PaymentMethod',
        'productCode',
        'status',
    ];

    private readonly ConcatenatedFieldSerializer $serializer;

    private readonly SignatureLocation $location;

    /**
     * @param list<string|list<string>>|null $signedFields  ordered signed fields; null uses the default set
     * @param string                         $glue          separator between fields, if your contract uses one
     */
    public function __construct(
        #[\SensitiveParameter] string $secret,
        ?array $signedFields = null,
        string $algorithm = 'sha256',
        string $signatureField = 'signature',
        string $glue = '',
    ) {
        $fields = $signedFields ?? self::DEFAULT_SIGNED_FIELDS;

        if ($fields === []) {
            throw InvalidConfigurationException::missingFields('easykash');
        }

        $this->serializer = new ConcatenatedFieldSerializer(
            fields: $fields,
            glue: $glue,
            caseInsensitive: true,
        );

        $this->location = SignatureLocation::firstOf(
            SignatureLocation::field($signatureField),
            SignatureLocation::field('data.' . $signatureField),
        );

        parent::__construct($secret, $algorithm);
    }

    public function gateway(): string
    {
        return 'easykash';
    }

    /** @return list<string|list<string>> */
    public function signedFields(): array
    {
        return $this->serializer->fields();
    }

    protected function serializer(Payload $payload): PayloadSerializer
    {
        return $this->serializer;
    }

    protected function signatureLocation(): SignatureLocation
    {
        return $this->location;
    }
}
