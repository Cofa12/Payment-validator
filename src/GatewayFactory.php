<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator;

use Cofa\PaymentValidator\Contracts\SignatureValidator;
use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Exceptions\UnsupportedGatewayException;
use Cofa\PaymentValidator\Gateways\EasyKash\EasyKash;
use Cofa\PaymentValidator\Gateways\Fawry\Fawry;
use Cofa\PaymentValidator\Gateways\HyperPay\HyperPay;
use Cofa\PaymentValidator\Gateways\Kashier\Kashier;
use Cofa\PaymentValidator\Gateways\Paymob\Paymob;
use Cofa\PaymentValidator\Gateways\PayPal\PayPal;
use Cofa\PaymentValidator\Gateways\PayTabs\PayTabs;
use Cofa\PaymentValidator\Support\RemoteCertificateResolver;

/**
 * Builds validators from plain configuration arrays, so a host application can
 * drive the whole package from `config/payments.php` or the environment.
 *
 * `extend()` adds a gateway without touching this class — the same entry point
 * a downstream package or an application-level integration should use.
 */
final class GatewayFactory
{
    /** @var array<string, \Closure(array<string, mixed>): SignatureValidator> */
    private array $builders = [];

    public function __construct()
    {
        $this->registerDefaults();
    }

    /**
     * @param callable(array<string, mixed>): SignatureValidator $builder
     */
    public function extend(string $gateway, callable $builder): self
    {
        $this->builders[strtolower(trim($gateway))] = $builder(...);

        return $this;
    }

    public function supports(string $gateway): bool
    {
        return isset($this->builders[strtolower(trim($gateway))]);
    }

    /** @return list<string> */
    public function supported(): array
    {
        $names = array_keys($this->builders);

        sort($names);

        return $names;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @throws UnsupportedGatewayException
     */
    public function make(string $gateway, array $config): SignatureValidator
    {
        $name = strtolower(trim($gateway));

        if (! isset($this->builders[$name])) {
            throw UnsupportedGatewayException::forGateway($gateway, $this->supported());
        }

        return ($this->builders[$name])($config);
    }

    private function registerDefaults(): void
    {
        $this->extend(Paymob::GATEWAY, static fn (array $c): SignatureValidator => Paymob::validator(
            self::required($c, ['hmac', 'hmac_secret', 'secret', 'key'], Paymob::GATEWAY),
        ));

        $this->extend(Kashier::GATEWAY, static fn (array $c): SignatureValidator => Kashier::validator(
            self::required($c, ['api_key', 'apiKey', 'payment_api_key', 'secret', 'key'], Kashier::GATEWAY),
            self::stringList($c, ['exclude', 'additional_excluded']),
        ));

        $this->extend(EasyKash::GATEWAY, static function (array $c): SignatureValidator {
            $secret = self::required($c, ['secret', 'secret_key', 'api_secret', 'key'], EasyKash::GATEWAY);
            $fields = self::stringList($c, ['fields', 'signed_fields']) ?: null;

            $apiKey = self::optionalString($c, ['api_key', 'apiKey']);

            return $apiKey === null
                ? EasyKash::validator($secret, $fields)
                : EasyKash::withApiKeyHeader(
                    $secret,
                    $apiKey,
                    self::optionalString($c, ['api_key_header', 'header']) ?? 'X-Api-Key',
                    $fields,
                );
        });

        $this->extend(HyperPay::GATEWAY, static fn (array $c): SignatureValidator => HyperPay::validator(
            self::required($c, ['decryption_key', 'webhook_key', 'key', 'secret'], HyperPay::GATEWAY),
        ));

        $this->extend(Fawry::GATEWAY, static fn (array $c): SignatureValidator => Fawry::validator(
            self::required($c, ['secure_key', 'secureKey', 'secret', 'key'], Fawry::GATEWAY),
        ));

        $this->extend(PayTabs::GATEWAY, static fn (array $c): SignatureValidator => PayTabs::validator(
            self::required($c, ['server_key', 'serverKey', 'secret', 'key'], PayTabs::GATEWAY),
            self::stringList($c, ['exclude', 'additional_excluded']),
        ));

        $this->extend(PayPal::GATEWAY, static function (array $c): SignatureValidator {
            $webhookId = self::required($c, ['webhook_id', 'webhookId', 'id'], PayPal::GATEWAY);
            $hosts = self::stringList($c, ['cert_hosts', 'certificate_hosts']);

            return PayPal::validator(
                $webhookId,
                $hosts === [] ? null : new RemoteCertificateResolver($hosts),
            );
        });
    }

    /**
     * A config value the gateway cannot be built without — usually a key, but
     * PayPal's is an identifier.
     *
     * @param array<string, mixed> $config
     * @param list<string>         $keys
     */
    private static function required(array $config, array $keys, string $gateway): string
    {
        $value = self::optionalString($config, $keys);

        if ($value === null || $value === '') {
            throw new InvalidConfigurationException(sprintf(
                'Gateway [%s] requires one of the following config keys: %s.',
                $gateway,
                implode(', ', $keys),
            ));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $config
     * @param list<string>         $keys
     */
    private static function optionalString(array $config, array $keys): ?string
    {
        foreach ($keys as $key) {
            if (isset($config[$key]) && is_scalar($config[$key]) && (string) $config[$key] !== '') {
                return (string) $config[$key];
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $config
     * @param list<string>         $keys
     *
     * @return list<string>
     */
    private static function stringList(array $config, array $keys): array
    {
        foreach ($keys as $key) {
            if (isset($config[$key]) && is_array($config[$key])) {
                return array_values(array_map(
                    static fn (mixed $v): string => is_scalar($v) ? (string) $v : '',
                    $config[$key],
                ));
            }
        }

        return [];
    }
}
