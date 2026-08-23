<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Fixtures;

/** Kashier webhook and redirect payloads with independently computed signatures. */
final class KashierFixture
{
    public const API_KEY = 'kashier-payment-api-key-0123456789';

    /** @return array<string, mixed> */
    public static function webhookData(): array
    {
        return [
            'status' => 'SUCCESS',
            'amount' => 250,
            'currency' => 'EGP',
            'merchantOrderId' => 'ORD-2024-001',
            'orderReference' => 'TEST-ORD-1911',
            'transactionId' => 'TX-9911',
            'cardDataToken' => 'card-token-abc',
            'maskedCard' => '512345xxxxxx2346',
            'signatureKeys' => ['amount', 'currency', 'merchantOrderId', 'orderReference', 'transactionId', 'status'],
        ];
    }

    /**
     * @param array<string, mixed> $overrides applied to `data` before signing
     *
     * @return array<string, mixed>
     */
    public static function webhook(array $overrides = []): array
    {
        $data = array_replace(self::webhookData(), $overrides);
        $data['kashierSignature'] = self::webhookSignature($data);

        return ['event' => 'pay', 'data' => $data];
    }

    /**
     * Reference implementation: the fields named by `signatureKeys`, in that
     * order, URL-encoded and HMAC-SHA256'd.
     *
     * @param array<string, mixed> $data
     */
    public static function webhookSignature(array $data, string $apiKey = self::API_KEY): string
    {
        $params = [];

        foreach ($data['signatureKeys'] as $key) {
            $params[$key] = $data[$key] ?? '';
        }

        return hash_hmac('sha256', http_build_query($params), $apiKey);
    }

    /** @return array<string, string> the signed portion of the redirect URL */
    public static function redirectParams(): array
    {
        return [
            'paymentStatus' => 'SUCCESS',
            'cardDataToken' => 'card-token-abc',
            'maskedCard' => '512345xxxxxx2346',
            'merchantOrderId' => 'ORD-2024-001',
            'orderId' => 'TEST-ORD-1911',
            'cardBrand' => 'MasterCard',
            'orderReference' => 'TEST-ORD-1911',
            'transactionId' => 'TX-9911',
            'amount' => '250',
            'currency' => 'EGP',
        ];
    }

    /**
     * The full redirect query string, including the unsigned `mode` parameter
     * Kashier appends after signing.
     *
     * @param array<string, string> $overrides
     */
    public static function redirectQueryString(array $overrides = [], array $unsignedExtras = []): string
    {
        $signed = array_replace(self::redirectParams(), $overrides);

        $all = array_merge($signed, $unsignedExtras, [
            'mode' => 'test',
            'signature' => self::redirectSignature($signed),
        ]);

        return http_build_query($all);
    }

    /**
     * A redirect whose signature was computed over the genuine parameters and
     * whose URL then had one of them swapped — what a customer editing the
     * address bar actually produces.
     */
    public static function tamperedRedirectQueryString(string $param, string $value): string
    {
        $signed = self::redirectParams();
        $signature = self::redirectSignature($signed);

        $signed[$param] = $value;

        return http_build_query(array_merge($signed, ['mode' => 'test', 'signature' => $signature]));
    }

    /** @param array<string, string> $signed */
    public static function redirectSignature(array $signed, string $apiKey = self::API_KEY): string
    {
        return hash_hmac('sha256', http_build_query($signed), $apiKey);
    }
}
