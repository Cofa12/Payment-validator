<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Fixtures;

/**
 * PayTabs PT2 callbacks and returns, signed by an independent transcription of
 * PayTabs' own reference implementation.
 */
final class PayTabsFixture
{
    public const SERVER_KEY = 'SJJ9WHRD26-JHKMDLZLZG-HRWMBLMLNZ';

    /** @return array<string, mixed> */
    public static function callbackBody(): array
    {
        return [
            'tran_ref' => 'TST2405012345678',
            'tran_type' => 'Sale',
            'cart_id' => 'ORD-2024-001',
            'cart_description' => 'Order ORD-2024-001',
            'cart_currency' => 'SAR',
            'cart_amount' => '250.00',
            'tran_currency' => 'SAR',
            'tran_total' => '250.00',
            'customer_details' => [
                'name' => 'Customer Name',
                'email' => 'customer@example.com',
                'country' => 'SA',
            ],
            'payment_result' => [
                'response_status' => 'A',
                'response_code' => '831000',
                'response_message' => 'Authorised',
                'transaction_time' => '2024-05-01T10:15:30Z',
            ],
            'payment_info' => [
                'card_type' => 'Credit',
                'card_scheme' => 'MasterCard',
                'payment_description' => '5123 45## #### 2346',
            ],
        ];
    }

    /**
     * The IPN as delivered: a raw JSON body plus a `signature` header over
     * those exact bytes.
     *
     * @return array{body: string, headers: array<string, string>}
     */
    public static function callback(?string $body = null, string $serverKey = self::SERVER_KEY): array
    {
        $body ??= json_encode(self::callbackBody(), JSON_THROW_ON_ERROR);

        return [
            'body' => $body,
            'headers' => [
                'Content-Type' => 'application/json',
                'signature' => self::bodySignature($body, $serverKey),
            ],
        ];
    }

    public static function bodySignature(string $body, string $serverKey = self::SERVER_KEY): string
    {
        return hash_hmac('sha256', $body, $serverKey);
    }

    /**
     * The browser return: form fields POSTed back to the merchant's return URL.
     * Values are strings, as a form post delivers them, and `respCode` is
     * deliberately `"0"` so the tests pin `array_filter()`'s behaviour.
     *
     * @return array<string, string>
     */
    public static function returnFields(): array
    {
        return [
            'tranRef' => 'TST2405012345678',
            'tranType' => 'Sale',
            'cartId' => 'ORD-2024-001',
            'cartDesc' => 'Order ORD-2024-001',
            'cartCurrency' => 'SAR',
            'cartAmount' => '250.00',
            'respStatus' => 'A',
            'respCode' => '0',
            'respMessage' => 'Authorised',
            'acquirerRRN' => '',
            'token' => '',
            'customerEmail' => 'customer@example.com',
        ];
    }

    /**
     * @param array<string, string> $overrides
     *
     * @return array<string, string>
     */
    public static function returnPost(array $overrides = [], array $unsignedExtras = []): array
    {
        $fields = array_replace(self::returnFields(), $overrides);

        return array_merge($fields, $unsignedExtras, ['signature' => self::returnSignature($fields)]);
    }

    /**
     * Reference implementation, transcribed from PayTabs' published PHP sample:
     * drop `signature`, drop falsy values, sort by key, URL-encode, HMAC-SHA256.
     *
     * @param array<string, string> $fields
     */
    public static function returnSignature(array $fields, string $serverKey = self::SERVER_KEY): string
    {
        unset($fields['signature']);

        $fields = array_filter($fields);
        ksort($fields);

        return hash_hmac('sha256', http_build_query($fields), $serverKey);
    }
}
