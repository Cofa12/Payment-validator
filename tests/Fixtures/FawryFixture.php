<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Fixtures;

/**
 * FawryPay V2 notifications with signatures computed by hand from the published
 * recipe, so the tests check the implementation against the spec rather than
 * against itself.
 */
final class FawryFixture
{
    public const SECURE_KEY = 'fawry-secure-key-9f8e7d6c5b4a3210';

    /** @return array<string, mixed> */
    public static function notificationBody(): array
    {
        return [
            'requestId' => 'a7f3c1e2-90bb-4c11-9a55-1d0e2f3a4b5c',
            'fawryRefNumber' => '970488',
            'merchantRefNumber' => 'ORD-2024-001',
            'customerName' => 'Customer Name',
            'customerMobile' => '01000000000',
            'customerMail' => 'customer@example.com',
            // JSON numbers: the trap this fixture exists to catch, because PHP
            // decodes 250.00 to the float 250.0 and renders it back as "250".
            'paymentAmount' => 250.00,
            'orderAmount' => 250.00,
            'fawryFees' => 5.00,
            'shippingFees' => 0.00,
            'orderStatus' => 'PAID',
            'paymentMethod' => 'PAYATFAWRY',
            'paymentTime' => 1714558530000,
            'authNumber' => '123456',
            'paymentRefrenceNumber' => '100155507',
            'orderExpiryDate' => 1714658530000,
            'orderItems' => [
                ['itemCode' => 'PRD-9001', 'price' => 250.00, 'quantity' => 1],
            ],
        ];
    }

    /**
     * The notification as delivered: the body plus its `messageSignature`.
     *
     * @param array<string, mixed> $overrides applied before signing
     *
     * @return array<string, mixed>
     */
    public static function notification(array $overrides = []): array
    {
        $body = array_replace(self::notificationBody(), $overrides);

        return $body + ['messageSignature' => self::signature($body)];
    }

    /**
     * Reference implementation of the documented recipe:
     *
     *     SHA-256(fawryRefNumber + merchantRefNumber + paymentAmount(2dp)
     *             + orderAmount(2dp) + orderStatus + paymentMethod
     *             + paymentRefrenceNumber + secureKey)
     *
     * @param array<string, mixed> $body
     */
    public static function signature(array $body, string $secureKey = self::SECURE_KEY): string
    {
        $amount = static fn (mixed $v): string => number_format((float) $v, 2, '.', '');

        $concatenated = $body['fawryRefNumber']
            . $body['merchantRefNumber']
            . $amount($body['paymentAmount'])
            . $amount($body['orderAmount'])
            . $body['orderStatus']
            . $body['paymentMethod']
            . ($body['paymentRefrenceNumber'] ?? '')
            . $secureKey;

        return hash('sha256', $concatenated);
    }

    /**
     * An order-creation notification: unpaid, and with no payment reference
     * number yet, which the recipe signs as an empty string.
     *
     * @return array<string, mixed>
     */
    public static function unpaidNotification(): array
    {
        $body = self::notificationBody();

        unset($body['paymentRefrenceNumber'], $body['authNumber'], $body['paymentTime']);

        $body['orderStatus'] = 'UNPAID';
        $body['paymentAmount'] = 0.00;

        return $body + ['messageSignature' => self::signature($body)];
    }

    /**
     * The hosted checkout's `chargeResponse`, handed back on the return URL as
     * query parameters — the same fields, with the amounts already two-decimal
     * text rather than JSON numbers.
     */
    public static function redirectQueryString(): string
    {
        $body = self::notificationBody();
        $signature = self::signature($body);

        $params = [
            'requestId' => (string) $body['requestId'],
            'fawryRefNumber' => (string) $body['fawryRefNumber'],
            'merchantRefNumber' => (string) $body['merchantRefNumber'],
            'customerMobile' => (string) $body['customerMobile'],
            'customerMail' => (string) $body['customerMail'],
            'paymentAmount' => number_format((float) $body['paymentAmount'], 2, '.', ''),
            'orderAmount' => number_format((float) $body['orderAmount'], 2, '.', ''),
            'fawryFees' => number_format((float) $body['fawryFees'], 2, '.', ''),
            'orderStatus' => (string) $body['orderStatus'],
            'paymentMethod' => (string) $body['paymentMethod'],
            'paymentRefrenceNumber' => (string) $body['paymentRefrenceNumber'],
            'messageSignature' => $signature,
        ];

        return http_build_query($params);
    }
}
