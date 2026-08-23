<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Fixtures;

/** EasyKash Direct Pay webhook payloads with independently computed signatures. */
final class EasyKashFixture
{
    public const SECRET = 'easykash-secret-key-abcdef123456';

    /** @return array<string, mixed> */
    public static function payload(array $overrides = []): array
    {
        $data = array_replace([
            'easykashRef' => 'EK-77213',
            'Amount' => '250.00',
            'Currency' => 'EGP',
            'PaymentMethod' => 'Fawry',
            'productCode' => 'PRD-9001',
            'status' => 'PAID',
            'customerEmail' => 'customer@example.com',
        ], $overrides);

        $data['signature'] = self::signature($data);

        return $data;
    }

    /**
     * Reference implementation over the default signed field set.
     *
     * @param array<string, mixed> $data
     */
    public static function signature(array $data, string $secret = self::SECRET): string
    {
        $concatenated = $data['easykashRef']
            . $data['Amount']
            . $data['Currency']
            . $data['PaymentMethod']
            . $data['productCode']
            . $data['status'];

        return hash_hmac('sha256', $concatenated, $secret);
    }
}
