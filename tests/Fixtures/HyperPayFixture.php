<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Tests\Fixtures;

/** Encrypts HyperPay notifications exactly the way HyperPay's webhook sender does. */
final class HyperPayFixture
{
    /** 32 bytes, hex encoded, as issued by the HyperPay dashboard. */
    public const KEY = 'ED07B9D6D64C4A0B5EC0B8B2F1D3A6C48E9F2A1B7C3D5E6F70819A2B3C4D5E6F';

    /** @return array<string, mixed> */
    public static function notification(): array
    {
        return [
            'type' => 'PAYMENT',
            'payload' => [
                'id' => '8ac7a4a1-8e2f-4c6b-9a3d-2f1e0b7c5d49',
                'paymentType' => 'DB',
                'paymentBrand' => 'VISA',
                'amount' => '92.00',
                'currency' => 'SAR',
                'merchantTransactionId' => 'ORD-2024-001',
                'result' => ['code' => '000.100.110', 'description' => 'Request successfully processed'],
            ],
        ];
    }

    /**
     * @return array{body: string, iv: string, tag: string, plaintext: string}
     */
    public static function encrypted(?string $plaintext = null, string $hexKey = self::KEY): array
    {
        $plaintext ??= json_encode(self::notification(), JSON_THROW_ON_ERROR);

        $key = (string) hex2bin($hexKey);
        $iv = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

        if ($ciphertext === false) {
            throw new \RuntimeException('Unable to encrypt the HyperPay fixture.');
        }

        return [
            'body' => bin2hex($ciphertext),
            'iv' => bin2hex($iv),
            'tag' => bin2hex($tag),
            'plaintext' => $plaintext,
        ];
    }

    /** @return array<string, string> */
    public static function headers(string $iv, string $tag): array
    {
        return [
            'X-Initialization-Vector' => $iv,
            'X-Authentication-Tag' => $tag,
            'Content-Type' => 'application/json',
        ];
    }
}
