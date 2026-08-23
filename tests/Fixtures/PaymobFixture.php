<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Tests\Fixtures;

/**
 * Builds Paymob callbacks with signatures computed by hand from the published
 * recipe, so the tests check the implementation against the spec rather than
 * against itself.
 */
final class PaymobFixture
{
    public const SECRET = 'A1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUV';

    /** @return array<string, mixed> */
    public static function transactionObject(): array
    {
        return [
            'id' => 123456789,
            'pending' => false,
            'amount_cents' => 10000,
            'success' => true,
            'is_auth' => false,
            'is_capture' => false,
            'is_standalone_payment' => true,
            'is_voided' => false,
            'is_refunded' => false,
            'is_3d_secure' => true,
            'integration_id' => 987654,
            'has_parent_transaction' => false,
            'order' => ['id' => 55555555, 'merchant_order_id' => 'ORD-2024-001'],
            'created_at' => '2024-05-01T10:15:30.123456',
            'currency' => 'EGP',
            'error_occured' => false,
            'owner' => 4242,
            'source_data' => [
                'pan' => '2346',
                'sub_type' => 'MasterCard',
                'type' => 'card',
            ],
        ];
    }

    /**
     * The processed callback: `{type, obj, hmac}` POSTed to the merchant.
     *
     * @param array<string, mixed> $overrides applied to `obj` before signing
     *
     * @return array<string, mixed>
     */
    public static function transactionWebhook(array $overrides = []): array
    {
        $obj = array_replace(self::transactionObject(), $overrides);

        return [
            'type' => 'TRANSACTION',
            'obj' => $obj,
            'hmac' => self::transactionHmac($obj),
        ];
    }

    /** Reference implementation of the documented lexicographical concatenation. */
    public static function transactionHmac(array $obj, string $secret = self::SECRET): string
    {
        $b = static fn (mixed $v): string => $v ? 'true' : 'false';

        $concatenated = $obj['amount_cents']
            . $obj['created_at']
            . $obj['currency']
            . $b($obj['error_occured'])
            . $b($obj['has_parent_transaction'])
            . $obj['id']
            . $obj['integration_id']
            . $b($obj['is_3d_secure'])
            . $b($obj['is_auth'])
            . $b($obj['is_capture'])
            . $b($obj['is_refunded'])
            . $b($obj['is_standalone_payment'])
            . $b($obj['is_voided'])
            . $obj['order']['id']
            . $obj['owner']
            . $b($obj['pending'])
            . $obj['source_data']['pan']
            . $obj['source_data']['sub_type']
            . $obj['source_data']['type']
            . $b($obj['success']);

        return hash_hmac('sha512', $concatenated, $secret);
    }

    /**
     * The response callback: the same fields flattened into a redirect URL,
     * with literal dots in the parameter names.
     */
    public static function redirectQueryString(): string
    {
        $obj = self::transactionObject();
        $b = static fn (mixed $v): string => $v ? 'true' : 'false';

        $params = [
            'id' => (string) $obj['id'],
            'pending' => $b($obj['pending']),
            'amount_cents' => (string) $obj['amount_cents'],
            'success' => $b($obj['success']),
            'is_auth' => $b($obj['is_auth']),
            'is_capture' => $b($obj['is_capture']),
            'is_standalone_payment' => $b($obj['is_standalone_payment']),
            'is_voided' => $b($obj['is_voided']),
            'is_refunded' => $b($obj['is_refunded']),
            'is_3d_secure' => $b($obj['is_3d_secure']),
            'integration_id' => (string) $obj['integration_id'],
            'has_parent_transaction' => $b($obj['has_parent_transaction']),
            'order' => (string) $obj['order']['id'],
            'created_at' => (string) $obj['created_at'],
            'currency' => (string) $obj['currency'],
            'error_occured' => $b($obj['error_occured']),
            'owner' => (string) $obj['owner'],
            'source_data.pan' => (string) $obj['source_data']['pan'],
            'source_data.sub_type' => (string) $obj['source_data']['sub_type'],
            'source_data.type' => (string) $obj['source_data']['type'],
            'hmac' => self::transactionHmac($obj),
        ];

        $pairs = [];

        foreach ($params as $key => $value) {
            $pairs[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $pairs);
    }

    /** @return array<string, mixed> */
    public static function cardTokenObject(): array
    {
        return [
            'id' => 778899,
            'token' => 'a1b2c3d4e5f6g7h8i9j0',
            'masked_pan' => 'xxxx-xxxx-xxxx-2346',
            'merchant_id' => 33221,
            'card_subtype' => 'MasterCard',
            'created_at' => '2024-05-01T10:15:31.654321',
            'email' => 'customer@example.com',
            'order_id' => '55555555',
        ];
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    public static function cardTokenWebhook(array $overrides = []): array
    {
        $obj = array_replace(self::cardTokenObject(), $overrides);

        return [
            'type' => 'TOKEN',
            'obj' => $obj,
            'hmac' => self::cardTokenHmac($obj),
        ];
    }

    public static function cardTokenHmac(array $obj, string $secret = self::SECRET): string
    {
        $concatenated = $obj['card_subtype']
            . $obj['created_at']
            . $obj['email']
            . $obj['id']
            . $obj['masked_pan']
            . $obj['merchant_id']
            . $obj['order_id']
            . $obj['token'];

        return hash_hmac('sha512', $concatenated, $secret);
    }
}
