<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Support;

use Appssquare\PaymentValidator\Exceptions\InvalidConfigurationException;

/**
 * AES-GCM open-and-authenticate.
 *
 * GCM is an AEAD mode: decryption only succeeds if the authentication tag
 * verifies, which makes a successful decrypt *proof of authenticity* — the same
 * guarantee an HMAC gives, obtained a different way. Gateways that deliver
 * encrypted webhooks (HyperPay among them) rely on exactly this.
 */
final class AesGcmDecryptor
{
    /** Held as a Secret so that dumping a validator cannot leak the key. */
    private readonly Secret $key;

    private readonly string $cipher;

    /** @param string $hexKey the decryption key, hex encoded, as issued by the gateway */
    public function __construct(#[\SensitiveParameter] string $hexKey, string $context = 'aes-gcm')
    {
        $key = self::hexToBin(trim($hexKey));

        if ($key === null) {
            throw new InvalidConfigurationException(
                sprintf('The [%s] decryption key must be a hex-encoded string.', $context),
            );
        }

        $this->cipher = match (strlen($key)) {
            16 => 'aes-128-gcm',
            24 => 'aes-192-gcm',
            32 => 'aes-256-gcm',
            default => throw new InvalidConfigurationException(sprintf(
                'The [%s] decryption key must decode to 16, 24 or 32 bytes; got %d.',
                $context,
                strlen($key),
            )),
        };

        if (! in_array($this->cipher, openssl_get_cipher_methods(), true)) {
            throw new InvalidConfigurationException(
                sprintf('Cipher [%s] is not available in this OpenSSL build.', $this->cipher),
            );
        }

        $this->key = new Secret($key);
    }

    /**
     * @param string $hexCiphertext hex-encoded ciphertext
     * @param string $hexIv         hex-encoded initialisation vector / nonce
     * @param string $hexTag        hex-encoded GCM authentication tag
     *
     * @return string|null the plaintext, or null when the payload is malformed
     *                     or the tag does not authenticate
     */
    public function decrypt(string $hexCiphertext, string $hexIv, string $hexTag): ?string
    {
        $ciphertext = self::hexToBin(trim($hexCiphertext));
        $iv = self::hexToBin(trim($hexIv));
        $tag = self::hexToBin(trim($hexTag));

        if ($ciphertext === null || $iv === null || $tag === null) {
            return null;
        }

        // GCM tags are 4-16 bytes; openssl_decrypt() errors out on anything else.
        if ($iv === '' || strlen($tag) < 4 || strlen($tag) > 16) {
            return null;
        }

        $plaintext = openssl_decrypt($ciphertext, $this->cipher, $this->key->reveal(), OPENSSL_RAW_DATA, $iv, $tag);

        return $plaintext === false ? null : $plaintext;
    }

    public function cipher(): string
    {
        return $this->cipher;
    }

    /** Strict hex decode: rejects odd lengths and non-hex characters instead of guessing. */
    private static function hexToBin(string $hex): ?string
    {
        if ($hex === '') {
            return '';
        }

        if (strlen($hex) % 2 !== 0 || ! ctype_xdigit($hex)) {
            return null;
        }

        $binary = @hex2bin($hex);

        return $binary === false ? null : $binary;
    }
}
