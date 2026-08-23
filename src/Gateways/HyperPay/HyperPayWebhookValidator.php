<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Gateways\HyperPay;

use Appssquare\PaymentValidator\Contracts\SignatureValidator;
use Appssquare\PaymentValidator\Support\AesGcmDecryptor;
use Appssquare\PaymentValidator\Support\Payload;
use Appssquare\PaymentValidator\Support\ValidationResult;

/**
 * HyperPay webhook authenticity.
 *
 * HyperPay does not sign its webhooks — it encrypts them with AES-256-GCM and
 * sends the nonce and authentication tag as headers:
 *
 *     X-Initialization-Vector: <hex>
 *     X-Authentication-Tag:    <hex>
 *     body:                    <hex ciphertext>
 *
 * Because GCM authenticates as it decrypts, a body that opens cleanly under the
 * merchant's key provably came from HyperPay and was not modified in transit.
 * The check is therefore "did it decrypt", and the decrypted notification is
 * returned on the result's `payload` context so the caller does not decrypt twice.
 */
final class HyperPayWebhookValidator implements SignatureValidator
{
    public const GATEWAY = 'hyperpay';

    private readonly AesGcmDecryptor $decryptor;

    /**
     * @param string $decryptionKey the hex webhook key from HyperPay dashboard
     *                              → Administration → Webhooks
     */
    public function __construct(
        #[\SensitiveParameter] string $decryptionKey,
        private readonly string $ivHeader = 'X-Initialization-Vector',
        private readonly string $tagHeader = 'X-Authentication-Tag',
    ) {
        $this->decryptor = new AesGcmDecryptor($decryptionKey, self::GATEWAY);
    }

    public function gateway(): string
    {
        return self::GATEWAY;
    }

    public function supports(Payload $payload): bool
    {
        return $payload->header($this->ivHeader) !== null
            && $payload->header($this->tagHeader) !== null;
    }

    public function validate(Payload $payload): ValidationResult
    {
        $iv = $payload->header($this->ivHeader);
        $tag = $payload->header($this->tagHeader);

        $missing = [];

        if ($iv === null || $iv === '') {
            $missing[] = $this->ivHeader;
        }

        if ($tag === null || $tag === '') {
            $missing[] = $this->tagHeader;
        }

        if ($missing !== []) {
            return ValidationResult::invalid(
                self::GATEWAY,
                'Missing required header(s): ' . implode(', ', $missing) . '.',
            );
        }

        $body = $payload->rawBody();

        if ($body === null || trim($body) === '') {
            return ValidationResult::invalid(
                self::GATEWAY,
                'The request body is empty; HyperPay webhooks carry a hex-encoded ciphertext.',
            );
        }

        $plaintext = $this->decryptor->decrypt($body, (string) $iv, (string) $tag);

        if ($plaintext === null) {
            return ValidationResult::invalid(
                self::GATEWAY,
                'The webhook body did not authenticate: wrong decryption key, or the payload was altered.',
                ['cipher' => $this->decryptor->cipher()],
            );
        }

        return ValidationResult::valid(self::GATEWAY, [
            'cipher' => $this->decryptor->cipher(),
            'payload' => $this->decodeJson($plaintext),
            'plaintext' => $plaintext,
        ]);
    }

    /**
     * Decrypt and decode in one step, for callers that only want the
     * notification and would rather branch on `null`.
     *
     * @return array<array-key, mixed>|null
     */
    public function decrypt(Payload $payload): ?array
    {
        $result = $this->validate($payload);

        if ($result->isInvalid()) {
            return null;
        }

        $decoded = $result->contextValue('payload');

        return is_array($decoded) ? $decoded : null;
    }

    /** @return array<array-key, mixed>|null */
    private function decodeJson(string $plaintext): ?array
    {
        $decoded = json_decode($plaintext, true);

        return is_array($decoded) ? $decoded : null;
    }
}
