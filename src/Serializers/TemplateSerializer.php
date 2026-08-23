<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Serializers;

use Appssquare\PaymentValidator\Contracts\PayloadSerializer;
use Appssquare\PaymentValidator\Contracts\ValueNormalizer;
use Appssquare\PaymentValidator\Support\Payload;

/**
 * Builds the signing string from a literal template: any gateway whose docs
 * give you a formula such as
 *
 *     "/?payment={merchantId}.{orderId}.{amount}.{currency}"
 *
 * can be added by transcribing that line, no new class required. Placeholders
 * accept dot notation and resolve against the payload.
 */
final class TemplateSerializer implements PayloadSerializer
{
    private readonly ValueNormalizer $normalizer;

    public function __construct(
        private readonly string $template,
        ?ValueNormalizer $normalizer = null,
    ) {
        $this->normalizer = $normalizer ?? new DefaultValueNormalizer();
    }

    public function serialize(Payload $payload): string
    {
        return preg_replace_callback(
            '/\{([A-Za-z0-9_.\-]+)\}/',
            fn (array $matches): string => $this->normalizer->normalize($payload->get($matches[1]), $matches[1]),
            $this->template,
        ) ?? '';
    }

    /** @return list<string> */
    public function placeholders(): array
    {
        preg_match_all('/\{([A-Za-z0-9_.\-]+)\}/', $this->template, $matches);

        return array_values(array_unique($matches[1]));
    }
}
