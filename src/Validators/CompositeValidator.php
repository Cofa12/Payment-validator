<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Validators;

use Cofa\PaymentValidator\Contracts\SignatureValidator;
use Cofa\PaymentValidator\Exceptions\InvalidConfigurationException;
use Cofa\PaymentValidator\Support\Payload;
use Cofa\PaymentValidator\Support\ValidationResult;

/**
 * Fans one gateway name out over its several callback channels.
 *
 * A gateway is rarely one signature scheme: Paymob signs transaction webhooks
 * and card-token webhooks over different field sets, Kashier signs its redirect
 * differently from its webhook. Callers should not have to know which arrived —
 * they register `paymob` once and this picks the channel.
 *
 * Each channel still verifies its own HMAC in full, so trying several is not a
 * weakening: a payload is accepted only if some channel's signature is genuinely
 * correct for that channel's rules.
 */
final class CompositeValidator implements SignatureValidator
{
    /** @var array<string, SignatureValidator> */
    private readonly array $channels;

    /**
     * @param array<string, SignatureValidator> $channels channel name => validator
     */
    public function __construct(private readonly string $gateway, array $channels)
    {
        if ($channels === []) {
            throw new InvalidConfigurationException(
                sprintf('The [%s] composite validator needs at least one channel.', $gateway),
            );
        }

        $this->channels = $channels;
    }

    public function gateway(): string
    {
        return $this->gateway;
    }

    /** @return array<string, SignatureValidator> */
    public function channels(): array
    {
        return $this->channels;
    }

    public function channel(string $name): SignatureValidator
    {
        return $this->channels[$name]
            ?? throw new InvalidConfigurationException(sprintf(
                'Gateway [%s] has no channel named [%s]. Available: %s.',
                $this->gateway,
                $name,
                implode(', ', array_keys($this->channels)),
            ));
    }

    public function supports(Payload $payload): bool
    {
        foreach ($this->channels as $channel) {
            if ($channel->supports($payload)) {
                return true;
            }
        }

        return false;
    }

    public function validate(Payload $payload): ValidationResult
    {
        $attempted = [];
        $failures = [];

        foreach ($this->channels as $name => $channel) {
            if (! $channel->supports($payload)) {
                continue;
            }

            $attempted[] = $name;
            $result = $channel->validate($payload);

            if ($result->isValid()) {
                return $result->withContext(['channel' => $name, 'gateway' => $this->gateway]);
            }

            $failures[$name] = $result->reason();
        }

        if ($attempted === []) {
            return ValidationResult::invalid(
                $this->gateway,
                sprintf(
                    'The payload did not match any known [%s] callback channel (%s).',
                    $this->gateway,
                    implode(', ', array_keys($this->channels)),
                ),
                ['channels' => array_keys($this->channels)],
            );
        }

        return ValidationResult::invalid(
            $this->gateway,
            sprintf('Validation failed for every matching channel: %s.', implode(', ', $attempted)),
            ['attempted_channels' => $attempted, 'channel_reasons' => $failures],
        );
    }
}
