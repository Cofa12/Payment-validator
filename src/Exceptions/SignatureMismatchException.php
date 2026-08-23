<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Exceptions;

use Cofa\PaymentValidator\Support\ValidationResult;
use RuntimeException;

/** Thrown by `ValidationResult::throwIfInvalid()` and `PaymentValidator::assertValid()`. */
final class SignatureMismatchException extends RuntimeException implements PaymentValidatorException
{
    public function __construct(string $message, private readonly ValidationResult $result)
    {
        parent::__construct($message);
    }

    public function result(): ValidationResult
    {
        return $this->result;
    }

    public function gateway(): string
    {
        return $this->result->gateway();
    }

    public function reason(): ?string
    {
        return $this->result->reason();
    }
}
