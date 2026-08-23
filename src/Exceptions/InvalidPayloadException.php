<?php

declare(strict_types=1);

namespace Appssquare\PaymentValidator\Exceptions;

use InvalidArgumentException;

/** The payload could not be parsed into a usable shape at construction time. */
final class InvalidPayloadException extends InvalidArgumentException implements PaymentValidatorException
{
}
