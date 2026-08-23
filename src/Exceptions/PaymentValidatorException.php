<?php

declare(strict_types=1);

namespace Cofa\PaymentValidator\Exceptions;

use Throwable;

/**
 * Marker for everything this package throws, so consumers can catch the whole
 * library with a single `catch (PaymentValidatorException $e)`.
 */
interface PaymentValidatorException extends Throwable
{
}
