<?php

declare(strict_types=1);

namespace Iodev\Whois\Exceptions;

use Throwable;

class WhoisException extends \Exception
{
    public function __construct($message = "", $code = 0, ?Throwable $previous = null)
    {
        // Cast explicitly: under strict_types a null message/code (e.g. from fsockopen or curl) would throw a TypeError
        parent::__construct((string)$message, (int)$code, $previous);
    }
}
