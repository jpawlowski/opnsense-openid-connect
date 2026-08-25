<?php

namespace OPNsense\OpenIDConnect;

/** A safe RFC 8935 error category paired with a private diagnostic. */
final class SecurityEventException extends ProtocolException
{
    public function __construct(
        private readonly string $errorCategory,
        string $message,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function errorCategory(): string
    {
        return $this->errorCategory;
    }
}
