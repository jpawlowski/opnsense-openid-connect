<?php

namespace OPNsense\OpenIDConnect;

/** A bounded provider request failed for a reason which can safely be retried later. */
class ProviderUnavailableException extends ProtocolException
{
    public function __construct(string $message, private readonly ?int $retryAfter = null)
    {
        parent::__construct($message);
    }

    public function retryAfter(): ?int
    {
        return $this->retryAfter;
    }
}
