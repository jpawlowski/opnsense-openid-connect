<?php

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;

/** Applies one verified Shared Signals event through the common push/poll boundary. */
final class SharedSignalsEventProcessor
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @return array{jti:string,event:string,count:int,duplicate:bool} */
    public function process(
        string $set,
        string $serverName,
        OpenIDConnect $settings,
        ?SharedSignalsMetadata $metadata = null
    ): array {
        $metadata ??= SharedSignalsMetadata::discover($settings->sharedSignalsIssuer(), $this->http);
        $event = $this->verify($set, $settings, $metadata);
        return $this->apply($event, $serverName, $settings, $metadata);
    }

    /**
     * @return array{
     *     jti:string,
     *     subject:?string,
     *     subject_issuer:?string,
     *     session_id:?string,
     *     cutoff:int,
     *     actionable:bool,
     *     event:string
     * }
     */
    public function verify(string $set, OpenIDConnect $settings, SharedSignalsMetadata $metadata): array
    {
        return (new SecurityEventVerifier(new JwtVerifier($this->http, 'ssf-jwks')))->verify(
            $set,
            $metadata,
            $settings->sharedSignalsAudience(),
            $settings->issuerUrl(),
            $settings->providerProfile()
        );
    }

    /**
     * @param array{
     *     jti:string,
     *     subject:?string,
     *     subject_issuer:?string,
     *     session_id:?string,
     *     cutoff:int,
     *     actionable:bool,
     *     event:string
     * } $event
     * @return array{jti:string,event:string,count:int,duplicate:bool}
     */
    public function apply(
        array $event,
        string $serverName,
        OpenIDConnect $settings,
        SharedSignalsMetadata $metadata
    ): array {
        if (!SessionRegistry::acceptSecurityEvent(
            $serverName,
            $metadata->issuer(),
            $settings->sharedSignalsAudience(),
            $event['jti']
        )) {
            return ['jti' => $event['jti'], 'event' => $event['event'], 'count' => 0, 'duplicate' => true];
        }
        try {
            $count = $event['actionable'] && $event['subject_issuer'] !== null
                && ($event['subject'] !== null || $event['session_id'] !== null)
                ? SessionRegistry::terminateForSecurityEvent(
                    $serverName,
                    $event['subject_issuer'],
                    $event['subject'],
                    $event['cutoff'],
                    $event['session_id']
                ) : 0;
        } catch (\Throwable $e) {
            try {
                SessionRegistry::releaseSecurityEvent(
                    $serverName,
                    $metadata->issuer(),
                    $settings->sharedSignalsAudience(),
                    $event['jti']
                );
            } catch (\Throwable $releaseError) {
                syslog(LOG_ERR, 'OIDC: a Shared Signals replay marker could not be released');
            }
            throw $e;
        }
        return ['jti' => $event['jti'], 'event' => $event['event'], 'count' => $count, 'duplicate' => false];
    }
}
