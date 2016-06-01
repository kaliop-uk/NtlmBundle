<?php

namespace BrowserCreative\NtlmBundle\Ntlm;

class ChallengeData
{
    public $challenge;
    public $targetname;
    public $domain;
    public $server;
    public $dnsdomain;
    public $dnsserver;

    /**
     * @param string $challenge a *random* 8-byte string
     * @param string $targetname
     * @param string $domain e.g. 'DOMAIN'
     * @param string $server name of the server e.g. 'SERVER'
     * @param string $dnsdomain e.g. 'domain.com'
     * @param string $dnsserver e.g. 'server.domain.com'
     */
    public function __construct($challenge, $targetname, $domain, $server, $dnsdomain, $dnsserver)
    {
        $this->challenge = $challenge;
        $this->targetname = $targetname;
        $this->domain = $domain;
        $this->server = $server;
        $this->dnsdomain = $dnsdomain;
        $this->dnsserver = $dnsserver;
    }
}
