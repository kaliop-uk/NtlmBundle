<?php

namespace BrowserCreative\NtlmBundle\Ntlm;

class SmbHelperTokenValidator implements TokenValidatorInterface
{
    protected $helperPath = 'ntlm_auth';

    public function __construct()
    {
    }

    /**
     * @param ChallengeData $challenge
     * @param array $response
     * @return bool
     *
     * @todo use the ntlm_auth helper from samba, in mode 'squid-2.5-ntlmssp'...
     * @see https://www.samba.org/samba/docs/man/manpages/ntlm_auth.1.html http://devel.squid-cache.org/ntlm/squid_helper_protocol.html
     */
    public function validate(ChallengeData $challenge, array $response)
    {
        /*var_dump($challenge);
        var_dump($response);
        die();*/
        return true;
    }
}
