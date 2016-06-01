<?php

namespace BrowserCreative\NtlmBundle\Ntlm;

/**
 * @todo we might need to add to this interface a call to generate a challenge (needed for the ntlm_auth helper)
 */
interface TokenValidatorInterface
{
    /**
     * @param ChallengeData $challenge
     * @param array $response
     * @return bool
     */
    public function validate(ChallengeData $challenge, array $response);
}
