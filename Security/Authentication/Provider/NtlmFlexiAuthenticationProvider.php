<?php

namespace BrowserCreative\NtlmBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmToken;
use BrowserCreative\NtlmBundle\Ntlm\TokenValidatorInterface;

class NtlmFlexiAuthenticationProvider implements AuthenticationProviderInterface
{
    protected $userProvider;
    protected $providerKey;
    protected $tokenValidator;

    public function __construct(UserProviderInterface $userProvider, TokenValidatorInterface $tokenValidator, $providerKey)
    {
        $this->userProvider = $userProvider;
        $this->tokenValidator = $tokenValidator;
        $this->providerKey = $providerKey;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof \BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmToken;
    }

    /**
     * Attempts to authenticate a TokenInterface object.
     *
     * @param NtlmToken $token The TokenInterface instance to authenticate
     * @return TokenInterface An authenticated TokenInterface instance, never null
     * @throws AuthenticationException if the authentication fails
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->tokenValidator->validate($token->getAttribute('challenge'), $token->getAttribute('response'))) {
            throw new AuthenticationException('');
        }

        try {
            $user = $this->userProvider->loadUserByUsername($token->getUsername());

            if ($user == null) {
                throw new UsernameNotFoundException('Ntlm user '.$token->getUsername().' not found locally');
            }

            return new NtlmToken(
                $user,
                array($token->getAttribute('challenge'), $token->getAttribute('response')),
                $token->getProviderKey(),
                array('ROLE_USER')
            );
        } catch(UsernameNotFoundException $e) {
            throw new AuthenticationException($e->getMessage());
        }
    }
}
