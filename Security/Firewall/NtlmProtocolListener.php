<?php

/**
 * Contains the NtlmProtocolListener class
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Firewall
 */

namespace BrowserCreative\NtlmBundle\Security\Firewall;

use BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmToken;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\SecurityEvents;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

/**
 * NtlmProtocolListener checks whether the user has been authenticated against the NTLM protocol
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Firewall
 *
 * @todo rename to NtlmAuthenticationListener
 */
class NtlmProtocolListener implements ListenerInterface
{

    /**
     *
     * @var tokenStorageInterface
     */
    protected $tokenStorage;

    /**
     *
     * @var AuthenticationEntryPointInterface
     */
    protected $authenticationEntryPoint;

    protected $authProvider;

    protected $providerKey;

    /**
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     *
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * If true, will redirect to the login form
     *
     * @var boolean
     */
    //protected $redirectToFormLogin = false;

    public function __construct(TokenStorageInterface $tokenStorage,
            AuthenticationEntryPointInterface $authenticationEntryPoint,
            AuthenticationProviderInterface $authProvider, $providerKey,
            LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null
        )
    {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->authProvider = $authProvider;
        $this->providerKey = $providerKey;
        $this->logger = $logger;
        $this->dispatcher = $dispatcher;
    }

    /**
     * @todo restructure to match more closely the code in DigestAuthenticationListener:
     *       - use $event->setResponse to send back responses
     *       - use an authenticationEntryPoint class instead of the authenticationManager one
     *
     * @param GetResponseEvent $event
     * @return null
     */
    public function handle(GetResponseEvent $event)
    {
        // Don't try to authenticate again if the user already has been
        /// @todo should we check that the token is authenticated before returning?
        if ($this->tokenStorage->getToken()) {
            return;
        }

        try {
            $response = $this->authenticationEntryPoint->start($event->getRequest());

            /// @todo check for a Response object, not just any object
            if (is_object($response)) {
                $event->setResponse($response);
                return;
            }

            $token = new NtlmToken($response['response']['user'], $response, $this->providerKey);

            // the auth provider does both validate the NTLM response and load the Sf user
            if ($authenticatedToken = $this->authProvider->authenticate($token)) {
                $this->tokenStorage->setToken($authenticatedToken);

                // Notify listeners that the user has been logged in
                /// @todo is this necessary? f.e. DigestAuthenticationListener does not do it...
                /*if ($this->dispatcher) {
                    $this->dispatcher->dispatch(SecurityEvents::INTERACTIVE_LOGIN,
                        new InteractiveLoginEvent($event->getRequest(), $token));
                }*/

                if ($this->logger) {
                    $this->logger->debug(sprintf(
                        'NTLM user "%s" authenticated', $token->getUsername()));
                }
            }

        } catch (AuthenticationException $e) {
        }
    }
}
