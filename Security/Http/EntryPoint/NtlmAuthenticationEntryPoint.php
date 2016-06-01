<?php

/**
 * Contains the NtlmProtocolAuthenticationProvider class
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Authentication\Provider
 */

namespace BrowserCreative\NtlmBundle\Security\Http\EntryPoint;

use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Psr\Log\LoggerInterface;
use BrowserCreative\NtlmBundle\Ntlm\Lib as Ntlm;
use BrowserCreative\NtlmBundle\Ntlm\ChallengeData;

class NtlmAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    /** @var ContainerInterface */
    protected $container;

    /** @var array */
    protected $trustedRemoteAddresses;

    protected $target;
    protected $server;
    protected $domain;
    protected $dnsServer;
    protected $dnsDomain;

    /**
     *
     * @var LoggerInterface
     */
    protected $logger;

    /** @var bool  */
    protected $redirectToFormLogin = false;

    /**
     * @param ContainerInterface $container so we can get the request
     * @param $target
     * @param $server
     * @param $domain
     * @param $dnsServer
     * @param $dnsDomain
     * @param bool $redirectToFormLogin when false, NTLM auth is enforced. When true, if ntlm auth fails, other aut providers can kick in
     * @param array $trustedRemoteAddresses list of IP addresses allowed to authenticate. An empty array means 'let all in'
     */
    public function __construct(
        ContainerInterface $container,
        $target,
        $server,
        $domain,
        $dnsServer,
        $dnsDomain,
        array $trustedRemoteAddresses = array(),
        $redirectToFormLogin = true)
    {
        $this->container = $container;
        $this->target = $target;
        $this->server = $server;
        $this->domain = $domain;
        $this->dnsServer = $dnsServer;
        $this->dnsDomain = $dnsDomain;
        $this->trustedRemoteAddresses = $trustedRemoteAddresses;
        $this->redirectToFormLogin = $redirectToFormLogin;
    }

    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param Request $request
     * @param AuthenticationException|null $authException
     * @return Response|array
     * @throws AuthenticationException
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        /// @todo use $request instead
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $remoteIp = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $remoteIp = $_SERVER['REMOTE_ADDR'];
        }

        $this->logger && $this->logger->info('NTLM Protocol Provider trying to authenticate: ' . $remoteIp);

        if (!$this->isRemoteAddressAuthorised($remoteIp)) {
            $this->logger && $this->logger->info('Remote address is not authorised for NTLM: ' . $remoteIp);
            throw new AuthenticationException('NTLM cannot authenticate against unauthorised IP addresses');
        }

        if ($this->isLoginFormBeingSubmitted()) {
            $message = 'NTLM cannot be used in conjunction with form submits in login';
            $this->logger && $this->logger->info($message);
            throw new AuthenticationException($message);
        }

        if (!$this->isUserAgentDesktopBrowser()) {
            $message = 'NTLM can only be used on desktop computers';
            $this->logger && $this->logger->info($message);
            throw new AuthenticationException($message);
        }

        $response = $this->ntlmPrompt(
            $this->target,
            $this->domain,
            $this->server,
            $this->dnsDomain,
            $this->dnsServer
        );

        if (!$response) {
            $this->logger && $this->logger->info('NTLM auth failed');
            throw new AuthenticationException('The NTLM authentication failed');
        }

        if (is_array($response)) {
            $this->logger && $this->logger->info('NTLM auth successful: ' . $response['response']['user']);
        }

        return $response;
    }

    /// @todo allow regexp matching as well
    public function isRemoteAddressAuthorised($remoteAddress)
    {
        return in_array($remoteAddress, $this->trustedRemoteAddresses);
    }

    /**
     * Validates the computer name and domain name sent by the browser along with the username and password.
     *
     * @param $computerName
     * @param $domainName
     * @return bool
     */
    public function isRemoteComputerAuthorised($computerName, $domainName)
    {
        /// @todo do we need to match using uppercase ?
        if ($domainName == $this->domain) {
            return true;
        }

        $this->logger && $this->logger->info('Remote computer is not authorised for NTLM: "' . $domainName . '/' . $computerName . '"');
        return false;
    }

    /// @todo we should make the /login path flexible, ideally getting it from config
    public function isLoginFormBeingSubmitted()
    {
        if (($this->container->get('request')->getMethod() == "POST") &&
            (substr($this->container->get('request')->getPathInfo(), 0, 6) == '/login')) {

            return true;
        }
        return false;
    }

    public function isUserAgentDesktopBrowser()
    {
        /// @todo can we use Sf Request object instead ?
        if (!isset($_SERVER['HTTP_USER_AGENT'])) {
            return false;
        }

        // Look for mobiles
        if ($this->container->hasParameter('browser_detection.mobile')) {
            preg_match($this->container->getParameter('browser_detection.mobile'), $_SERVER['HTTP_USER_AGENT'], $matches);
            if (count($matches) !== 0) {
                return false;
            }
        }

        // Look for desktops
        if ($this->container->hasParameter('browser_detection.desktop')) {
            preg_match($this->container->getParameter('browser_detection.desktop'), $_SERVER['HTTP_USER_AGENT'], $matches);
            if (count($matches) === 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Code originally from https://github.com/loune/php-ntlm
     *
     * @todo use class constants or config vars for the name of the session vars '_ntlm_auth', '_ntlm_server_challenge'
     * @todo use a class member to hold the auth failed msg
     * @todo throw an auth exception instead of returning null on non-auth ?
     *
     * Docs describing the NTML auth scheme implemented by MS browsers, servers and proxies:
     * https://www.innovation.ch/personal/ronald/ntlm.html
     * https://blogs.msdn.microsoft.com/chiranth/2013/09/20/ntlm-want-to-know-how-it-works/
     *
     * @param $targetName the name of the target to authenticate against
     * @param string $domain e.g. 'DOMAIN'
     * @param string $server name of the server e.g. 'SERVER'
     * @param string $dnsDomain e.g. 'domain.com'
     * @param string $dnsServer e.g. 'server.domain.com'
     * @param string $ntlm_verify_hash_callback
     * @param string $failMsg
     * @return array|null|Response array for valid ntlm response, null for fail, Response for need to redirect
     */
    protected function ntlmPrompt($targetName, $domain, $server, $dnsDomain, $dnsServer, $ntlm_verify_hash_callback = '\BrowserCreative\NtlmBundle\Ntlm\Lib::verify_hash', $failMsg = "<h1>Authentication Required</h1>")
    {
        if (isset($_SESSION['_ntlm_auth']))
            return $_SESSION['_ntlm_auth'];

        /// @todo check if we can use Sf Request instead
        $auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
        if ($auth_header == null && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
        }

        // step 1
        if (!$auth_header) {
            $response = new Response($failMsg);
            $response->headers->set('WWW-Authenticate', Ntlm::get_auth_header_value());
            $response->setStatusCode(401);
            return $response;
        }

        try {
            $received = Ntlm::parse_auth_header($auth_header);
            switch($received['type']) {

                case Ntlm::MSG_TYPE_NEGOTIATE:
                    $data = Ntlm::parse_negotiate_msg($received['message']);

                    $session = $this->container->get('session');
                    /// @todo move this to a call to the token validator ?
                    $challenge = Ntlm::get_random_bytes(8);
                    $session->set('_ntlm_server_challenge', $challenge);

                    $challengeData = new ChallengeData($challenge, $targetName, $domain, $server, $dnsDomain, $dnsServer);
                    $msg = Ntlm::get_challenge_msg($challengeData);

                    $response = new Response($failMsg);
                    $response->headers->set('WWW-Authenticate', Ntlm::get_auth_header_value($msg));
                    $response->setStatusCode(401);
                    return $response;

                case Ntlm::MSG_TYPE_AUTENTICATE:
                    $session = $this->container->get('session');
                    try {
                        $responseData = Ntlm::parse_authenticate_msg($received['message']);

                        if (!$this->isRemoteComputerAuthorised($responseData['domain'], $responseData['workstation'])) {
                            return;
                        }

                        $auth = array(
                            'challenge' => new ChallengeData($session->get('_ntlm_server_challenge'), $targetName, $domain, $server, $dnsDomain, $dnsServer),
                            'response' => $responseData
                        );
                    } catch (\Exception $e) {
                        // invalid client response
                        $this->logger && $this->logger->info('Received from the client an invalid NTLM authenticate message: '.$received['message']);
                    }

                    $session->remove('_ntlm_server_challenge');

                    /// in this case the user browser sent us auth headers which are not deemed valid.
                    ///  @todo We should honour $this->redirectToFormLogin - or maybe just do nothing? => not doing anything for now
                    /*if (!$auth['authenticated']) {
                        $response = new Response($failMsg.$auth['error']);
                        $response->headers->set('WWW-Authenticate', Ntlm::get_auth_header_value());
                        $response->setStatusCode(401);
                        return $response;
                    }*/

                    $this->container->get('session')->set('_ntlm_auth', $auth);

                    return $auth;

                default:
                    // invalid client response - do nothing here: returning null means auth failed
                    $this->logger && $this->logger->info('Received from the client an NTLM message of unknown type: '.$received['message']);
            }
        } catch (\Exception $e) {
            // invalid client response - do nothing here: returning null means auth failed
            $this->logger && $this->logger->info('Received from the client a non-NTLM auth header: '.$auth_header);
        }
    }
}
