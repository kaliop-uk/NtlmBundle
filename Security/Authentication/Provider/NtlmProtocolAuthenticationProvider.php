<?php

/**
 * Contains the NtlmProtocolAuthenticationProvider class
 *
 * @author     Miquel Rodríguez Telep / Michael Rodríguez-Torrent <mike@themikecam.com>
 * @author     Ka Yue Yeung
 * @package    BrowserCreative\NtlmBundle
 * @subpackage Security\Authentication\Provider
 */

namespace BrowserCreative\NtlmBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use BrowserCreative\NtlmBundle\Ntlm\Lib as Ntlm;

use BrowserCreative\NtlmBundle\Security\Authentication\Token\NtlmProtocolToken;

/**
 * @todo make logger injectable
 */
class NtlmProtocolAuthenticationProvider implements AuthenticationProviderInterface
{
    /** @var ContainerInterface */
    protected $container;

    /** @var UserProviderInterface */
    protected $userProvider;

    /** @var array */
    protected $trustedRemoteAddresses;

    protected $target;
    protected $server;
    protected $domain;
    protected $dnsServer;
    protected $dnsDomain;

    /** @var bool  */
    protected $redirectToFormLogin = false;

    /**
     * @param ContainerInterface $container so we can get the request
     * @param UserProviderInterface $userProvider
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
        UserProviderInterface $userProvider,
        $target,
        $server,
        $domain,
        $dnsServer,
        $dnsDomain,
        $redirectToFormLogin = true,
        array $trustedRemoteAddresses = array())
    {
        $this->container = $container;
        $this->userProvider = $userProvider;
        $this->target = $target;
        $this->server = $server;
        $this->domain = $domain;
        $this->dnsServer = $dnsServer;
        $this->dnsDomain = $dnsDomain;
        $this->redirectToFormLogin = $redirectToFormLogin;
        $this->trustedRemoteAddresses = $trustedRemoteAddresses;
    }

    public function authenticate(TokenInterface $token)
    {
        $logger = $this->container->get('logger');

        /// @todo can we use Sf Request object instead ?
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $remoteIp = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $remoteIp = $_SERVER['REMOTE_ADDR'];
        }

        $logger->info('NTLM Protocol Provider trying to authenticate: ' . $remoteIp);

        if (!$this->isRemoteAddressAuthorised($remoteIp)) {
            $logger->info('Remote address is not authorised for NTLM: ' . $remoteIp);
            throw new AuthenticationException('NTLM cannot authenticate against unauthorised IP addresses');
        }

        if ($this->isLoginFormBeingSubmitted()) {
            $message = 'NTLM cannot be used in conjunction with form submits in login';
            $logger->info($message);
            throw new AuthenticationException($message);
        }

        if (!$this->isUserAgentDesktopBrowser()) {
            $message = 'NTLM can only be used on desktop computers';
            $logger->info($message);
            throw new AuthenticationException($message);
        }

        $username = $this->checkNtlm();

        if ($username) {
            $user = $this->container->get('user.entity');
            $user->setUsername($username);
            $token->setUser($user);

            try {
                /**
                 * Token is passed to loadUserByUsername as we require the credentials for
                 * the LDAP provider. Unfortunately, we cannot use another function, as
                 * ChainUserProvider will fire off the same function which is out of our
                 * control.
                 */
                $user = $this->userProvider->loadUserByUsername($token);

                $this->container->get('session')->set('ntlm-user', true);

                $logger->info('NTLM: user loaded: ' . $username);

                return new NtlmProtocolToken($user);
            } catch (UsernameNotFoundException $e) {
                $logger->info('Username not found: ' . $username);
            }
        }

        throw new AuthenticationException('The NTLM authentication failed');
    }

    /**
     * @return array
     */
    public function checkNtlm()
    {
        $logger = $this->container->get('logger');

        $username = $this->ntlmPrompt(
            $this->target,
            $this->domain,
            $this->server,
            $this->dnsDomain,
            $this->dnsServer,
            '\BrowserCreative\NtlmBundle\Ntlm\Lib::get_ntlm_user_hash'
        );

        if (!$username) {
            $logger->info('NTLM auth failed');
            throw new AuthenticationException('The NTLM authentication failed');
        }

        $logger->info('NTLM auth successful: ' . $username);
        return $username;
    }

    /// @todo allow regexp matching as well
    public function isRemoteAddressAuthorised($remoteAddress)
    {
        return in_array($remoteAddress, $this->trustedRemoteAddresses);
    }

    /// @todo do we need to match using uppercase ?
    public function isRemoteComputerAuthorised($computerName, $domainName)
    {
        if ($domainName == $this->domain) {
            return true;
        }

        $logger = $this->container->get('logger');
        $logger->info('Remote computer is not authorised for NTLM: ' . $domainName . '/' . $computerName);
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
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     *
     * @return Boolean true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof NtlmProtocolToken;
    }

    /**
     * Code originally from https://github.com/loune/php-ntlm
     *
     * @todo use class constants or config vars for the name of the session vars '_ntlm_auth', '_ntlm_server_challenge'
     * @todo move this method to an EntryPoint class (see DigestAuthenticationEntryPoint)
     * @todo use a class member to hold the auth failed msg
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
     * @param $get_ntlm_user_hash_callback
     * @param string $ntlm_verify_hash_callback
     * @param string $failMsg
     * @return array|null
     */
    protected function ntlmPrompt($targetName, $domain, $server, $dnsDomain, $dnsServer, $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback = '\BrowserCreative\NtlmBundle\Ntlm\Lib::verify_hash', $failMsg = "<h1>Authentication Required</h1>")
    {
        if (isset($_SESSION['_ntlm_auth']))
            return $_SESSION['_ntlm_auth'];

        /// @todo check if we can use Sf Request instead
        $auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
        if ($auth_header == null && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
        }

        // post data retention, looks like not needed
        /*if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $_SESSION['_ntlm_post_data'] = $_POST;
        }*/

        // step 1
        if (!$auth_header) {
            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: NTLM');
            print $failMsg;
            exit;
        }

        if (substr($auth_header,0,5) == 'NTLM ') {
            $msg = base64_decode(substr($auth_header, 5));
            if (substr($msg, 0, 8) != "NTLMSSP\x00") {
                //unset($_SESSION['_ntlm_post_data']);
                /// @todo write warning or info log message
                throw new AuthenticationException('NTLM error header not recognised');
            }
            if ($msg[8] == "\x01") {
                $data = Ntlm::parse_negotiate_msg($msg);
                if (!$this->isRemoteComputerAuthorised($data['domain'], $data['workstation'])) {
                    return;
                }

                $session = $this->container->get('session');
                $challenge = Ntlm::get_random_bytes(8);
                $session->set('_ntlm_server_challenge', $challenge);

                /// @todo allow validation of workstation/domain received from the client
                $msg2 = Ntlm::get_challenge_msg($challenge, $targetName, $domain, $server, $dnsDomain, $dnsServer);
                //$_SESSION['_ntlm_server_challenge'] = Ntlm::get_random_bytes(8);
                header('HTTP/1.1 401 Unauthorized');
                header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
                //print bin2hex($msg2);
                exit;
            } else if ($msg[8] == "\x03") {
                $session = $this->container->get('session');

                $auth = Ntlm::verify_authenticate_msg($msg, $session->get('_ntlm_server_challenge'), $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback);
                $session->remove('_ntlm_server_challenge');
                //unset($_SESSION['_ntlm_server_challenge']);

                /// @todo in this case the user browser sent us auth headers which are not deemed valid.
                ///       We should honour $this->redirectToFormLogin
                if (!$auth['authenticated']) {
                    header('HTTP/1.1 401 Unauthorized');
                    header('WWW-Authenticate: NTLM');
                    //unset($_SESSION['_ntlm_post_data']);
                    print $failMsg;
                    print $auth['error'];
                    exit;
                }

                // post data retention looks like not needed
                /*if (isset($_SESSION['_ntlm_post_data'])) {
                    foreach ($_SESSION['_ntlm_post_data'] as $k => $v) {
                        $_REQUEST[$k] = $v;
                        $_POST[$k] = $v;
                    }
                    $_SERVER['REQUEST_METHOD'] = 'POST';
                    unset($_SESSION['_ntlm_post_data']);
                }*/

                $this->container->get('session')->set('_ntlm_auth', $auth);
                //$_SESSION['_ntlm_auth'] = $auth;

                return $auth;
            }
        }
    }
}
