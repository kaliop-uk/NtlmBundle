<?php

namespace BrowserCreative\NtlmBundle\Ntlm;

/**
 * A fork of https://github.com/loune/php-ntlm
 *
 * Original copyright notice:

php ntlm authentication library
Version 1.2

Copyright (c) 2009-2010 Loune Lam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

 */

/**
 * NTLMv2 Helper library.
 * For a description of the protocol, see f.e. https://www.innovation.ch/personal/ronald/ntlm.html,
 * http://davenport.sourceforge.net/ntlm.html as well as https://msdn.microsoft.com/en-us/library/cc236639.aspx
 *
 * Here is a schematic of the communication when NTLM is used over HTTP
 *
 * 1: C  --> S   GET ...
 *
 * 2: C <--  S   401 Unauthorized
 * WWW-Authenticate: NTLM
 *
 * 3: C  --> S   GET ...
 * Authorization: NTLM <base64-encoded negotiate-message>
 *
 * 4: C <--  S   401 Unauthorized
 * WWW-Authenticate: NTLM <base64-encoded challenge-message>
 *
 * 5: C  --> S   GET ...
 * Authorization: NTLM <base64-encoded authenticate-message>
 *
 * 6: C <--  S   200 Ok
 *
 * @todo move all methods to be non-static
 */
class Lib
{
    const MSG_TYPE_NEGOTIATE = "\x01";
    const MSG_TYPE_CHALLENGE = "\x02";
    const MSG_TYPE_AUTENTICATE = "\x03";

    /**
     * @param string $str
     * @return string
     */
    protected static function utf8_to_utf16le($str) {
        //$result = "";
        //for ($i = 0; $i < strlen($str); $i++)
        //    $result .= $str[$i]."\0";
        //return $result;
        return iconv('UTF-8', 'UTF-16LE', $str);
    }

    protected static function md4($s) {
        if (function_exists('mhash'))
            return mhash(MHASH_MD4, $s);
        return pack('H*', hash('md4', $s));
    }

    /**
     * @param string $type
     * @param string $utf16
     * @return string
     */
    protected static function av_pair($type, $utf16) {
        return pack('v', $type).pack('v', strlen($utf16)).$utf16;
    }

    /**
     * @param string $msg
     * @param int $start
     * @param bool $decode_utf16
     * @return string
     */
    protected static function field_value($msg, $start, $decode_utf16 = true) {
        $len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
        $off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
        $result = substr($msg, $off, $len);
        if ($decode_utf16) {
            //$result = str_replace("\0", '', $result);
            $result = iconv('UTF-16LE', 'UTF-8', $result);
        }
        return $result;
    }

    /**
     * @param string $key
     * @param string $msg
     * @return string
     */
    protected static function hmac_md5($key, $msg) {
        $blocksize = 64;
        if (strlen($key) > $blocksize)
            $key = pack('H*', md5($key));

        $key = str_pad($key, $blocksize, "\0");
        $ipadk = $key ^ str_repeat("\x36", $blocksize);
        $opadk = $key ^ str_repeat("\x5c", $blocksize);
        return pack('H*', md5($opadk.pack('H*', md5($ipadk.$msg))));
    }

    /**
     * Parses auth headers received by the Client
     * @param string $auth_header
     * @return array keys: message, type
     * @throws \Exception
     */
    public static function parse_auth_header($auth_header) {
        if (substr($auth_header,0,5) == 'NTLM ') {
            $msg = base64_decode(substr($auth_header, 5));
            if (substr($msg, 0, 8) != "NTLMSSP\x00") {
                //unset($_SESSION['_ntlm_post_data']);
                throw new \Exception('NTLM error header not recognised');
            }
            if ($msg[8] == static::MSG_TYPE_AUTENTICATE || $msg[8] == static::MSG_TYPE_NEGOTIATE) {
                return array(
                    'message' => $msg,
                    'type' => $msg[8]
                );
            }
        } else {
            throw new \Exception('Auth headers is not NTLM');
        }
    }

    /**
     * @param string $msg
     * @return string the header value to be used in an 'WWW-Authenticate' header
     */
    public static function get_auth_header_value($msg='') {
        if ($msg == '') {
            return 'NTLM';
        }
        return 'NTLM '.trim(base64_encode($msg));
    }

    /**
     * Generates a sequence of random bytes
     * @todo use crypto-safe random function
     * @param int $length
     * @return string
     */
    public static function get_random_bytes($length) {
        $result = "";
        for ($i = 0; $i < $length; $i++) {
            $result .= chr(rand(0, 255));
        }
        return $result;
    }

    /**
     * @param $msg the 1st NTLM message sent from the Client
     * @return array keys: domain, workstation
     *
     * @todo add decoding of the optional 'os version structure'
     */
    public static function parse_negotiate_msg($msg) {
        return array(
            'domain' => static::field_value($msg, 16),
            'workstation' => static::field_value($msg, 24)
        );
    }

    /**
     * Generates the 'challenge message' to be sent back to the client in step 4
     *
     * @param ChallengeData $challengeData
     * @return string
     */
    public static function get_challenge_msg(ChallengeData $challengeData) {
        /*$domain = static::field_value($msg, 16);
        $workstation = static::field_value($msg, 24);*/
        $tdata = static::av_pair(2, static::utf8_to_utf16le($challengeData->domain)).static::av_pair(1, static::utf8_to_utf16le($challengeData->server)).static::av_pair(4, static::utf8_to_utf16le($challengeData->dnsdomain)).static::av_pair(3, static::utf8_to_utf16le($challengeData->dnsserver))."\0\0\0\0\0\0\0\0";
        $tname = static::utf8_to_utf16le($challengeData->targetname);
        $msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
            pack('vvV', strlen($tname), strlen($tname), 48). // target name len/alloc/offset
            "\x01\x02\x81\x00". // flags
            $challengeData->challenge. // challenge
            "\x00\x00\x00\x00\x00\x00\x00\x00". // context
            pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)). // target info len/alloc/offset
            $tname.$tdata;
        return $msg2;
    }

    /**
     * Parses the NTLM authenticate message received from the Client in step 5
     * @param string $msg
     * @return array
     * @throws \Exception
     *
     * @todo use a structured class instead of an array as return type
     */
    public static function parse_authenticate_msg($msg) {
        $ntlmresponse = static::field_value($msg, 20, false);
        $data = array(
            'user' => static::field_value($msg, 36),
            'domain' => static::field_value($msg, 28),
            'workstation' => static::field_value($msg, 44),
            'ntlmresponse' => $ntlmresponse,
            //$blob = "\x01\x01\x00\x00\x00\x00\x00\x00".$timestamp.$nonce."\x00\x00\x00\x00".$tdata;
            'clientblob' => substr($ntlmresponse, 16),
            'clientblobhash' => substr($ntlmresponse, 0, 16),
        );

        if (substr($data['clientblob'], 0, 8) != "\x01\x01\x00\x00\x00\x00\x00\x00") {
            throw new \Exception('NTLMv2 response required. Please force your client to use NTLMv2.');
        }

        return $data;
    }

    /**
     * NB: logic moved to auth provider + token validator
     *
     * Verifies the message received from the Client in step 5
     *
     * @param array $data the parsed data gotten from the NTLM authenticate message sent from the Client (see parse_authenticate_msg)
     * @param string $challenge the sequence of random bytes which was used to generate the challenge
     * @param callable $ntlm_verify_hash_callback Check that the ntlm hash received from the browser corresponds to the one calculated for the local user
     *                                            params: $challenge, $data; return: bool
     * @return array
     * @throws \Exception
     */
    /*public static function verify_authenticate_msg($challenge, $data, $ntlm_verify_hash_callback) {
        $authenticated = call_user_func_array($ntlm_verify_hash_callback, array($challenge, $data));
        if (!$authenticated)
            return array('authenticated' => false, 'error' => 'Incorrect username or password.', 'username' => $data['user'], 'domain' => $data['domain'], 'workstation' => $data['workstation']);
        return array('authenticated' => true, 'username' => $data['user'], 'domain' => $data['domain'], 'workstation' => $data['workstation']);
    }*/

    /* *** example callbacks *** */
    /// @todo move to token validators

    /**
     * Example callback: get the password hash of a user via invocation of a C program based on having a local Samba user db
     */
    private static function verify_hash_smb($challenge, $data) {
        $cmd = bin2hex($challenge)." ".bin2hex(static::utf8_to_utf16le(strtoupper($data['user'])))." ".
            bin2hex(static::utf8_to_utf16le($data['domain']))." ".bin2hex(static::utf8_to_utf16le($data['workstation'])).
            " ".bin2hex($data['clientblobhash'])." ".bin2hex($data['clientblob']);
        return (shell_exec("/sbin/verifyntlm " . $cmd) == "1\n");
    }

    /**
     * Example callback - for when we have access to the database of users and passwords
     */
    private static function verify_hash($challenge, $data) {
        $md4hash = static::get_ntlm_user_hash($data['user']);
        if (!$md4hash)
            return false;
        $ntlmv2hash = static::hmac_md5($md4hash, static::utf8_to_utf16le(strtoupper($data['user']).$data['domain']));
        $blobhash = static::hmac_md5($ntlmv2hash, $challenge.$data['clientblob']);

        return ($blobhash == $data['clientblobhash']);
    }

    /**
     * Subroutine for the example callback: generate the ntlm password hash of a user account
     */
    private static function get_ntlm_user_hash($user) {
        $userdb = array('admin'=>'admin');
        if (!isset($userdb[strtolower($user)]))
            return false;
        $pwd = $userdb[strtolower($user)];

        return static::md4(static::utf8_to_utf16le($pwd));
    }

}