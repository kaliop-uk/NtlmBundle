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

class Lib
{
    protected $ntlm_verifyntlmpath = '/sbin/verifyntlm';

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
     * @param string $msg
     * @param string $challenge
     * @param string $targetname
     * @param string $domain
     * @param string $computer
     * @param string $dnsdomain
     * @param string $dnscomputer
     * @return string
     */
    public static function get_challenge_msg($msg, $challenge, $targetname, $domain, $computer, $dnsdomain, $dnscomputer) {
        $domain = static::field_value($msg, 16);
        $ws = static::field_value($msg, 24);
        $tdata = static::av_pair(2, static::utf8_to_utf16le($domain)).static::av_pair(1, static::utf8_to_utf16le($computer)).static::av_pair(4, static::utf8_to_utf16le($dnsdomain)).static::av_pair(3, static::utf8_to_utf16le($dnscomputer))."\0\0\0\0\0\0\0\0";
        $tname = static::utf8_to_utf16le($targetname);
        $msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
            pack('vvV', strlen($tname), strlen($tname), 48). // target name len/alloc/offset
            "\x01\x02\x81\x00". // flags
            $challenge. // challenge
            "\x00\x00\x00\x00\x00\x00\x00\x00". // context
            pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)). // target info len/alloc/offset
            $tname.$tdata;
        return $msg2;
    }

    /**
     * Example callback: generate the ntlm password hash of a user account
     */
    static function get_ntlm_user_hash($user) {
        $userdb = array('admin'=>'admin');
        if (!isset($userdb[strtolower($user)]))
            return false;
        $pwd = $userdb[strtolower($user)];

        return static::md4(static::utf8_to_utf16le($pwd));
    }

    /**
     * Example callback: get the password hash of a user via invocation of a C program based on having a local Samba user db
     */
    static function verify_hash_smb($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash_callback) {
        $cmd = bin2hex($challenge)." ".bin2hex(static::utf8_to_utf16le(strtoupper($user)))." ".bin2hex(static::utf8_to_utf16le($domain))." ".bin2hex(static::utf8_to_utf16le($workstation))." ".bin2hex($clientblobhash)." ".bin2hex($clientblob);
        return (shell_exec(self::$ntlm_verifyntlmpath . " $cmd") == "1\n");
    }

    /**
     * Example callback
     *
     */
    static function verify_hash($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash_callback) {
        $md4hash = call_user_func_array($get_ntlm_user_hash_callback, array($user));
        if (!$md4hash)
            return false;
        $ntlmv2hash = static::hmac_md5($md4hash, static::utf8_to_utf16le(strtoupper($user).$domain));
        $blobhash = static::hmac_md5($ntlmv2hash, $challenge.$clientblob);

        /*
        print $domain ."<br>";
        print $user ."<br>";
        print bin2hex($challenge )."<br>";
        print bin2hex($clientblob )."<br>";
        print bin2hex($clientblobhash )."<br>";
        print bin2hex($md4hash )."<br>";
        print bin2hex($ntlmv2hash)."<br>";
        print bin2hex($blobhash)."<br>"; die; */
        return ($blobhash == $clientblobhash);
    }

    /**
     * @param string $msg
     * @param string $challenge
     * @param callable $get_ntlm_user_hash_callback Given the username $user, retrieve his/her password, and return it in ntlm_user_hash format
     *                                              params: $user; return string|false
     * @param callable $ntlm_verify_hash_callback Check that the ntlm hash received from the browser corresponds to the one calculated for the local user
     *                                            params: $challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash_callback; returns bool
     * @return array
     */
    public static function parse_response_msg($msg, $challenge, $get_ntlm_user_hash_callback, $ntlm_verify_hash_callback) {
        $user = static::field_value($msg, 36);
        $domain = static::field_value($msg, 28);
        $workstation = static::field_value($msg, 44);
        $ntlmresponse = static::field_value($msg, 20, false);
        //$blob = "\x01\x01\x00\x00\x00\x00\x00\x00".$timestamp.$nonce."\x00\x00\x00\x00".$tdata;
        $clientblob = substr($ntlmresponse, 16);
        $clientblobhash = substr($ntlmresponse, 0, 16);
        if (substr($clientblob, 0, 8) != "\x01\x01\x00\x00\x00\x00\x00\x00") {
            return array('authenticated' => false, 'error' => 'NTLMv2 response required. Please force your client to use NTLMv2.');
        }

        // print bin2hex($msg)."<br>";

        $authenticated = call_user_func_array($ntlm_verify_hash_callback, array($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob, $get_ntlm_user_hash_callback));
        if (!$authenticated)
            return array('authenticated' => false, 'error' => 'Incorrect username or password.', 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
        return array('authenticated' => true, 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
    }
}