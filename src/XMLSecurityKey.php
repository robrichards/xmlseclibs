<?php
namespace RobRichards\XMLSecLibs;

use DOMElement;
use Exception;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\TripleDES;
use phpseclib3\File\X509;

/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2026, Robert Richards <rrichards@cdatazone.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author    Robert Richards <rrichards@cdatazone.org>
 * @copyright 2007-2026 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

class XMLSecurityKey
{
    const TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
    const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
    const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
    const AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
    const AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';
    const AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
    const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    const RSA_OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
    const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
    const HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
    const RSA_SHA256_MGF1 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
    const AUTHTAG_LENGTH = 16;

    /** @var array */
    private $cryptParams = array();

    /** @var int|string */
    public $type = 0;

    /** @var mixed|null */
    public $key = null;

    /** @var string  */
    public $passphrase = "";

    /** @var string|null */
    public $iv = null;

    /** @var string|null */
    public $name = null;

    /** @var mixed|null */
    public $keyChain = null;

    /** @var bool */
    public $isEncrypted = false;

    /** @var XMLSecEnc|null */
    public $encryptedCtx = null;

    /** @var mixed|null */
    public $guid = null;

    /**
     * This variable contains the certificate as a string if this key represents an X509-certificate.
     * If this key doesn't represent a certificate, this will be null.
     * @var string|null
     */
    private $x509Certificate = null;

    /**
     * This variable contains the certificate thumbprint if we have loaded an X509-certificate.
     * @var string|null
     */
    private $X509Thumbprint = null;

    /**
     * @param string $type
     * @param null|array $params
     * @throws Exception
     */
    public function __construct($type, $params=null)
    {
        switch ($type) {
            case (self::TRIPLEDES_CBC):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['cipher'] = 'tripledes';
                $this->cryptParams['mode'] = 'cbc';
                $this->cryptParams['type'] = 'symmetric';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
                $this->cryptParams['keysize'] = 24;
                $this->cryptParams['blocksize'] = 8;
                $this->cryptParams['ivsize'] = 8;
                break;
            case (self::AES128_CBC):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['cipher'] = 'aes';
                $this->cryptParams['mode'] = 'cbc';
                $this->cryptParams['type'] = 'symmetric';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
                $this->cryptParams['keysize'] = 16;
                $this->cryptParams['blocksize'] = 16;
                $this->cryptParams['ivsize'] = 16;
                break;
            case (self::AES192_CBC):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['cipher'] = 'aes';
                $this->cryptParams['mode'] = 'cbc';
                $this->cryptParams['type'] = 'symmetric';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
                $this->cryptParams['keysize'] = 24;
                $this->cryptParams['blocksize'] = 16;
                $this->cryptParams['ivsize'] = 16;
                break;
            case (self::AES256_CBC):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['cipher'] = 'aes';
                $this->cryptParams['mode'] = 'cbc';
                $this->cryptParams['type'] = 'symmetric';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
                $this->cryptParams['keysize'] = 32;
                $this->cryptParams['blocksize'] = 16;
                $this->cryptParams['ivsize'] = 16;
                break;
            case (self::AES128_GCM):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['cipher'] = 'aes';
                $this->cryptParams['mode'] = 'gcm';
                $this->cryptParams['type'] = 'symmetric';
                $this->cryptParams['method'] = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
                $this->cryptParams['keysize'] = 16;
                $this->cryptParams['blocksize'] = 16;
                $this->cryptParams['ivsize'] = 12;
                break;
            case (self::AES192_GCM):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['cipher'] = 'aes';
                $this->cryptParams['mode'] = 'gcm';
                $this->cryptParams['type'] = 'symmetric';
                $this->cryptParams['method'] = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';
                $this->cryptParams['keysize'] = 24;
                $this->cryptParams['blocksize'] = 16;
                $this->cryptParams['ivsize'] = 12;
                break;
            case (self::AES256_GCM):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['cipher'] = 'aes';
                $this->cryptParams['mode'] = 'gcm';
                $this->cryptParams['type'] = 'symmetric';
                $this->cryptParams['method'] = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
                $this->cryptParams['keysize'] = 32;
                $this->cryptParams['blocksize'] = 16;
                $this->cryptParams['ivsize'] = 12;
                break;
            case (self::RSA_1_5):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['padding'] = RSA::ENCRYPTION_PKCS1;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_OAEP_MGF1P):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['padding'] = RSA::ENCRYPTION_OAEP;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
                $this->cryptParams['digest'] = 'sha1';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_OAEP):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['padding'] = RSA::ENCRYPTION_OAEP;
                $this->cryptParams['method'] = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
                $this->cryptParams['digest'] = 'sha256';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA1):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['method'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
                $this->cryptParams['padding'] = RSA::SIGNATURE_PKCS1;
                $this->cryptParams['digest'] = 'sha1';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA256):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
                $this->cryptParams['padding'] = RSA::SIGNATURE_PKCS1;
                $this->cryptParams['digest'] = 'sha256';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::ECDSA_SHA256):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
                $this->cryptParams['digest'] = 'SHA256';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA384):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
                $this->cryptParams['padding'] = RSA::SIGNATURE_PKCS1;
                $this->cryptParams['digest'] = 'sha384';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA512):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
                $this->cryptParams['padding'] = RSA::SIGNATURE_PKCS1;
                $this->cryptParams['digest'] = 'sha512';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            case (self::HMAC_SHA1):
                $this->cryptParams['library'] = $type;
                $this->cryptParams['method'] = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
                break;
            case (self::RSA_SHA256_MGF1):
                $this->cryptParams['library'] = 'phpseclib';
                $this->cryptParams['method'] = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
                $this->cryptParams['padding'] = RSA::SIGNATURE_PSS;
                $this->cryptParams['digest'] = 'sha256';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new Exception('Certificate "type" (private/public) must be passed via parameters');
            default:
                throw new Exception('Invalid Key Type');
        }
        $this->type = $type;
    }

    /**
     * Retrieve the key size for the symmetric encryption algorithm..
     *
     * If the key size is unknown, or this isn't a symmetric encryption algorithm,
     * null is returned.
     *
     * @return int|null  The number of bytes in the key.
     */
    public function getSymmetricKeySize()
    {
        if (! isset($this->cryptParams['keysize'])) {
            return null;
        }
        return $this->cryptParams['keysize'];
    }

    /**
     * Generates a session key.
     * In case of using DES3-CBC the key is checked for a proper parity bits set.
     * @return string
     * @throws Exception
     */
    public function generateSessionKey()
    {
        if (!isset($this->cryptParams['keysize'])) {
            throw new Exception('Unknown key size for type "' . $this->type . '".');
        }
        $keysize = $this->cryptParams['keysize'];

        $key = random_bytes($keysize);

        if ($this->type === self::TRIPLEDES_CBC) {
            /* Make sure that the generated key has the proper parity bits set.
             * Mcrypt doesn't care about the parity bits, but others may care.
            */
            for ($i = 0; $i < strlen($key); $i++) {
                $byte = ord($key[$i]) & 0xfe;
                $parity = 1;
                for ($j = 1; $j < 8; $j++) {
                    $parity ^= ($byte >> $j) & 1;
                }
                $byte |= $parity;
                $key[$i] = chr($byte);
            }
        }

        $this->key = $key;
        return $key;
    }

    /**
     * Get the raw thumbprint of a certificate
     *
     * @param string $cert
     * @return null|string
     */
    public static function getRawThumbprint($cert)
    {

        $arCert = explode("\n", $cert);
        $data = '';
        $inData = false;

        foreach ($arCert AS $curData) {
            if (! $inData) {
                if (strncmp($curData, '-----BEGIN CERTIFICATE', 22) == 0) {
                    $inData = true;
                }
            } else {
                if (strncmp($curData, '-----END CERTIFICATE', 20) == 0) {
                    break;
                }
                $data .= trim($curData);
            }
        }

        if (! empty($data)) {
            return strtolower(sha1(base64_decode($data)));
        }

        return null;
    }

    /**
     * Loads the given key, or - with isFile set true - the key from the keyfile.
     *
     * @param string $key
     * @param bool $isFile
     * @param bool $isCert
     * @throws Exception
     */
    public function loadKey($key, $isFile=false, $isCert = false)
    {
        if ($isFile) {
            $this->key = file_get_contents($key);
        } else {
            $this->key = $key;
        }
        if ($isCert) {
            $x509 = new X509();
            $certData = $x509->loadX509($this->key);
            if ($certData === false) {
                throw new Exception('Unable to extract certificate');
            }
            $str_cert = $x509->saveX509($certData);
            if ($str_cert === false) {
                throw new Exception('Unable to export certificate');
            }
            $this->x509Certificate = $str_cert;
            $this->key = $str_cert;
            $this->X509Thumbprint = self::getRawThumbprint($this->key);
        } else {
            $this->x509Certificate = null;
        }
        if (($this->cryptParams['type'] ?? null) === 'symmetric') {
            if (strlen($this->key) < $this->cryptParams['keysize']) {
                throw new Exception('Key must contain at least '.$this->cryptParams['keysize'].' characters for this cipher, contains '.strlen($this->key));
            }
        }
    }

    /**
     * ISO 10126 Padding
     *
     * @param string $data
     * @param integer $blockSize
     * @throws Exception
     * @return string
     */
    private function padISO10126($data, $blockSize)
    {
        if ($blockSize > 256) {
            throw new Exception('Block size higher than 256 not allowed');
        }
        $padChr = $blockSize - (strlen($data) % $blockSize);
        $pattern = chr($padChr);
        return $data . str_repeat($pattern, $padChr);
    }

    /**
     * Remove ISO 10126 Padding
     *
     * @param string $data
     * @return string
     */
    private function unpadISO10126($data)
    {
        $padChr = substr($data, -1);
        $padLen = ord($padChr);
        return substr($data, 0, -$padLen);
    }

    /**
     * @return AES|TripleDES
     * @throws Exception
     */
    private function createSymmetricCipher()
    {
        $mode = $this->cryptParams['mode'];
        if ($this->cryptParams['cipher'] === 'aes') {
            $cipher = new AES($mode);
        } elseif ($this->cryptParams['cipher'] === 'tripledes') {
            $cipher = new TripleDES($mode);
        } else {
            throw new Exception('Unknown symmetric cipher');
        }
        /* Match OpenSSL behaviour: truncate overlong keys to the algorithm size. */
        $key = $this->key;
        if (isset($this->cryptParams['keysize']) && strlen($key) > $this->cryptParams['keysize']) {
            $key = substr($key, 0, $this->cryptParams['keysize']);
        }
        $cipher->setKey($key);
        return $cipher;
    }

    /**
     * Encrypts the given data (string) using phpseclib
     *
     * @param string $data
     * @return string
     * @throws Exception
     */
    private function encryptSymmetric($data)
    {
        $this->iv = random_bytes($this->cryptParams['ivsize']);
        $cipher = $this->createSymmetricCipher();
        $authTag = null;

        if ($this->cryptParams['mode'] === 'gcm') {
            $cipher->setNonce($this->iv);
            $encrypted = $cipher->encrypt($data);
            $authTag = $cipher->getTag(self::AUTHTAG_LENGTH);
        } else {
            $data = $this->padISO10126($data, $this->cryptParams['blocksize']);
            $cipher->disablePadding();
            $cipher->setIV($this->iv);
            $encrypted = $cipher->encrypt($data);
        }

        if ($encrypted === false) {
            throw new Exception('Failure encrypting Data (phpseclib symmetric)');
        }
        return $this->iv . $encrypted . $authTag;
    }

    /**
     * Decrypts the given data (string) using phpseclib
     *
     * @param string $data
     * @return string
     * @throws Exception
     */
    private function decryptSymmetric($data)
    {
        $iv_length = $this->cryptParams['ivsize'];
        $this->iv = substr($data, 0, $iv_length);
        $data = substr($data, $iv_length);
        $cipher = $this->createSymmetricCipher();
        $authTag = null;

        if ($this->cryptParams['mode'] === 'gcm') {
            $offset = 0 - self::AUTHTAG_LENGTH;
            $authTag = substr($data, $offset);
            if (strlen($authTag) !== self::AUTHTAG_LENGTH) {
                throw new Exception('Authentication tag length is invalid');
            }
            $data = substr($data, 0, $offset);
            $cipher->setNonce($this->iv);
            $cipher->setTag($authTag);
            $decrypted = $cipher->decrypt($data);
        } else {
            $cipher->disablePadding();
            $cipher->setIV($this->iv);
            $decrypted = $cipher->decrypt($data);
        }

        if ($decrypted === false) {
            throw new Exception('Failure decrypting Data (phpseclib symmetric)');
        }
        return null !== $authTag ? $decrypted : $this->unpadISO10126($decrypted);
    }

    /**
     * Apply padding / digest options to a phpseclib RSA key.
     *
     * @param mixed $key
     * @return mixed
     */
    private function configureRSAKey($key)
    {
        $key = $key->withPadding($this->cryptParams['padding']);
        if (! empty($this->cryptParams['digest'])) {
            $key = $key->withHash($this->cryptParams['digest']);
            if (
                $this->cryptParams['padding'] === RSA::ENCRYPTION_OAEP ||
                $this->cryptParams['padding'] === RSA::SIGNATURE_PSS
            ) {
                $key = $key->withMGFHash($this->cryptParams['digest']);
            }
        }
        return $key;
    }

    /**
     * Encrypts the given data (string) using phpseclib.
     *
     * @param string $data
     * @return mixed|string
     * @throws Exception
     */
    public function encryptData($data)
    {
        if ($this->cryptParams['library'] !== 'phpseclib') {
            return null;
        }
        switch ($this->cryptParams['type']) {
            case 'symmetric':
                return $this->encryptSymmetric($data);
            case 'public':
                $public = PublicKeyLoader::load($this->key);
                return $this->configureRSAKey($public)->encrypt($data);
            case 'private':
                throw new Exception('Encrypting with a private key is not supported');
        }
    }

    /**
     * Decrypts the given data (string) using phpseclib.
     *
     * @param string $data
     * @return mixed|string
     * @throws Exception
     */
    public function decryptData($data)
    {
        if ($this->cryptParams['library'] !== 'phpseclib') {
            return null;
        }
        switch ($this->cryptParams['type']) {
            case 'symmetric':
                return $this->decryptSymmetric($data);
            case 'public':
                throw new Exception('Decrypting with a public key is not supported');
            case 'private':
                $passphrase = $this->passphrase !== '' ? $this->passphrase : false;
                $private = PublicKeyLoader::load($this->key, $passphrase);
                return $this->configureRSAKey($private)->decrypt($data);
        }
    }

    /**
     * Signs the data (string) using the extension assigned to the type in the constructor.
     *
     * @param string $data
     * @return mixed|string
     */
    public function signData($data)
    {
        switch ($this->cryptParams['library']) {
            case 'phpseclib':
                $passphrase = $this->passphrase !== '' ? $this->passphrase : false;
                $private = PublicKeyLoader::load($this->key, $passphrase);
                if ($this->type === self::ECDSA_SHA256) {
                    return $private
                        ->withHash($this->cryptParams['digest'])
                        ->withSignatureFormat('IEEE')
                        ->sign($data);
                }
                return $this->configureRSAKey($private)->sign($data);
            case (self::HMAC_SHA1):
                return hash_hmac("sha1", $data, $this->key, true);
        }
    }

    /**
     * Verifies the data (string) against the given signature using the extension assigned to the type in the constructor.
     *
     * Returns:
     *  1 on succesful signature verification,
     *  0 when signature verification failed,
     *  -1 if an error occurred during processing.
     *
     * NOTE: be very careful when checking the return value, because in PHP,
     * -1 will be cast to True when in boolean context. So always check the
     * return value in a strictly typed way, e.g. "$obj->verify(...) === 1".
     *
     * @param string $data
     * @param string $signature
     * @return bool|int
     */
    public function verifySignature($data, $signature)
    {
        switch ($this->cryptParams['library']) {
            case 'phpseclib':
                try {
                    $public = PublicKeyLoader::load($this->key);
                    if ($this->type === self::ECDSA_SHA256) {
                        $result = $public
                            ->withHash($this->cryptParams['digest'])
                            ->withSignatureFormat('IEEE')
                            ->verify($data, $signature);
                        return $result === true ? 1 : 0;
                    }
                    $result = $this->configureRSAKey($public)->verify($data, $signature);
                    return $result === true ? 1 : 0;
                } catch (Exception $e) {
                    return -1;
                }
            case (self::HMAC_SHA1):
                $expectedSignature = hash_hmac("sha1", $data, $this->key, true);
                return strcmp($signature, $expectedSignature) == 0;
        }
    }

    /**
     * @deprecated
     * @see getAlgorithm()
     * @return mixed
     */
    public function getAlgorith()
    {
        return $this->getAlgorithm();
    }

    /**
     * @return mixed
     */
    public function getAlgorithm()
    {
        return $this->cryptParams['method'];
    }

    /**
     *
     * @param int $type
     * @param string $string
     * @return null|string
     */
    public static function makeAsnSegment($type, $string)
    {
        switch ($type) {
            case 0x02:
                if (ord($string) > 0x7f)
                    $string = chr(0).$string;
                break;
            case 0x03:
                $string = chr(0).$string;
                break;
        }

        $length = strlen($string);

        if ($length < 128) {
            $output = sprintf("%c%c%s", $type, $length, $string);
        } else if ($length < 0x0100) {
            $output = sprintf("%c%c%c%s", $type, 0x81, $length, $string);
        } else if ($length < 0x010000) {
            $output = sprintf("%c%c%c%c%s", $type, 0x82, $length / 0x0100, $length % 0x0100, $string);
        } else {
            $output = null;
        }
        return $output;
    }

    /**
     *
     * Hint: Modulus and Exponent must already be base64 decoded
     * @param string $modulus
     * @param string $exponent
     * @return string
     */
    public static function convertRSA($modulus, $exponent)
    {
        /* make an ASN publicKeyInfo */
        $exponentEncoding = self::makeAsnSegment(0x02, $exponent);
        $modulusEncoding = self::makeAsnSegment(0x02, $modulus);
        $sequenceEncoding = self::makeAsnSegment(0x30, $modulusEncoding.$exponentEncoding);
        $bitstringEncoding = self::makeAsnSegment(0x03, $sequenceEncoding);
        $rsaAlgorithmIdentifier = pack("H*", "300D06092A864886F70D0101010500");
        $publicKeyInfo = self::makeAsnSegment(0x30, $rsaAlgorithmIdentifier.$bitstringEncoding);

        /* encode the publicKeyInfo in base64 and add PEM brackets */
        $publicKeyInfoBase64 = base64_encode($publicKeyInfo);
        $encoding = "-----BEGIN PUBLIC KEY-----\n";
        $offset = 0;
        while ($segment = substr($publicKeyInfoBase64, $offset, 64)) {
            $encoding = $encoding.$segment."\n";
            $offset += 64;
        }
        return $encoding."-----END PUBLIC KEY-----\n";
    }

    /**
     * @param mixed $parent
     */
    public function serializeKey($parent)
    {

    }

    /**
     * Retrieve the X509 certificate this key represents.
     *
     * Will return the X509 certificate in PEM-format if this key represents
     * an X509 certificate.
     *
     * @return string The X509 certificate or null if this key doesn't represent an X509-certificate.
     */
    public function getX509Certificate()
    {
        return $this->x509Certificate;
    }

    /**
     * Get the thumbprint of this X509 certificate.
     *
     * Returns:
     *  The thumbprint as a lowercase 40-character hexadecimal number, or null
     *  if this isn't a X509 certificate.
     *
     *  @return string Lowercase 40-character hexadecimal number of thumbprint
     */
    public function getX509Thumbprint()
    {
        return $this->X509Thumbprint;
    }


    /**
     * Create key from an EncryptedKey-element.
     *
     * @param DOMElement $element The EncryptedKey-element.
     * @throws Exception
     *
     * @return XMLSecurityKey The new key.
     */
    public static function fromEncryptedKeyElement(DOMElement $element)
    {

        $objenc = new XMLSecEnc();
        $objenc->setNode($element);
        if (! $objKey = $objenc->locateKey()) {
            throw new Exception("Unable to locate algorithm for this Encrypted Key");
        }
        $objKey->isEncrypted = true;
        $objKey->encryptedCtx = $objenc;
        XMLSecEnc::staticLocateKeyInfo($objKey, $element);
        return $objKey;
    }

}
