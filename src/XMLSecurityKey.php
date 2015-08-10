<?php
namespace RobRichards\XMLSecLibs;

use DomElement;
use RobRichards\XMLSecLibs\Extension\Hash_Hmac;
use RobRichards\XMLSecLibs\Extension\Mcrypt;
use RobRichards\XMLSecLibs\Extension\OpenSSL;

/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2015, Robert Richards <rrichards@cdatazone.org>.
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
 * @copyright 2007-2015 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

class XMLSecurityKey
{
    const TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
    const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
    const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
    const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
    const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
    const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
    const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    const HMAC_SHA1 = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';

    private $cryptParams = array();
    public $type = 0;
    public $key = null;
    public $passphrase = "";
    public $name = null;
    public $keyChain = null;
    public $isEncrypted = false;
    public $encryptedCtx = null;
    public $guid = null;

    /**
     * This variable contains the certificate as a string if this key represents an X509-certificate.
     * If this key doesn't represent a certificate, this will be null.
     */
    private $x509Certificate = null;

    /* This variable contains the certificate thumbprint if we have loaded an X509-certificate. */
    private $X509Thumbprint = null;

    /**
     * @param $type
     *
     * @param array|null $params
     *
     * @throws XMLSecLibsException
     */
    public function __construct($type, $params=null)
    {
        switch ($type) {
            case (self::TRIPLEDES_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_TRIPLEDES;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
                $this->cryptParams['keysize'] = 24;
                break;
            case (self::AES128_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_RIJNDAEL_128;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
                $this->cryptParams['keysize'] = 16;
                break;
            case (self::AES192_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_RIJNDAEL_128;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
                $this->cryptParams['keysize'] = 24;
                break;
            case (self::AES256_CBC):
                $this->cryptParams['library'] = 'mcrypt';
                $this->cryptParams['cipher'] = MCRYPT_RIJNDAEL_128;
                $this->cryptParams['mode'] = MCRYPT_MODE_CBC;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
                $this->cryptParams['keysize'] = 32;
                break;
            case (self::RSA_1_5):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecLibsException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_OAEP_MGF1P):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_OAEP_PADDING;
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
                $this->cryptParams['hash'] = null;
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecLibsException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA1):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecLibsException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA256):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'SHA256';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecLibsException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA384):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'SHA384';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecLibsException('Certificate "type" (private/public) must be passed via parameters');
            case (self::RSA_SHA512):
                $this->cryptParams['library'] = 'openssl';
                $this->cryptParams['method'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
                $this->cryptParams['padding'] = OPENSSL_PKCS1_PADDING;
                $this->cryptParams['digest'] = 'SHA512';
                if (is_array($params) && ! empty($params['type'])) {
                    if ($params['type'] == 'public' || $params['type'] == 'private') {
                        $this->cryptParams['type'] = $params['type'];
                        break;
                    }
                }
                throw new XMLSecLibsException('Certificate "type" (private/public) must be passed via parameters');
            case (self::HMAC_SHA1):
                $this->cryptParams['library'] = $type;
                $this->cryptParams['method'] = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1';
                break;
            default:
                throw new XMLSecLibsException('Invalid Key Type');
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
     * @return string
     *
     * @throws XMLSecLibsException
     */
    public function generateSessionKey()
    {
        if (!isset($this->cryptParams['keysize'])) {
            throw new XMLSecLibsException('Unknown key size for type "' . $this->type . '".');
        }
        $keysize = $this->cryptParams['keysize'];
        
        if (function_exists('openssl_random_pseudo_bytes')) {
            /* We have PHP >= 5.3 - use openssl to generate session key. */
            $key = openssl_random_pseudo_bytes($keysize);
        } else {
            throw new XMLSecLibsException('The openssl-extension is needed for generating a session key.');
        }
        
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
     * @param $cert
     *
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
     * @param $key
     *
     * @param bool|false $isFile
     *
     * @param bool|false $isCert
     *
     * @throws XMLSecLibsException
     */
    public function loadKey($key, $isFile = false, $isCert = false)
    {
        switch ($this->cryptParams['library']) {
            case 'openssl':
                $objExtension = new OpenSSL($this->cryptParams, $this->key);
                $objExtension->setPassphrase($this->passphrase);
                $objExtension->setType($this->type);
                break;
            case 'mcrypt':
                $objExtension = new Mcrypt($this->cryptParams, $this->key);
                $objExtension->setPassphrase($this->passphrase);
                $objExtension->setType($this->type);
                break;
            default:
                throw new XMLSecLibsException('Not implemented yet for this type.');
        }
        return $objExtension->loadKey($key, $isFile, $isCert);
    }

    /**
     * @param $data
     *
     * @return mixed|string
     *
     * @throws XMLSecLibsException
     */
    public function encryptData($data)
    {
        switch ($this->cryptParams['library']) {
            case 'mcrypt':
                $objExtension = new Mcrypt($this->cryptParams, $this->key);
                break;
            case 'openssl':
                $objExtension = new OpenSSL($this->cryptParams, $this->key);
                break;
            default:
                throw new XMLSecLibsException('No, unknown or unsupported crypto-library called for encryption.');
        }
        return $objExtension->encrypt($data);
    }

    /**
     * @param $data
     *
     * @return mixed|string
     *
     * @throws XMLSecLibsException
     */
    public function decryptData($data)
    {
        switch ($this->cryptParams['library']) {
            case 'mcrypt':
                $objExtension = new Mcrypt($this->cryptParams, $this->key);
                break;
            case 'openssl':
                $objExtension = new OpenSSL($this->cryptParams, $this->key);
                break;
            default:
                throw new XMLSecLibsException('No, unknown or unsupported crypto-library called for decryption.');
        }
        return $objExtension->decrypt($data);
    }

    /**
     * @param $data
     *
     * @return mixed|string
     *
     * @throws XMLSecLibsException
     */
    public function signData($data)
    {
        switch ($this->cryptParams['library']) {
            case 'openssl':
                $objExtension = new OpenSSL($this->cryptParams, $this->key);
                break;
            case (self::HMAC_SHA1):
                $objExtension = new Hash_Hmac($this->cryptParams, $this->key);
                break;
            default:
                throw new XMLSecLibsException('No, unknown or unsupported crypto-library called for decryption.');
        }
        return $objExtension->signData($data);
    }

    /**
     * @param $data
     *
     * @param $signature
     *
     * @throws XMLSecLibsException
     *
     * @return bool|int
     */
    public function verifySignature($data, $signature)
    {
        switch ($this->cryptParams['library']) {
            case 'openssl':
                $objExtension = new OpenSSL($this->cryptParams, $this->key);
                break;
            case (self::HMAC_SHA1):
                $objExtension = new Hash_Hmac($this->cryptParams, $this->key);
                break;
            default:
                throw new XMLSecLibsException('None, unknown or unsupported option for verifying called.');
        }
        return $objExtension->verifySignature($data, $signature);
    }

    /**
     * @deprecated
     *
     * @see getAlgorithm()
     */
    public function getAlgorith()
    {
        return $this->getAlgorithm();
    }

    /**
     * @return string|null
     */
    public function getAlgorithm()
    {
        return $this->cryptParams['method'];
    }

    /**
     * @param $type
     *
     * @param $string
     *
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

    /* Modulus and Exponent must already be base64 decoded */
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
     *
     * @throws XMLSecLibsException
     *
     * @return XMLSecurityKey The new key.
     */
    public static function fromEncryptedKeyElement(DOMElement $element)
    {

        $objenc = new XMLSecEnc();
        $objenc->setNode($element);
        if (! $objKey = $objenc->locateKey()) {
            throw new XMLSecLibsException("Unable to locate algorithm for this Encrypted Key");
        }
        $objKey->isEncrypted = true;
        $objKey->encryptedCtx = $objenc;
        XMLSecEnc::staticLocateKeyInfo($objKey, $element);
        return $objKey;
    }

}
