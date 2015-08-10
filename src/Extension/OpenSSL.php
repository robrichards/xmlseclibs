<?php
/**
 * Created by PhpStorm.
 * User: gfaust
 * Date: 10.08.2015
 * Time: 00:24
 */

namespace RobRichards\XMLSecLibs\Extension;

use RobRichards\XMLSecLibs\XMLSecLibsException;
use RobRichards\XMLSecLibs\XMLSecLibsExtensionAbstract;
use RobRichards\XMLSecLibs\XMLSecLibsExtensionInterface;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class OpenSSL extends XMLSecLibsExtensionAbstract implements XMLSecLibsExtensionInterface
{

    /**
     * @param $data
     *
     * @return mixed
     *
     * @throws XMLSecLibsException
     */
    public function encrypt($data)
    {
        if ($this->cryptParams['type'] == 'public') {
            if (! openssl_public_encrypt($data, $encrypted_data, $this->key, $this->cryptParams['padding'])) {
                throw new XMLSecLibsException('Failure encrypting Data');
            }
        } else {
            if (! openssl_private_encrypt($data, $encrypted_data, $this->key, $this->cryptParams['padding'])) {
                throw new XMLSecLibsException('Failure encrypting Data');
            }
        }
        return $encrypted_data;
    }

    /**
     * @param $data
     *
     * @return mixed
     *
     * @throws XMLSecLibsException
     */
    public function decrypt($data)
    {
        if ($this->cryptParams['type'] == 'public') {
            if (! openssl_public_decrypt($data, $decrypted, $this->key, $this->cryptParams['padding'])) {
                throw new XMLSecLibsException('Failure decrypting Data');
            }
        } else {
            if (! openssl_private_decrypt($data, $decrypted, $this->key, $this->cryptParams['padding'])) {
                throw new XMLSecLibsException('Failure decrypting Data');
            }
        }
        return $decrypted;
    }

    /**
     * @param string $data
     * @param string $signature
     * @return int
     */
    public function verifySignature($data, $signature)
    {
        $algo = OPENSSL_ALGO_SHA1;
        if (! empty($this->cryptParams['digest'])) {
            $algo = $this->cryptParams['digest'];
        }
        return openssl_verify($data, $signature, $this->key, $algo);
    }

    /**
     * @param string $data
     * @return mixed
     * @throws XMLSecLibsException
     */
    public function signData($data)
    {
        $algo = OPENSSL_ALGO_SHA1;
        if (! empty($this->cryptParams['digest'])) {
            $algo = $this->cryptParams['digest'];
        }
        if (! openssl_sign($data, $signature, $this->key, $algo)) {
            throw new XMLSecLibsException('Failure Signing Data: ' . openssl_error_string() . ' - ' . $algo);
        }
        return $signature;
    }

    public function loadKey($key, $isFile = false, $isCert = false)
    {
        if ($isFile) {
            $this->key = file_get_contents($key);
        } else {
            $this->key = $key;
        }
        if ($isCert) {
            $this->key = openssl_x509_read($this->key);
            openssl_x509_export($this->key, $str_cert);
            $this->x509Certificate = $str_cert;
            $this->key = $str_cert;
        } else {
            $this->x509Certificate = null;
        }

        if ($this->cryptParams['type'] == 'public') {
            if ($isCert) {
                /* Load the thumbprint if this is an X509 certificate. */
                $this->X509Thumbprint = XMLSecurityKey::getRawThumbprint($this->key);
            }
            $this->key = openssl_get_publickey($this->key);
            if (! $this->key) {
                throw new XMLSecLibsException('Unable to extract public key');
            }
        } else {
            $this->key = openssl_get_privatekey($this->key, $this->passphrase);
        }

    }
}