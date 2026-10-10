<?php

namespace RobRichards\XMLSecLibs\PhpSecLib;

/**
 * X.509 facade with the phpseclib 3 method names.
 *
 * phpseclib 4 removed loadX509(), saveX509() and made getDN() throw unless the
 * certificate is self-signed. Callers in this library keep using the version 3
 * shape; this class picks the installed implementation.
 */
class X509
{
    const DN_OPENSSL = 3;

    /** @var object|null */
    private $inner = null;

    /**
     * @param string $cert
     * @return array|false
     */
    public function loadX509($cert)
    {
        if (Bootstrap::isVersion4()) {
            return $this->loadVersion4($cert);
        }
        return $this->loadVersion3($cert);
    }

    /**
     * @param mixed $certData
     * @return string|false
     */
    public function saveX509($certData)
    {
        if ($this->inner === null) {
            return false;
        }
        if (Bootstrap::isVersion4()) {
            return $this->saveVersion4();
        }
        return $this->inner->saveX509($certData);
    }

    /**
     * Subject DN. On phpseclib 4 this is getSubjectDN(), because getDN()
     * rejects certificates that are not self-signed.
     *
     * @param int $format
     * @return array|string|false
     */
    public function getDN($format = self::DN_OPENSSL)
    {
        if ($this->inner === null) {
            return false;
        }
        if (Bootstrap::isVersion4()) {
            return $this->inner->getSubjectDN($format);
        }
        return $this->inner->getDN($format);
    }

    /**
     * @param int $format
     * @return array|string|false
     */
    public function getIssuerDN($format = self::DN_OPENSSL)
    {
        if ($this->inner === null) {
            return false;
        }
        return $this->inner->getIssuerDN($format);
    }

    /**
     * @param string $cert
     * @return array|false
     */
    private function loadVersion4($cert)
    {
        try {
            $loaded = \phpseclib4\File\X509::load($cert);
            $decoded = $loaded->toArray();
        } catch (\Throwable $e) {
            $this->inner = null;
            return false;
        }
        if (!is_array($decoded)) {
            $this->inner = null;
            return false;
        }
        $this->inner = $loaded;
        return $decoded;
    }

    /**
     * @param string $cert
     * @return array|false
     */
    private function loadVersion3($cert)
    {
        $x509 = new \phpseclib3\File\X509();
        $this->inner = $x509;
        return $x509->loadX509($cert);
    }

    /**
     * @return string|false
     */
    private function saveVersion4()
    {
        try {
            return $this->inner->toString();
        } catch (\Throwable $e) {
            return false;
        }
    }
}
