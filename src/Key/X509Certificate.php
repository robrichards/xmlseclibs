<?php

namespace SimpleSAML\XMLSec\Key;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;

/**
 * A class modeling X509 certificates.
 *
 * @package SimpleSAML\XMLSec\Key
 */
class X509Certificate extends PublicKey
{
    /** @var string */
    protected $certificate;

    /** @var string */
    protected $thumbprint;


    /**
     * Create a new X509 certificate from its PEM-encoded representation.
     *
     * @param string $cert The PEM-encoded certificate or the path to a file containing it.
     *
     * @throws InvalidArgumentException If the certificate cannot be read from $cert.
     * @throws RuntimeException If the certificate cannot be exported to PEM format.
     */
    public function __construct($cert)
    {
        $resource = openssl_x509_read($cert);
        if ($resource === false) {
            throw new InvalidArgumentException('Cannot read certificate: '.openssl_error_string());
        }

        if (!openssl_x509_export($resource, $this->certificate)) {
            throw new RuntimeException('Cannot export certificate to PEM: '.openssl_error_string());
        }
        parent::__construct(openssl_pkey_get_public($this->certificate));
        $this->thumbprint = self::getRawThumbprint($this->certificate);
    }


    /**
     * Get the raw thumbprint of a certificate
     *
     * @param string $cert The PEM-encoded X509 certificate.
     *
     * @return string The thumbprint associated with the given certificate.
     *
     * @throws RuntimeException If $cert is not a PEM-encoded certificate.
     */
    public static function getRawThumbprint($cert)
    {
        $cert = trim($cert);

        // remove beginning and end delimiters
        $lines = explode("\n", $cert);
        array_shift($lines);
        array_pop($lines);

        if (empty($lines)) {
            throw new RuntimeException('Cannot get thumbprint for certificate.');
        }

        $lines = array_map("trim", $lines);
        return strtolower(hash('sha1', base64_decode(implode(array_map("trim", $lines)))));
    }


    /**
     * Get the certificate this key originated from.
     *
     * @return string The certificate.
     */
    public function getCertificate()
    {
        return $this->certificate;
    }


    /**
     * Get a new X509 certificate from a file.
     *
     * @param string $file The file where the PEM-encoded certificate is stored.
     *
     * @return X509Certificate A new X509Certificate key.
     * @throws InvalidArgumentException If the file cannot be read.
     */
    public static function fromFile($file)
    {
        return new static(static::readFile($file));
    }
}
