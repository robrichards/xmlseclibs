<?php

namespace SimpleSAML\XMLSec\Key;

use SimpleSAML\XMLSec\Constants;
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

    /** @var array */
    protected $thumbprint = [];

    /** @var array */
    protected $parsed = [];


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
        $this->thumbprint[Constants::DIGEST_SHA1] = $this->getRawThumbprint();

        $this->parsed = openssl_x509_parse($this->certificate);
    }


    /**
     * Compute a certificate digest manually.
     *
     * @param string $alg The digest algorithm to use.
     *
     * @return string The thumbprint associated with the given certificate.
     */
    protected function manuallyComputeThumbprint($alg)
    {
        // remove beginning and end delimiters
        $lines = explode("\n", trim($this->certificate));
        array_shift($lines);
        array_pop($lines);

        return $this->thumbprint[$alg] = strtolower(
            hash(
                Constants::$DIGEST_ALGORITHMS[$alg],
                base64_decode(
                    implode(
                        array_map("trim", $lines)
                    )
                )
            )
        );
    }


    /**
     * Get the raw thumbprint of a certificate
     *
     * @param string $alg The digest algorithm to use. Defaults to SHA1.
     *
     * @return string The thumbprint associated with the given certificate.
     *
     * @throws InvalidArgumentException If $alg is not a valid digest identifier.
     */
    public function getRawThumbprint($alg = Constants::DIGEST_SHA1)
    {
        if (isset($this->thumbprint[$alg])) {
            return $this->thumbprint[$alg];
        }

        if (!isset(Constants::$DIGEST_ALGORITHMS[$alg])) {
            throw new InvalidArgumentException('Invalid digest algorithm identifier');
        }

        if (function_exists('openssl_x509_fingerprint')) {
            // if available, use the openssl function
            return $this->thumbprint[$alg] = openssl_x509_fingerprint(
                $this->certificate,
                Constants::$DIGEST_ALGORITHMS[$alg]
            );
        }

        return $this->manuallyComputeThumbprint($alg);
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
     * Get the details of this certificate.
     *
     * @return array An array with all the details of the certificate.
     *
     * @see openssl_x509_parse()
     */
    public function getCertificateDetails()
    {
        return $this->parsed;
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
