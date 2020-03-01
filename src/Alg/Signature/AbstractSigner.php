<?php

namespace SimpleSAML\XMLSec\Alg\Signature;

use SimpleSAML\XMLSec\Alg\SignatureAlgorithm;
use SimpleSAML\XMLSec\Backend\SignatureBackend;
use SimpleSAML\XMLSec\Key\AbstractKey;

/**
 * An abstract class that implements a generic digital signature algorithm.
 *
 * @package SimpleSAML\XMLSec\Alg\Signature
 */
abstract class AbstractSigner implements SignatureAlgorithm
{
    /** @var AbstractKey */
    protected $key;

    /** @var SignatureBackend */
    protected $backend;

    /** @var string */
    protected $default_backend;

    /** @var string */
    protected $digest;


    /**
     * Build a signature algorithm.
     *
     * @param \SimpleSAML\XMLSec\Key\AbstractKey $key The signing key.
     * @param string $digest The identifier of the digest algorithm to use.
     */
    public function __construct(AbstractKey $key, string $digest)
    {
        $this->key = $key;
        $this->digest = $digest;
        $this->backend = new $this->default_backend();
        $this->backend->setDigestAlg($digest);
    }


    /**
     * @return string
     */
    public function getDigest(): string
    {
        return $this->digest;
    }


    /**
     * @param \SimpleSAML\XMLSec\Backend\SignatureBackend
     *
     * @return void
     */
    public function setBackend(SignatureBackend $backend): void
    {
        $this->backend = $backend;
        $this->backend->setDigestAlg($this->digest);
    }


    /**
     * Sign a given plaintext with the current algorithm and key.
     *
     * @param string $plaintext The plaintext to sign.
     *
     * @return string The (binary) signature corresponding to the given plaintext.
     */
    public function sign(string $plaintext): string
    {
        return $this->backend->sign($this->key, $plaintext);
    }


    /**
     * Verify a signature with the current algorithm and key.
     *
     * @param string $plaintext The original signed text.
     * @param string $signature The (binary) signature to verify.
     *
     * @return boolean True if the signature can be verified, false otherwise.
     */
    public function verify(string $plaintext, string $signature): bool
    {
        return $this->backend->verify($this->key, $plaintext, $signature);
    }
}
