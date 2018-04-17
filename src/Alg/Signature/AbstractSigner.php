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

    /**
     * @var AbstractKey
     */
    protected $key;

    /** @var SignatureBackend */
    protected $backend;

    /** @var string */
    protected $default_backend;


    /**
     * Build a signature algorithm.
     *
     * @param AbstractKey $key The signing key.
     * @param string $digest The identifier of the digest algorithm to use.
     * @param SignatureBackend $backend The backend to use. Optional.
     */
    public function __construct(AbstractKey $key, $digest, SignatureBackend $backend = null)
    {
        $this->key = $key;

        if ($backend !== null) {
            $this->backend = $backend;
        } else {
            $this->backend = new $this->default_backend();
        }
        $this->backend->setDigestAlg($digest);
    }


    /**
     * Sign a given plaintext with the current algorithm and key.
     *
     * @param string $plaintext The plaintext to sign.
     *
     * @return string The (binary) signature corresponding to the given plaintext.
     */
    public function sign($plaintext)
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
    public function verify($plaintext, $signature)
    {
        return $this->backend->verify($this->key, $plaintext, $signature);
    }
}
