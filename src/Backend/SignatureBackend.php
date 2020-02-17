<?php

namespace SimpleSAML\XMLSec\Backend;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\AbstractKey;

/**
 * Interface for backends implementing digital signatures.
 *
 * @package SimpleSAML\XMLSec\Backend
 */
interface SignatureBackend
{

    /**
     * Set the digest algorithm to use.
     *
     * @param string $digest The identifier of the digest algorithm.
     *
     * @throws InvalidArgumentException If the given digest is not valid.
     */
    public function setDigestAlg($digest);


    /**
     * Sign a given plaintext with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to sign.
     * @param string $plaintext The original text to sign.
     *
     * @return string The (binary) signature corresponding to the given plaintext.
     *
     * @throws RuntimeException If there is an error while signing the plaintext.
     */
    public function sign(AbstractKey $key, $plaintext);


    /**
     * Verify a signature with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to verify.
     * @param string $plaintext The original signed text.
     * @param string $signature The (binary) signature to verify.
     *
     * @return boolean True if the signature can be verified, false otherwise.
     */
    public function verify(AbstractKey $key, $plaintext, $signature);
}