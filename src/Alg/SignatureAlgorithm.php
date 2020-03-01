<?php

namespace SimpleSAML\XMLSec\Alg;

use SimpleSAML\XMLSec\Backend\SignatureBackend;

/**
 * An interface representing algorithms that can be used for digital signatures.
 *
 * @package SimpleSAML\XMLSec\Alg
 */
interface SignatureAlgorithm
{
    /**
     * Get the digest used by this signature algorithm.
     *
     * @return string The identifier of the digest algorithm used.
     */
    public function getDigest(): string;


    /**
     * Set the backend to use for actual computations by this algorithm.
     *
     * @param SignatureBackend $backend The backend to use.
     *
     * @return void
     */
    public function setBackend(SignatureBackend $backend): void;


    /**
     * Sign a given plaintext with this cipher and the loaded key.
     *
     * @param string $plaintext The original text to sign.
     *
     * @return string|false The (binary) signature corresponding to the given plaintext.
     */
    public function sign(string $plaintext);


    /**
     * Verify a signature with this cipher and the loaded key.
     *
     * @param string $plaintext The original signed text.
     * @param string $signature The (binary) signature to verify.
     *
     * @return boolean True if the signature can be verified, false otherwise.
     */
    public function verify(string $plaintext, string $signature): bool;
}
