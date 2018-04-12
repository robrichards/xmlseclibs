<?php

namespace SimpleSAML\XMLSec\Backend;

use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\AbstractKey;
use SimpleSAML\XMLSec\Utils\Security;

/**
 * Backend for digital signatures based on hash-based message authentication codes.
 *
 * @package SimpleSAML\XMLSec\Backend
 */
class HMAC implements SignatureBackend
{

    /** @var string */
    protected $digest;


    /**
     * Build an HMAC backend.
     */
    public function __construct()
    {
        $this->digest = Constants::$DIGEST_ALGORITHMS[Constants::DIGEST_SHA256];
    }


    /**
     * Set the digest algorithm to be used by this backend.
     *
     * @param string $digest The identifier of the digest algorithm.
     *
     * @throws InvalidArgumentException If the given digest is not valid.
     */
    public function setDigestAlg($digest)
    {
        if (!isset(Constants::$DIGEST_ALGORITHMS[$digest])) {
            throw new InvalidArgumentException('Unknown digest or non-cryptographic hash function.');
        }
        $this->digest = Constants::$DIGEST_ALGORITHMS[$digest];
    }


    /**
     * Sign a given plaintext with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to sign.
     * @param string $plaintext The original text to sign.
     *
     * @return string The (binary) signature corresponding to the given plaintext.
     */
    public function sign(AbstractKey $key, $plaintext)
    {
        return hash_hmac($this->digest, $plaintext, $key->get(), true);
    }


    /**
     * Verify a signature with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to.
     * @param string $plaintext The original signed text.
     * @param string $signature The (binary) signature to verify.
     *
     * @return boolean True if the signature can be verified, false otherwise.
     */
    public function verify(AbstractKey $key, $plaintext, $signature)
    {
        return Security::compareStrings(hash_hmac($this->digest, $plaintext, $key->get(), true), $signature);
    }
}
