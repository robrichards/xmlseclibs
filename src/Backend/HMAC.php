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
    protected $digest = Constants::DIGEST_SHA256;


    /**
     * Set the digest algorithm to be used by this backend.
     *
     * @param string $digest The identifier of the digest algorithm.
     */
    public function setDigestAlg($digest)
    {
        $this->digest = $digest;
    }


    /**
     * Sign a given plaintext with this cipher and a given key.
     *
     * @param AbstractKey $key The key to use to sign.
     * @param string $plaintext The original text to sign.
     *
     * @return string The (binary) signature corresponding to the given plaintext.
     *
     * @throws RuntimeException If the digest algorithm is unknown or a non-cryptographic hash function.
     */
    public function sign(AbstractKey $key, $plaintext)
    {
        $hash = hash_hmac($this->digest, $plaintext, $key->get(), true);
        if ($hash === false) {
            throw new InvalidArgumentException('"'.$this->digest.'" is unknown or non-cryptographic hash function.');
        }
        return $hash;
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
