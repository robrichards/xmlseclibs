<?php

namespace SimpleSAML\XMLSec\Alg\Signature;

use SimpleSAML\XMLSec\Alg\SignatureAlgorithm;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\AbstractKey;
use SimpleSAML\XMLSec\Key\AsymmetricKey;
use SimpleSAML\XMLSec\Key\SymmetricKey;

/**
 * Factory class to create and configure digital signature algorithms.
 *
 * @package SimpleSAML\XMLSec\Alg\Signature
 */
class SignatureAlgorithmFactory
{

    /** @var string */
    protected $digest;

    /**
     * An array of blacklisted algorithms.
     *
     * Defaults to RSA-SHA1 & HMAC-SHA1 due to the weakness of SHA1.
     *
     * @var array
     */
    protected $blacklist = [
        Constants::SIG_RSA_SHA1,
        Constants::SIG_HMAC_SHA1,
    ];


    /**
     * Build a factory that creates signature algorithms.
     *
     * @param string[]|null $blacklist
     */
    public function __construct($blacklist = null)
    {
        if ($blacklist !== null) {
            $this->blacklist = $blacklist;
        }
    }


    /**
     * Get the identifier of the digest associated with the last algorithm built.
     *
     * @return string The digest identifier.
     *
     * @see \SimpleSAML\XMLSec\Constants
     */
    public function getDigestAlgorithm()
    {
        return $this->digest;
    }


    /**
     * Get a new object implementing the given digital signature algorithm.
     *
     * @param string $algId The identifier of the algorithm desired.
     * @param AbstractKey $key The key to use with the given algorithm.
     *
     * @return SignatureAlgorithm An object implementing the given algorithm.
     *
     * @throws RuntimeException If an error occurs, e.g. the given algorithm is blacklisted, unknown or the given key is
     * not suitable for it.
     */
    public function getAlgorithm($algId, AbstractKey $key)
    {
        if (in_array($algId, $this->blacklist)) {
            throw new RuntimeException('Blacklisted signature algorithm');
        }

        // determine digest
        switch ($algId) {
            case Constants::SIG_RSA_SHA1:
            case Constants::SIG_HMAC_SHA1:
                $this->digest = Constants::DIGEST_SHA1;
                break;
            case Constants::SIG_RSA_SHA224:
            case Constants::SIG_HMAC_SHA224:
                $this->digest = Constants::DIGEST_SHA224;
                break;
            case Constants::SIG_RSA_SHA256:
            case Constants::SIG_HMAC_SHA256:
                $this->digest = Constants::DIGEST_SHA256;
                break;
            case Constants::SIG_RSA_SHA384:
            case Constants::SIG_HMAC_SHA384:
                $this->digest = Constants::DIGEST_SHA384;
                break;
            case Constants::SIG_RSA_SHA512:
            case Constants::SIG_HMAC_SHA512:
                $this->digest = Constants::DIGEST_SHA512;
                break;
            case Constants::SIG_RSA_RIPEMD160:
            case Constants::SIG_HMAC_RIPEMD160:
                $this->digest = Constants::DIGEST_RIPEMD160;
                break;
            default:
                throw new RuntimeException('Unsupported signature algorithm');
        }

        // create instance
        switch ($algId) {
            case Constants::SIG_RSA_SHA1:
            case Constants::SIG_RSA_SHA224:
            case Constants::SIG_RSA_SHA256:
            case Constants::SIG_RSA_SHA384:
            case Constants::SIG_RSA_SHA512:
            case Constants::SIG_RSA_RIPEMD160:
                if ($key instanceof AsymmetricKey) {
                    return new RSA($key, $this->digest);
                }
                break;
            case Constants::SIG_HMAC_SHA1:
            case Constants::SIG_HMAC_SHA224:
            case Constants::SIG_HMAC_SHA256:
            case Constants::SIG_HMAC_SHA384:
            case Constants::SIG_HMAC_SHA512:
            case Constants::SIG_HMAC_RIPEMD160:
                if ($key instanceof SymmetricKey) {
                    return new HMAC($key, $this->digest);
                }
                break;
        }
        throw new RuntimeException('Invalid type of key for algorithm');
    }
}
