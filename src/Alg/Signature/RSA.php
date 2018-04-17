<?php

namespace SimpleSAML\XMLSec\Alg\Signature;

use SimpleSAML\XMLSec\Alg\SignatureAlgorithm;
use SimpleSAML\XMLSec\Backend\SignatureBackend;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Key\AsymmetricKey;

/**
 * Class implementing the RSA signature algorithm.
 *
 * @package SimpleSAML\XMLSec\Alg\Signature
 */
class RSA extends AbstractSigner implements SignatureAlgorithm
{
    /** @var string */
    protected $default_backend = '\SimpleSAML\XMLSec\Backend\OpenSSL';


    /**
     * RSA constructor.
     *
     * @param AsymmetricKey $key The asymmetric key (either public or private) to use.
     * @param string $digest The identifier of the digest algorithm to use.
     * @param SignatureBackend $backend The signature backend to use.
     */
    public function __construct(AsymmetricKey $key, $digest = Constants::DIGEST_SHA1, SignatureBackend $backend = null)
    {
        parent::__construct($key, $digest, $backend);
    }
}
