<?php

namespace SimpleSAML\XMLSec\Alg\Signature;

use SimpleSAML\XMLSec\Alg\SignatureAlgorithm;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Key\SymmetricKey;

/**
 * Class implementing the HMAC signature algorithm
 *
 * @package SimpleSAML\XMLSec\Alg\Signature
 */
class HMAC extends AbstractSigner implements SignatureAlgorithm
{
    /** @var string */
    protected $default_backend = '\SimpleSAML\XMLSec\Backend\HMAC';


    /**
     * HMAC constructor.
     *
     * @param \SimpleSAML\XMLSec\Key\SymmetricKey $key The symmetric key to use.
     * @param string $digest The identifier of the digest algorithm to use.
     */
    public function __construct(SymmetricKey $key, string $digest = Constants::DIGEST_SHA1)
    {
        parent::__construct($key, $digest);
    }
}
