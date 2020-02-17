<?php

namespace SimpleSAML\XMLSec\Test\Alg;

use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSec\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\PublicKey;
use SimpleSAML\XMLSec\Key\SymmetricKey;

/**
 * Tests for SimpleSAML\XMLSec\Alg\Signature\SignatureAlgorithmFactory
 *
 * @package SimpleSAML\XMLSec\Test\Alg
 */
class SignatureAlgorithmFactoryTest extends TestCase
{

    /** @var SymmetricKey */
    protected $skey;

    /** @var PublicKey */
    protected $pkey;


    public function setUp()
    {
        $this->skey = SymmetricKey::generate(16);
        $this->pkey = PublicKey::fromFile('tests/pubkey.pem');
    }


    /**
     * Test obtaining the digest algorithm from a signature algorithm.
     */
    public function testGetDigestAlgorithm()
    {
        $factory = new SignatureAlgorithmFactory([]);
        $hmac = [
            Constants::SIG_HMAC_SHA1      => Constants::DIGEST_SHA1,
            Constants::SIG_HMAC_SHA224    => Constants::DIGEST_SHA224,
            Constants::SIG_HMAC_SHA256    => Constants::DIGEST_SHA256,
            Constants::SIG_HMAC_SHA384    => Constants::DIGEST_SHA384,
            Constants::SIG_HMAC_SHA512    => Constants::DIGEST_SHA512,
            Constants::SIG_HMAC_RIPEMD160 => Constants::DIGEST_RIPEMD160,
        ];

        $rsa = [
            Constants::SIG_RSA_SHA1      => Constants::DIGEST_SHA1,
            Constants::SIG_RSA_SHA224    => Constants::DIGEST_SHA224,
            Constants::SIG_RSA_SHA256    => Constants::DIGEST_SHA256,
            Constants::SIG_RSA_SHA384    => Constants::DIGEST_SHA384,
            Constants::SIG_RSA_SHA512    => Constants::DIGEST_SHA512,
            Constants::SIG_RSA_RIPEMD160 => Constants::DIGEST_RIPEMD160,
        ];

        foreach ($hmac as $signature => $digest) {
            $alg = $factory->getAlgorithm($signature, $this->skey);
            $this->assertEquals($digest, $alg->getDigest());
        }

        foreach ($rsa as $signature => $digest) {
            $alg = $factory->getAlgorithm($signature, $this->pkey);
            $this->assertEquals($digest, $alg->getDigest());
        }
    }


    /**
     * Test for unsupported algorithms.
     *
     * @expectedException RuntimeException
     */
    public function testGetUnknownAlgorithm()
    {
        $factory = new SignatureAlgorithmFactory([]);
        $factory->getAlgorithm('Unknown alg', $this->skey);
    }


    /**
     * Test for blacklisted algorithms.
     *
     * @expectedException InvalidArgumentException
     */
    public function testBlacklistedAlgorithm()
    {
        $factory = new SignatureAlgorithmFactory([Constants::SIG_RSA_SHA1]);
        $this->assertInstanceOf(
            '\SimpleSAML\XMLSec\Alg\Signature\HMAC',
            $factory->getAlgorithm(Constants::SIG_HMAC_SHA1, $this->skey)
        );
        $factory->getAlgorithm(Constants::SIG_RSA_SHA1, $this->pkey);
    }
}
