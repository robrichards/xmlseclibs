<?php

namespace SimpleSAML\XMLSec\Test\Alg;

use SimpleSAML\XMLSec\Alg\Signature\HMAC;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Key\PrivateKey;
use SimpleSAML\XMLSec\Key\PublicKey;
use SimpleSAML\XMLSec\Key\SymmetricKey;
use SimpleSAML\XMLSec\Key\X509Certificate;

/**
 * Tests for SimpleSAML\XMLSec\Alg\Signature\HMAC.
 *
 * @package SimpleSAML\Test\Signature
 */
class HMACSignatureTest extends \PHPUnit_Framework_TestCase
{

    /** @var string */
    protected $plaintext = 'plaintext';

    /** @var string */
    protected $secret = 'de54fbd0f10c34df6e800b11043024fa';


    /**
     * Test that signing works.
     */
    public function testSign()
    {
        $key = new SymmetricKey($this->secret);

        // test HMAC-SHA1
        $hmac = new HMAC($key, Constants::DIGEST_SHA1);
        $this->assertEquals('655c3b4277b39f31dedf5adc7f4cc9f07da7102c', bin2hex($hmac->sign($this->plaintext)));

        // test HMAC-SHA224
        $hmac = new HMAC($key, Constants::DIGEST_SHA224);
        $this->assertEquals(
            '645405ccc725e10022e5a89e98cc33db07c0cd89ba78c21caf931f40',
            bin2hex($hmac->sign($this->plaintext))
        );

        // test HMAC-SHA256
        $hmac = new HMAC($key, Constants::DIGEST_SHA256);
        $this->assertEquals(
            '721d8385785a3d4c8d16c7b4a96b343728a11e221656e6dd9502d540d4e87ef2',
            bin2hex($hmac->sign($this->plaintext))
        );

        // test HMAC-SHA384
        $hmac = new HMAC($key, Constants::DIGEST_SHA384);
        $this->assertEquals(
            'b3ad2e39a057fd7a952cffd503d30eca295c6698dc23ddf0bebf98631a0162da0db0105db156a220dec78cebaf2c202c',
            bin2hex($hmac->sign($this->plaintext))
        );

        // test HMAC-SHA512
        $hmac = new HMAC($key, Constants::DIGEST_SHA512);
        $this->assertEquals(
            '9cc73c95f564a142b28340cf6e1d6b509a9e97dab6577e5d0199760a858105185252e203b6b096ad24708a2b7e34a0f506776d88e'.
            '2f47fff055fc51342b69cdc',
            bin2hex($hmac->sign($this->plaintext))
        );

        // test HMAC-RIPEMD160
        $hmac = new HMAC($key, Constants::DIGEST_RIPEMD160);
        $this->assertEquals('a9fd77b68644464d08be0ba2cd998eab3e2a7b1d', bin2hex($hmac->sign($this->plaintext)));
    }


    /**
     * Test that signature verification works.
     */
    public function testVerify()
    {
        $key = new SymmetricKey($this->secret);

        // test HMAC-SHA1
        $hmac = new HMAC($key, Constants::DIGEST_SHA1);
        $this->assertTrue($hmac->verify($this->plaintext, hex2bin('655c3b4277b39f31dedf5adc7f4cc9f07da7102c')));

        // test HMAC-SHA224
        $hmac = new HMAC($key, Constants::DIGEST_SHA224);
        $this->assertTrue($hmac->verify(
            $this->plaintext,
            hex2bin('645405ccc725e10022e5a89e98cc33db07c0cd89ba78c21caf931f40')
        ));

        // test HMAC-SHA256
        $hmac = new HMAC($key, Constants::DIGEST_SHA256);
        $this->assertTrue($hmac->verify(
            $this->plaintext,
            hex2bin('721d8385785a3d4c8d16c7b4a96b343728a11e221656e6dd9502d540d4e87ef2')
        ));

        // test HMAC-SHA384
        $hmac = new HMAC($key, Constants::DIGEST_SHA384);
        $this->assertTrue($hmac->verify(
            $this->plaintext,
            hex2bin('b3ad2e39a057fd7a952cffd503d30eca295c6698dc23ddf0bebf98631a0162da0db0105db156a220dec78cebaf2c202c')
        ));

        // test HMAC-SHA512
        $hmac = new HMAC($key, Constants::DIGEST_SHA512);
        $this->assertTrue($hmac->verify(
            $this->plaintext,
            hex2bin(
                '9cc73c95f564a142b28340cf6e1d6b509a9e97dab6577e5d0199760a858105185252e203b6b096ad24708a2b7e34a0f5067'.
                '76d88e2f47fff055fc51342b69cdc'
            )
        ));

        // test HMAC-RIPEMD160
        $hmac = new HMAC($key, Constants::DIGEST_RIPEMD160);
        $this->assertTrue($hmac->verify($this->plaintext, hex2bin('a9fd77b68644464d08be0ba2cd998eab3e2a7b1d')));
    }


    /**
     * Test that signature verification fails properly.
     */
    public function testVerificationFailure()
    {
        $key = new SymmetricKey($this->secret);

        // test wrong plaintext
        $hmac = new HMAC($key, Constants::DIGEST_SHA1);
        $this->assertFalse($hmac->verify($this->plaintext.'.', hex2bin('655c3b4277b39f31dedf5adc7f4cc9f07da7102c')));

        // test wrong signature
        $this->assertFalse($hmac->verify($this->plaintext, hex2bin('655c3b4277b39f31dedf5adc7f4cc9f07da7102d')));

        // test wrong key
        $wrongKey = new SymmetricKey('de54fbd0f10c34df6e800b11043024fb');
        $hmac = new HMAC($wrongKey, Constants::DIGEST_SHA1);
        $this->assertFalse($hmac->verify($this->plaintext, hex2bin('655c3b4277b39f31dedf5adc7f4cc9f07da7102c')));
    }


    /**
     * Test that verification fails when the wrong type of key is passed.
     */
    public function testVerifyWithCertificate()
    {
        if (version_compare(phpversion(), '7.0', '>=')) {
            $this->setExpectedException('TypeError');
            new HMAC(X509Certificate::fromFile('tests/mycert.pem'));
        } else {
            $this->markTestSkipped();
        }
    }


    /**
     * Test that verification fails when the wrong type of key is passed.
     */
    public function testVerifyWithPublicKey()
    {
        if (version_compare(phpversion(), '7.0', '>=')) {
            $this->setExpectedException('TypeError');
            new HMAC(PublicKey::fromFile('tests/pubkey.pem'));
        } else {
            $this->markTestSkipped();
        }
    }


    /**
     * Test that verification fails when the wrong type of key is passed.
     */
    public function testVerifyWithPrivateKey()
    {
        if (version_compare(phpversion(), '7.0', '>=')) {
            $this->setExpectedException('TypeError');
            new HMAC(PrivateKey::fromFile('tests/privkey.pem'));
        } else {
            $this->markTestSkipped();
        }
    }
}
