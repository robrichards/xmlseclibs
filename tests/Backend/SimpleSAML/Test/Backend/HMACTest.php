<?php

namespace SimpleSAML\Test\Backend;

use SimpleSAML\XMLSec\Backend\HMAC;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Key\SymmetricKey;

/**
 * Test for SimpleSAML\XMLSec\Backend\HMAC.
 *
 * @package SimpleSAML\Test\Backend
 */
class HMACTest extends \PHPUnit_Framework_TestCase
{

    const PLAINTEXT = "plaintext";
    const SIGNATURE = "61b85d9e800ed0eca556a304cc9e1ac7ae8eecb3";
    const SECRET = 'secret key';

    /** @var SymmetricKey */
    protected $key;


    /**
     * Initialize shared key.
     */
    protected function setUp()
    {
        $this->key = new SymmetricKey(self::SECRET);
    }


    /**
     * Test signing of messages.
     */
    public function testSign()
    {
        $backend = new HMAC();
        $backend->setDigestAlg(Constants::DIGEST_SHA1);
        $this->assertEquals(self::SIGNATURE, bin2hex($backend->sign($this->key, self::PLAINTEXT)));
    }


    /**
     * Test for wrong digests.
     *
     * @expectedException InvalidArgumentException
     */
    public function testSetUnknownDigest()
    {
        $backend = new HMAC();
        $backend->setDigestAlg('foo');
    }


    /**
     * Test verification of signatures.
     */
    public function testVerify()
    {
        // test successful verification
        $backend = new HMAC();
        $backend->setDigestAlg(Constants::DIGEST_SHA1);
        $this->assertTrue($backend->verify($this->key, self::PLAINTEXT, hex2bin(self::SIGNATURE)));

        // test failure to verify with different plaintext
        $this->assertFalse($backend->verify($this->key, 'foo', hex2bin(self::SIGNATURE)));

        // test failure to verify with different signature
        $this->assertFalse($backend->verify(
            $this->key,
            self::PLAINTEXT,
            hex2bin('12345678901234567890abcdefabcdef12345678')
        ));

        // test failure to verify with wrong key
        $key = new SymmetricKey('wrong secret');
        $this->assertFalse($backend->verify($key, self::PLAINTEXT, hex2bin(self::SIGNATURE)));

        // test failure to verify with wrong digest algorithm
        $backend->setDigestAlg(Constants::DIGEST_RIPEMD160);
        $this->assertFalse($backend->verify($this->key, self::PLAINTEXT, hex2bin(self::SIGNATURE)));
    }
}
