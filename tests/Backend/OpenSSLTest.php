<?php

namespace SimpleSAML\Test\Backend;

use SimpleSAML\XMLSec\Backend\OpenSSL;
use SimpleSAML\XMLSec\Constants;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\PrivateKey;
use SimpleSAML\XMLSec\Key\PublicKey;
use SimpleSAML\XMLSec\Key\SymmetricKey;

/**
 * Tests for SimpleSAML\XMLSec\Backend\OpenSSL.
 *
 * @package SimpleSAML\Test\Backend
 */
class OpenSSLTest extends \PHPUnit_Framework_TestCase
{

    /** @var PrivateKey */
    protected $privKey;

    /** @var PublicKey */
    protected $pubKey;

    /** @var OpenSSL */
    protected $backend;

    /** @var string */
    protected $validSig;

    protected function setUp()
    {
        $this->privKey = PrivateKey::fromFile('tests/privkey.pem');
        $this->pubKey = PublicKey::fromFile('tests/pubkey.pem');
        $this->backend = new OpenSSL();
        $this->backend->setDigestAlg(Constants::DIGEST_SHA256);
        $this->validSig =
            'cdd80e925e509f954807448217157367c00f7ff53c5eec74ea51ef5fee48a048283b37639c7f43400631fa2b9063a1ed05710'.
            '4721887a10ad62f128c26e01f363538a84ad261f40b80df86de9cc920d1dce2c27058da81d9c7aa0e68e459ab94995e27e57d'.
            '183ff08188b338f7975681ad67b1b6f8d174b57b666f787b801df9511d7a90e90e9af2386f4051669a4763ce5e9720fc8ae2b'.
            'c90e7c33d92a4bcecefddb06599b1f3adf48cde42d442d76c4d938d1570379bf1ab45feae95f94f48a460a8894f90e0208ba9'.
            '3d86b505f32942f53bdab8e506ba227cc813cd26a0ba9a93c46f27dd0c2b7452fd8c79c7aa72b885d95ef6d1dc810829b0832'.
            'abe290d';
    }


    /**
     * Test that signing works.
     */
    public function testSign()
    {
        $this->assertEquals($this->validSig, bin2hex($this->backend->sign($this->privKey, 'Signed text')));
    }


    /**
     * Test signing with something that's not a private key.
     *
     * @expectedException RuntimeException
     */
    public function testSignFailure()
    {
        $k = SymmetricKey::generate(10);
        @$this->backend->sign($k, 'Signed text');
    }


    /**
     * Test the verification of signatures.
     */
    public function testVerify()
    {
        // test successful verification
        $this->assertTrue($this->backend->verify($this->pubKey, 'Signed text', hex2bin($this->validSig)));

        // test forged signature
        $wrongSig = $this->validSig;
        $wrongSig[10] = '6';
        $this->assertFalse($this->backend->verify($this->pubKey, 'Signed text', hex2bin($wrongSig)));
    }


    /**
     * Test for wrong digests.
     *
     * @expectedException InvalidArgumentException
     */
    public function testSetUnknownDigest()
    {
        $backend = new OpenSSL();
        $backend->setDigestAlg('foo');
    }



    /**
     * Test ISO 10126 padding.
     */
    public function testPad()
    {
        $backend = new OpenSSL();
        $backend->setCipher(Constants::BLOCK_ENC_AES256_GCM);
        $this->assertEquals('666f6f0d0d0d0d0d0d0d0d0d0d0d0d0d', bin2hex($backend->pad('foo')));
        $this->assertEquals(
            '666f6f626172666f6f626172666f6f6261720e0e0e0e0e0e0e0e0e0e0e0e0e0e',
            bin2hex($backend->pad('foobarfoobarfoobar'))
        );
    }


    /**
     * Test ISO 10126 unpadding.
     */
    public function testUnpad()
    {
        $backend = new OpenSSL();
        $backend->setCipher(Constants::BLOCK_ENC_AES256_GCM);
        $this->assertEquals('foo', $backend->unpad(hex2bin('666f6f0d0d0d0d0d0d0d0d0d0d0d0d0d')));
        $this->assertEquals(
            'foobarfoobarfoobar',
            $backend->unpad(hex2bin('666f6f626172666f6f626172666f6f6261720e0e0e0e0e0e0e0e0e0e0e0e0e0e'))
        );
    }


    /**
     * Test for wrong ciphers.
     *
     * @expectedException InvalidArgumentException
     */
    public function testSetUnknownCipher()
    {
        $backend = new OpenSSL();
        $backend->setCipher('foo');
    }
}
