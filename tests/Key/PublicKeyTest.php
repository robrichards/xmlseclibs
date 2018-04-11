<?php

namespace SimpleSAML\XMLSec\Test\Key;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Key\PublicKey;

/**
 * Tests for SimpleSAML\XMLSec\Key\PublicKey.
 *
 * @package SimpleSAML\XMLSec\Test\Key
 */
class PublicKeyTest extends \PHPUnit_Framework_TestCase
{

    /** @var resource */
    protected $pubKey;

    /** @var string */
    protected $f;


    /**
     * Initialize the test by loading the file ourselves.
     */
    protected function setUp()
    {
        $this->f = file_get_contents('tests/pubkey.pem');
        $this->pubKey = openssl_pkey_get_details(openssl_pkey_get_public($this->f));
    }

    /**
     * Cover basic creation and retrieval.
     */
    public function testCreation()
    {
        $k = new PublicKey($this->f);
        $keyDetails = openssl_pkey_get_details($k->get());
        $this->assertEquals($this->pubKey['key'], $keyDetails['key']);
    }


    /**
     * Test creation from a file containing the PEM-encoded public key.
     */
    public function testFromFile()
    {
        $k = PublicKey::fromFile('tests/pubkey.pem');
        $keyDetails = openssl_pkey_get_details($k->get());
        $this->assertEquals($this->pubKey['key'], $keyDetails['key']);
    }


    /**
     * Test failure to create key from missing file.
     *
     * @expectedException InvalidArgumentException
     */
    public function testFromMissingFile()
    {
        @PublicKey::fromFile('foo/bar');
    }


    /**
     * Test creation from the RSA public key details (modulus and exponent).
     */
    public function testFromDetails()
    {
        $k = PublicKey::fromDetails($this->pubKey['rsa']['n'], $this->pubKey['rsa']['e']);
        $keyDetails = openssl_pkey_get_details($k->get());
        $this->assertEquals($this->pubKey['key'], $keyDetails['key']);
    }
}
