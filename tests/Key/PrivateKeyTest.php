<?php

namespace SimpleSAML\XMLSec\Test\Key;

use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSec\Key\PrivateKey;

/**
 * Tests for SimpleSAML\XMLSec\Key\PrivateKey
 *
 * @package SimpleSAML\XMLSec\Test\Key
 */
class PrivateKeyTest extends TestCase
{

    /** @var resource */
    protected $privKey;

    /** @var string */
    protected $f;


    /**
     * Initialize the test by loading the file ourselves.
     */
    protected function setUp(): void
    {
        $this->f = file_get_contents('tests/privkey.pem');
        $this->privKey = openssl_pkey_get_details(openssl_pkey_get_private($this->f));
    }


    /**
     * Cover basic creation and retrieval.
     */
    public function testCreation()
    {
        $k = new PrivateKey($this->f);
        $keyDetails = openssl_pkey_get_details($k->get());
        $this->assertEquals($this->privKey['key'], $keyDetails['key']);
    }


    /**
     * Test creation from a file containing the PEM-encoded private key.
     */
    public function testFromFile()
    {
        $k = PrivateKey::fromFile('tests/privkey.pem');
        $keyDetails = openssl_pkey_get_details($k->get());
        $this->assertEquals($this->privKey['key'], $keyDetails['key']);
    }
}
