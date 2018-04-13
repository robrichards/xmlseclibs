<?php

namespace SimpleSAML\XMLSec\Test\Key;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Key\X509Certificate;

/**
 * Test for SimpleSAML\XMLSec\Key\X509Certificate
 *
 * @package SimpleSAML\XMLSec\Test\Key
 */
class X509CertificateTest extends \PHPUnit_Framework_TestCase
{

    /** @var resource */
    protected $cert;

    /** @var string */
    protected $f;

    /** @var X509Certificate */
    protected $c;


    /**
     * Initialize the test by loading the file ourselves.
     */
    protected function setUp()
    {
        $this->f = file_get_contents('tests/mycert.pem');
        $this->cert = openssl_pkey_get_details(openssl_pkey_get_public(openssl_x509_read($this->f)));
        $this->c = new X509Certificate($this->f);
    }


    /**
     * Cover basic creation and retrieval.
     */
    public function testCreation()
    {
        $pubDetails = openssl_pkey_get_details($this->c->get());
        $this->assertEquals($this->cert['key'], $pubDetails['key']);
    }


    /**
     * Test for retrieval of the PEM-encoded certificate.
     */
    public function testGetCertificate()
    {
        $this->assertEquals($this->f, $this->c->getCertificate());
    }


    /**
     * Test for retrieval of the certificate's details.
     */
    public function testGetCertificateDetails()
    {
        $this->assertEquals(openssl_x509_parse($this->f), $this->c->getCertificateDetails());
    }


    /**
     * Test thumbprint generation from a certificate.
     */
    public function testGetRawThumbprint()
    {
        if (!function_exists('openssl_x509_fingerprint')) {
            $this->markTestSkipped();
        }
        $this->assertEquals(openssl_x509_fingerprint($this->f), $this->c->getRawThumbprint());
    }


    /**
     * Test thumbprint generation with an invalid digest algorithm.
     *
     * @expectedException InvalidArgumentException
     */
    public function testGetRawThumbprintWithWrongAlg()
    {
        $this->c->getRawThumbprint('invalid');
    }


    /**
     * Test creation from a file containing the PEM-encoded certificate.
     */
    public function testFromFile()
    {
        $c = X509Certificate::fromFile('tests/mycert.pem');
        $pubDetails = openssl_pkey_get_details($c->get());
        $this->assertEquals($this->cert['key'], $pubDetails['key']);
    }
}
