<?php

namespace SimpleSAML\XMLSec\Test;

use SimpleSAML\XMLSec\Constants as C;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\PrivateKey;
use SimpleSAML\XMLSec\Key\X509Certificate;
use SimpleSAML\XMLSec\Signature;
use SimpleSAML\XMLSec\Utils\DOMDocumentFactory;

/**
 * Test for XML digital signatures.
 *
 * @package SimpleSAML\XMLSec\Test
 */
class SignatureTest extends \PHPUnit_Framework_TestCase
{

    /** @var \DOMDocument */
    protected $basicDoc;

    /** @var PrivateKey */
    protected $privKey;

    /** @var X509Certificate */
    protected $cert;


    /**
     * SignatureTest constructor.
     */
    public function __construct()
    {
        $this->privKey = PrivateKey::fromFile('tests/privkey.pem');
        $this->cert = X509Certificate::fromFile('tests/mycert.pem');
        parent::__construct();
    }


    /**
     * Initialization for all tests.
     */
    public function setUp()
    {
        $this->basicDoc = DOMDocumentFactory::fromFile('tests/xml/basic-doc.xml');
    }


    /**
     * Test blacklisting of signature algorithms.
     */
    public function testBlacklistedAlgorithms()
    {
        // test defaults
        $signature = new Signature($this->basicDoc->documentElement);
        $this->assertEquals([C::SIG_RSA_SHA1, C::SIG_HMAC_SHA1], $signature->getBlacklistedAlgorithms());

        // test emptying the list
        $signature->setBlacklistedAlgorithms([]);
        $this->assertEquals([], $signature->getBlacklistedAlgorithms());

        // test setting the list again
        $signature->setBlacklistedAlgorithms([C::SIG_HMAC_SHA224, C::SIG_HMAC_SHA384]);
        $this->assertEquals([C::SIG_HMAC_SHA224, C::SIG_HMAC_SHA384], $signature->getBlacklistedAlgorithms());
    }


    /**
     * Basic test for setting and getting the prefix for XML elements.
     */
    public function testSetPrefix()
    {
        $signature = new Signature($this->basicDoc->documentElement);

        // test default
        $this->assertEquals('ds', $signature->getPrefix());

        // test setting a prefix
        $signature->setPrefix('pfx');
        $this->assertEquals('pfx', $signature->getPrefix());

        // test clearing the prefix with an empty string
        $signature->setPrefix('');
        $this->assertEquals('', $signature->getPrefix());

        // test clearing the prefix with null
        $signature->setPrefix(null);
        $this->assertEquals('', $signature->getPrefix());

        // test clearing the prefix with false
        $signature->setPrefix(false);
        $this->assertEquals('', $signature->getPrefix());

        // test restoring the default prefix
        $signature->setPrefix('ds');
        $this->assertEquals('ds', $signature->getPrefix());
    }


    /**
     * Basic test for signatures.
     */
    public function testBasicSignature()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReferences([$this->basicDoc], C::DIGEST_SHA1, [C::XMLDSIG_ENVELOPED]);
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-basic-test.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing with an empty URI in the Reference element.
     */
    public function testSignatureWithEmptyURI()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA1, [C::XMLDSIG_ENVELOPED]);
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-empty-uri.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing without a URI in the Reference element.
     */
    public function testSignatureWithNoURI()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA1, [C::XMLDSIG_ENVELOPED], ['force_uri' => false]);
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-no-uri.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test adding the subject of the certificate to the corresponding KeyInfo.
     */
    public function testSignatureWithSubject()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA1, [C::XMLDSIG_ENVELOPED]);
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert, true);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-subject.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing with a user-provided prefix for the XML elements of the signature.
     */
    public function testSignatureWithGivenPrefix()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->setPrefix('pfx');
        $signature->addReference($this->basicDoc, C::DIGEST_SHA1, [C::XMLDSIG_ENVELOPED]);
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/xml-sign-prefix-pfx.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing with no prefix used for the XML elements of the signature.
     */
    public function testSignatureWithNoPrefix()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->setPrefix(false);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA1, [C::XMLDSIG_ENVELOPED]);
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/xml-sign-prefix-none.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing a document that includes comments.
     */
    public function testSignatureWithComments()
    {
        $doc = DOMDocumentFactory::fromString(
            '<ApplicationRequest xmlns:pfx="http://example.org/xmldata/" Id="SomeID">'.
              '<!-- this is a comment -->'.
              '<CustomerId>12345678</CustomerId>'.
              '<Command>GetUserInfo</Command>'.
              '<Timestamp>1317032524</Timestamp>'.
              '<Status>ALL</Status>'.
              '<Environment>DEVELOPMENT</Environment>'.
              '<SoftwareId>ExampleApp 0.1\b</SoftwareId>'.
              '<FileType>ABCDEFG</FileType>'.
            '</ApplicationRequest>'
        );
        $signature = new Signature($doc->documentElement);
        $signature->setCanonicalizationMethod(C::C14N_EXCLUSIVE_WITH_COMMENTS);
        $signature->setBlacklistedAlgorithms([]);
        $signature->addReference(
            $doc->documentElement,
            C::DIGEST_SHA1,
            [C::XMLDSIG_ENVELOPED, C::C14N_EXCLUSIVE_WITH_COMMENTS],
            ['overwrite' => false]//, 'prefix' => 'pfx', 'prefix_ns' => 'http://example.org/xmldata/']
        );
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->prepend();

        $expected = file_get_contents('tests/xml/sign-with-comments.xml');
        $this->assertEquals($expected, $doc->saveXML());
    }


    /**
     * Test that the "root" element provided when building the signature is referenced automatically when signing and no
     * references have been added yet.
     */
    public function testAutomaticallyAddingReferences()
    {
        // now test without explicitly adding the reference
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-basic-test.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test that the "root" element provided when building the signature is referenced automatically when signing and no
     * references have been added yet, and make sure the reference is an xpointer when comments should be retained
     * during canonicalization.
     */
    public function testAutomaticallyAddingReferencesWithComments()
    {
        // now test without explicitly adding the reference
        $doc = DOMDocumentFactory::fromFile('tests/xml/basic-doc-embedded-comments.xml');
        $signature = new Signature($doc->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $signature->setCanonicalizationMethod(C::C14N_EXCLUSIVE_WITH_COMMENTS);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->addX509Certificates($this->cert);
        $signature->prepend();

        $expected = file_get_contents('tests/xml/withcomment-xpointer-uri.xml');
        $this->assertEquals($expected, $doc->saveXML());
    }


    /**
     * Test adding a reference with a new ID (overwriting the existing).
     */
    public function testSignatureWithRegeneratedId()
    {
        $doc = DOMDocumentFactory::fromString(
            '<ApplicationRequest xmlns="http://example.org/xmldata/" ID="SomeID">'.
            '<!-- this is a comment -->'.
            '<CustomerId>12345678</CustomerId>'.
            '<Command>GetUserInfo</Command>'.
            '<Timestamp>1317032524</Timestamp>'.
            '<Status>ALL</Status>'.
            '<Environment>DEVELOPMENT</Environment>'.
            '<SoftwareId>ExampleApp 0.1\b</SoftwareId>'.
            '<FileType>ABCDEFG</FileType>'.
            '</ApplicationRequest>'
        );
        $signature = new Signature($doc->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $signature->addReference(
            $doc->documentElement,
            C::DIGEST_SHA1,
            [C::XMLDSIG_ENVELOPED, C::C14N_EXCLUSIVE_WITH_COMMENTS],
            ['id_name' => 'ID', 'overwrite' => true]
        );

        $app = $doc->getElementsByTagName('ApplicationRequest')->item(0);
        $this->assertNotEmpty("SomeID", $app->getAttribute('ID'));
    }


    /**
     * Test that signing with a blacklisted algorithm fails.
     *
     * @expectedException InvalidArgumentException
     */
    public function testSignWithBlacklistedAlg()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA1, [C::XMLDSIG_ENVELOPED]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
    }


    /**
     * Test signing a document with RSA-SHA224.
     */
    public function testSignatureWithRsaSha224()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA224, [C::XMLDSIG_ENVELOPED]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA224);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-sha224-rsa-sha224-test.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing a document with RSA-SHA256.
     */
    public function testSignatureWithRsaSha256()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA256, [C::XMLDSIG_ENVELOPED]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA256);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-sha256-rsa-sha256-test.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing a document with RSA-SHA384.
     */
    public function testSignatureWithRsaSha384()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA384, [C::XMLDSIG_ENVELOPED]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA384);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-sha384-rsa-sha384-test.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Test signing a document with RSA-SHA512.
     */
    public function testSignatureWithRsaSha512()
    {
        $signature = new Signature($this->basicDoc->documentElement);
        $signature->addReference($this->basicDoc, C::DIGEST_SHA512, [C::XMLDSIG_ENVELOPED]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA512);
        $signature->addX509Certificates($this->cert);
        $signature->append();

        $expected = file_get_contents('tests/xml/sign-sha512-rsa-sha512-test.xml');
        $this->assertEquals($expected, $this->basicDoc->saveXML());
    }


    /**
     * Make sure that comments are removed when processing a reference to an element by ID.
     *
     * > URI="#chapter1"
     * >   Identifies a node-set containing the element with ID attribute value 'chapter1' of the XML resource
     * >   containing the signature. XML Signature (and its applications) modify this node-set to include the element
     * >   plus all descendants including namespaces and attributes -- but not comments.
     *
     * @throws \ReflectionException
     *
     * @see https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-ReferenceProcessingModel
     */
    public function testReferenceWithCommentsRemovedWhenIDReferenced()
    {
        $doc = DOMDocumentFactory::fromFile('tests/xml/withcomment-id-uri.xml');
        $signature = Signature::fromXML($doc->documentElement);
        $signature->setIdAttributes(['xml:id']);
        $this->assertEquals(['xml:id'], $signature->getIdAttributes());
        $validateReference = new \ReflectionMethod('\SimpleSAML\XMLSec\Signature', 'validateReferences');
        $validateReference->setAccessible(true);
        $this->assertTrue($validateReference->invokeArgs($signature, []));
    }


    /**
     * Make sure that comments are removed when processing an enveloped signature.
     *
     * > URI=""
     * >   Identifies the node-set (minus any comment nodes) of the XML resource containing the signature
     *
     * @throws \ReflectionException
     *
     * @see https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-ReferenceProcessingModel
     */
    public function testReferenceWithCommentsRemovedWhenEmptyID()
    {
        $doc = DOMDocumentFactory::fromFile('tests/xml/withcomment-empty-uri.xml');
        $signature = Signature::fromXML($doc->documentElement);
        $signature->setIdAttributes(['xml:id']);
        $validateReference = new \ReflectionMethod('\SimpleSAML\XMLSec\Signature', 'validateReferences');
        $validateReference->setAccessible(true);
        $this->assertTrue($validateReference->invokeArgs($signature, []));
    }


    /**
     * Make sure that comments are removed when processing a reference to an object.
     *
     * @throws \ReflectionException
     */
    public function testReferenceWithCommentsRemovedWhenObjectID()
    {
        $doc = DOMDocumentFactory::fromFile('tests/xml/withcomment-id-uri-object.xml');
        $signature = Signature::fromXML($doc);
        $signature->setIdAttributes(['xml:id']);
        $validateReference = new \ReflectionMethod('\SimpleSAML\XMLSec\Signature', 'validateReferences');
        $validateReference->setAccessible(true);
        $this->assertTrue($validateReference->invokeArgs($signature, []));
    }


    /**
     *
     */
    public function testEnvelopingSignature()
    {
        $doc = DOMDocumentFactory::fromString(
            '<root Id="SomeID">'.
            '<!-- This comment should not be included in the digest. -->'.
            '<!-- withcomment-id-uri ds:signature tag -->'.
            '<!-- Neither should this comment be included. -->'.
            '<childnode>'.
            'sometext'.
            '<!-- Nor this comment. -->'.
            '</childnode>'.
            '</root>'
        );
        $signature = new Signature($doc->documentElement);
        $signature->addReference(
            $doc->documentElement,
            C::DIGEST_SHA1,
            [C::XMLDSIG_ENVELOPED],
            ['overwrite' => false]
        );
        $signature->setBlacklistedAlgorithms([]);
        $signature->sign($this->privKey, C::SIG_RSA_SHA1);
        $signature->envelop();
        $object = $signature->getRoot();

        $expected = file_get_contents('tests/xml/enveloping-sig.xml');
        $this->assertEquals($expected, $object->ownerDocument->saveXML());
    }


    // XML Signature verification


    /**
     * Test verifying a signature with the default blacklisted algorithms.
     *
     * @expectedException InvalidArgumentException
     */
    public function testVerifySigWithAlgBlacklistedByDefault()
    {
        $xml = DOMDocumentFactory::fromFile('tests/xml/sign-basic-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $signature->verify($this->cert);
    }


    /**
     * Test verifying a signature with a blacklisted algorithm.
     *
     * @expectedException InvalidArgumentException
     */
    public function testVerifySigWithCustomBlacklistedAlg()
    {
        $xml = DOMDocumentFactory::fromFile('tests/xml/sign-sha256-rsa-sha256-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $signature->setBlacklistedAlgorithms([C::SIG_RSA_SHA256]);
        $signature->verify($this->cert);
    }


    /**
     * Test the verification of signatures with different supported algorithms.
     */
    public function testVerifySignature()
    {
        // verify our own signature
        $xml = DOMDocumentFactory::fromFile('tests/xml/sign-basic-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify our own signature.');
        $this->assertEquals(C::SIG_RSA_SHA1, $signature->getSignatureMethod());

        $xml = DOMDocumentFactory::fromFile('tests/xml/sign-sha224-rsa-sha224-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify our own RSA-SHA224 signature.');
        $this->assertEquals(C::SIG_RSA_SHA224, $signature->getSignatureMethod());

        $xml = DOMDocumentFactory::fromFile('tests/xml/sign-sha256-rsa-sha256-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify our own RSA-SHA256 signature.');
        $this->assertEquals(C::SIG_RSA_SHA256, $signature->getSignatureMethod());

        $xml = DOMDocumentFactory::fromFile('tests/xml/sign-sha384-rsa-sha384-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify our own RSA-SHA384 signature.');
        $this->assertEquals(C::SIG_RSA_SHA384, $signature->getSignatureMethod());

        $xml = DOMDocumentFactory::fromFile('tests/xml/sign-sha512-rsa-sha512-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify our own RSA-SHA512 signature.');
        $this->assertEquals(C::SIG_RSA_SHA512, $signature->getSignatureMethod());

        // verify signatures made by other library
        $xml = DOMDocumentFactory::fromFile('tests/xml/alt/sign-basic-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify alternative signature.');
        $this->assertEquals(C::SIG_RSA_SHA1, $signature->getSignatureMethod());

        $xml = DOMDocumentFactory::fromFile('tests/xml/alt/sign-sha256-rsa-sha256-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify alternative RSA-SHA256 signature.');
        $this->assertEquals(C::SIG_RSA_SHA256, $signature->getSignatureMethod());

        $xml = DOMDocumentFactory::fromFile('tests/xml/alt/sign-formatted-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $this->assertTrue($signature->verify($this->cert), 'Failed to verify formatted signature.');

        $xml = DOMDocumentFactory::fromFile('tests/xml/alt/sign-sha512-rsa-sha512-test.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $validateRef = new \ReflectionMethod('\SimpleSAML\XMLSec\Signature', 'validateReferences');
        $validateRef->setAccessible(true);
        $this->assertTrue($validateRef->invokeArgs($signature, []), 'Failed to verify formatted RSA-SHA512 signature.');
    }


    /**
     * Verify enveloping signatures.
     */
    public function testVerifyEnvelopingSignature()
    {
        $signature = Signature::fromXML(DOMDocumentFactory::fromFile('tests/xml/enveloping-sig.xml'));
        $signature->setBlacklistedAlgorithms([]);
        $this->assertTrue($signature->verify($this->cert));
    }


    /**
     * Make sure that incorrect signatures fail to verify.
     */
    public function testVerificationFailure()
    {
        $xml = DOMDocumentFactory::fromFile('tests/xml/invalid-sign.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $this->assertFalse($signature->verify($this->cert), 'A signature was verified with the wrong public key.');
    }


    /**
     * Test to evaluate how signed nodes are transformed after being verified (e.g. comments removed when using
     * exclusive canonicalization, etc).
     */
    public function testVerifiedNode()
    {
        $xml = DOMDocumentFactory::fromFile('tests/xml/withcomment-id-uri.xml');
        $signature = Signature::fromXML($xml->documentElement);
        $signature->setBlacklistedAlgorithms([]);
        $signature->setIdAttributes(['xml:id']);
        $this->assertTrue($signature->verify($this->cert));

        $verified = $signature->getVerifiedElements();
        $this->assertCount(1, $verified);

        $expected = file_get_contents('tests/xml/withcomment-id-uri-verified.xml');
        $node = array_pop($verified);
        $this->assertEquals($expected, $node->ownerDocument->saveXML());
    }


    /**
     * Test for the vulnerability discovered by Duo Security which allowed to alter contents of the XML without
     * invalidating the signature.
     *
     * @see https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
     */
    public function testForCommentsInContents()
    {
        $doc = DOMDocumentFactory::fromString(
            '<ApplicationRequest xmlns="http://example.org/xmldata/" Id="SomeID">'.
            '<CustomerId>12345678<!--0-->9</CustomerId>'.
            '</ApplicationRequest>'
        );
        $signature = new Signature($doc->documentElement);
        $signature->addReference(
            $doc->documentElement,
            C::DIGEST_SHA224,
            [C::XMLDSIG_ENVELOPED],
            ['overwrite' => false]
        );
        $signature->sign($this->privKey, C::SIG_RSA_SHA224);
        $signature->append();

        $verify = Signature::fromXML($doc->documentElement);
        $this->assertTrue($verify->verify($this->cert));

        $verified = $verify->getVerifiedElements()['SomeID'];

        $this->assertEquals(
            '123456789',
            $verified->ownerDocument->getElementsByTagName('CustomerId')->item(0)->textContent,
            'Contents after signature verification are affected by inserted comments.'
        );

        $this->assertEquals(
            '123456789',
            $doc->getElementsByTagName('CustomerId')->item(0)->textContent,
            'XML backend is ignoring nodes after comments.'
        );
    }
}
