<?php

namespace SimpleSAML\XMLSec\Test\Utils;

use SimpleSAML\XMLSec\Utils\DOMDocumentFactory;

/**
 * Tests for SimpleSAML\XMLSec\Utils\DOMDocumentFactory
 *
 * @package SimpleSAML\XMLSec\Test\Utils
 */
class DOMDocumentFactoryTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Test simple creation.
     */
    public function testCreate()
    {
        $this->assertInstanceOf('DOMDocument', DOMDocumentFactory::create());
    }


    /**
     * Test creation from a file.
     */
    public function testFromFile()
    {
        $this->assertInstanceOf('DOMDocument', DOMDocumentFactory::fromFile('tests/xml/basic-doc.xml'));
    }


    /**
     * Test wrong argument type passed to fromFile().
     *
     * @expectedException \SimpleSAML\XMLSec\Exception\InvalidArgumentException
     */
    public function testFromFileWrongArgument()
    {
        DOMDocumentFactory::fromFile([]);
    }


    /**
     * Test missing file.
     *
     * @expectedException \SimpleSAML\XMLSec\Exception\InvalidArgumentException
     */
    public function testFromInvalidFile()
    {
        DOMDocumentFactory::fromFile('/foo/bar');
    }


    /**
     * Test creation from a string.
     */
    public function testFromString()
    {
        $this->assertInstanceOf('DOMDocument', DOMDocumentFactory::fromString('<xml>XML</xml>'));
    }


    /**
     * Test creation from an empty string.
     *
     * @expectedException \SimpleSAML\XMLSec\Exception\InvalidArgumentException
     */
    public function testFromEmptyString()
    {
        DOMDocumentFactory::fromString('');
    }


    /**
     * Test creation from a string that doesn't contain valid XML.
     *
     * @expectedException \SimpleSAML\XMLSec\Exception\UnparseableXmlException
     */
    public function testFromUnparseableString()
    {
        DOMDocumentFactory::fromString('>this is not valid XML<');
    }


    /**
     * Test creation from a string containing potentially dangerous XML.
     *
     * @expectedException \SimpleSAML\XMLSec\Exception\RuntimeException
     */
    public function testFromStringDangerousXML()
    {
        DOMDocumentFactory::fromString('<!DOCTYPE test [<!ENTITY foo "bar">]>');
    }
}
