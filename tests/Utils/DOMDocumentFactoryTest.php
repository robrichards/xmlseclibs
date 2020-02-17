<?php

namespace SimpleSAML\XMLSec\Test\Utils;

use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Exception\UnparseableXmlException;
use SimpleSAML\XMLSec\Utils\DOMDocumentFactory;

/**
 * Tests for SimpleSAML\XMLSec\Utils\DOMDocumentFactory
 *
 * @package SimpleSAML\XMLSec\Test\Utils
 */
class DOMDocumentFactoryTest extends TestCase
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
     */
    public function testFromFileWrongArgument()
    {
        $this->expectException(InvalidArgumentException::class);
        DOMDocumentFactory::fromFile([]);
    }


    /**
     * Test missing file.
     */
    public function testFromInvalidFile()
    {
        $this->expectException(InvalidArgumentException::class);
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
     */
    public function testFromEmptyString()
    {
        $this->expectException(InvalidArgumentException::class);
        DOMDocumentFactory::fromString('');
    }


    /**
     * Test creation from a string that doesn't contain valid XML.
     */
    public function testFromUnparseableString()
    {
        $this->expectException(UnparseableXmlException::class);
        DOMDocumentFactory::fromString('>this is not valid XML<');
    }


    /**
     * Test creation from a string containing potentially dangerous XML.
     */
    public function testFromStringDangerousXML()
    {
        $this->expectException(RuntimeException::class);
        DOMDocumentFactory::fromString('<!DOCTYPE test [<!ENTITY foo "bar">]>');
    }
}
