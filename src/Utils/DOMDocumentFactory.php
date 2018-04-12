<?php

namespace SimpleSAML\XMLSec\Utils;

use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Exception\UnparseableXmlException;

/**
 * A factory class to generate DOM documents.
 *
 * @package SimpleSAML\XMLSec\Utils
 */
final class DOMDocumentFactory
{
    private function __construct()
    {
    }

    /**
     * Create a new DOM document from a string.
     *
     * @param string $xml A string containing XML to create a DOM document from.
     *
     * @return \DOMDocument The DOM document containing the given XML contents.
     */
    public static function fromString($xml)
    {
        if (!is_string($xml) || trim($xml) === '') {
            throw InvalidArgumentException::invalidType('non-empty string', $xml);
        }

        $entityLoader   = libxml_disable_entity_loader(true);
        $internalErrors = libxml_use_internal_errors(true);
        libxml_clear_errors();

        $domDocument = self::create();
        $options     = LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_NONET;
        if (defined(LIBXML_COMPACT)) {
            $options |= LIBXML_COMPACT;
        }

        $loaded = $domDocument->loadXML($xml, $options);

        libxml_use_internal_errors($internalErrors);
        libxml_disable_entity_loader($entityLoader);

        if (!$loaded) {
            $error = libxml_get_last_error();
            libxml_clear_errors();

            throw new UnparseableXmlException($error);
        }

        libxml_clear_errors();

        foreach ($domDocument->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                throw new RuntimeException(
                    'Dangerous XML detected, DOCTYPE nodes are not allowed in the XML body'
                );
            }
        }

        return $domDocument;
    }

    /**
     * Create a new DOM document from a file.
     *
     * @param string $file The path to the file with XML contents.
     *
     * @return \DOMDocument The DOM document with the XML contents of the file.
     */
    public static function fromFile($file)
    {
        if (!is_string($file)) {
            throw InvalidArgumentException::invalidType('string', $file);
        }

        if (!is_file($file)) {
            throw new InvalidArgumentException(sprintf('Path "%s" is not a file', $file));
        }

        if (!is_readable($file)) {
            throw new InvalidArgumentException(sprintf('File "%s" is not readable', $file));
        }

        // libxml_disable_entity_loader(true) disables \DOMDocument::load() method
        // so we need to read the content and use \DOMDocument::loadXML()
        $xml = file_get_contents($file);
        if ($xml === false) {
            throw new RuntimeException(sprintf(
                'Contents of readable file "%s" could not be read',
                $file
            ));
        }

        if (trim($xml) === '') {
            throw new RuntimeException(sprintf('File "%s" does not have content', $file));
        }

        return static::fromString($xml);
    }

    /**
     * Create a new DOM document.
     *
     * @return \DOMDocument The new document.
     */
    public static function create()
    {
        return new \DOMDocument();
    }
}
