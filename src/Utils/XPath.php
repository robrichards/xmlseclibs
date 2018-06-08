<?php

namespace SimpleSAML\XMLSec\Utils;

use SimpleSAML\XMLSec\Constants as C;
use SimpleSAML\XMLSec\Exception\RuntimeException;

/**
 * Compilation of utilities for XPath.
 *
 * @package SimpleSAML\XMLSec\Utils
 */
class XPath
{
    const ALPHANUMERIC = '\w\d';
    const NUMERIC = '\d';
    const LETTERS = '\w';
    const EXTENDED_ALPHANUMERIC = '\w\d\s-_:\.';

    const SINGLE_QUOTE = '\'';
    const DOUBLE_QUOTE = '"';
    const ALL_QUOTES = '[\'"]';


    /**
     * Get a DOMXPath object that can be used to search for XMLDSIG elements.
     *
     * @param \DOMDocument $doc The document to associate to the DOMXPath object.
     *
     * @return \DOMXPath A DOMXPath object ready to use in the given document, with the XMLDSIG namespace already
     * registered.
     */
    public static function getXPath(\DOMDocument $doc)
    {
        $xp = new \DOMXPath($doc);
        $xp->registerNamespace('ds', C::XMLDSIGNS);
        $xp->registerNamespace('xenc', C::XMLENCNS);
        return $xp;
    }


    /**
     * Filter an attribute name for save inclusion in an XPath query.
     *
     * @param string $name The attribute name to filter.
     * @param mixed $allow The set of characters to allow. Can be one of the constants provided by this class, or a
     * custom regex excluding the '#' character (used as delimiter).
     *
     * @return string The filtered attribute name.
     */
    public static function filterAttrName($name, $allow = self::EXTENDED_ALPHANUMERIC)
    {
        return preg_replace('#[^'.$allow.']#', '', $name);
    }


    /**
     * Filter an attribute value for save inclusion in an XPath query.
     *
     * @param string $value The value to filter.
     * @param string $quotes The quotes used to delimit the value in the XPath query.
     *
     * @return string The filtered attribute value.
     */
    public static function filterAttrValue($value, $quotes = self::ALL_QUOTES)
    {
        return preg_replace('#'.$quotes.'#', '', $value);
    }


    /**
     * Search for an element with a certain name among the children of a reference element.
     *
     * @param \DOMNode $ref The DOMDocument or DOMElement where encrypted data is expected to be found as a child.
     * @param string $name The name (possibly prefixed) of the element we are looking for.
     *
     * @return \DOMElement|false The element we are looking for, or false when not found.
     *
     * @throws RuntimeException If no DOM document is available.
     */
    public static function findElement(\DOMNode $ref, $name)
    {
        $doc = $ref instanceof \DOMDocument ? $ref : $ref->ownerDocument;
        if ($doc === null) {
            throw new RuntimeException('Cannot search, no DOM document available');
        }

        $nodeset = self::getXPath($doc)->query('./'.$name, $ref);

        if ($nodeset->length === 0) {
            return false;
        }
        return $nodeset->item(0);
    }

}
