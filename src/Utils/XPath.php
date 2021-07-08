<?php

namespace RobRichards\XMLSecLibs\Utils;

use DOMNameSpaceNode;

class XPath
{
    const ALPHANUMERIC = '\w\d';
    const NUMERIC = '\d';
    const LETTERS = '\w';
    const EXTENDED_ALPHANUMERIC = '\w\d\s\-_:\.';

    const SINGLE_QUOTE = '\'';
    const DOUBLE_QUOTE = '"';
    const ALL_QUOTES = '[\'"]';

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
	 * Utility function to output a summary the items in a node list
	 * @param \DOMNode[] $nodelist
	 * @return void
	 */
	public static function dumpNodelist( $nodelist )
	{
		$elementTypes = array(
			XML_ELEMENT_NODE => "XML_ELEMENT_NODE",
			XML_ATTRIBUTE_NODE => "XML_ATTRIBUTE_NODE",
			XML_TEXT_NODE => "XML_TEXT_NODE",
			XML_CDATA_SECTION_NODE => "XML_CDATA_SECTION_NODE",
			XML_ENTITY_REF_NODE => "XML_ENTITY_REF_NODE",
			XML_ENTITY_NODE => "XML_ENTITY_NODE",
			XML_PI_NODE => "XML_PI_NODE",
			XML_COMMENT_NODE => "XML_COMMENT_NODE",
			XML_DOCUMENT_NODE => "XML_DOCUMENT_NODE",
			XML_DOCUMENT_TYPE_NODE => "XML_DOCUMENT_TYPE_NODE",
			XML_DOCUMENT_FRAG_NODE => "XML_DOCUMENT_FRAG_NODE",
			XML_NOTATION_NODE => "XML_NOTATION_NODE",
			XML_HTML_DOCUMENT_NODE => "XML_HTML_DOCUMENT_NODE",
			XML_DTD_NODE => "XML_DTD_NODE",
			XML_ELEMENT_DECL_NODE => "XML_ELEMENT_DECL_NODE",
			XML_ATTRIBUTE_DECL_NODE => "XML_ATTRIBUTE_DECL_NODE",
			XML_ENTITY_DECL_NODE => "XML_ENTITY_DECL_NODE",
			XML_NAMESPACE_DECL_NODE => "XML_NAMESPACE_DECL_NODE",
			XML_ATTRIBUTE_CDATA => "XML_ATTRIBUTE_CDATA",
			XML_ATTRIBUTE_ID => "XML_ATTRIBUTE_ID",
			XML_ATTRIBUTE_IDREF => "XML_ATTRIBUTE_IDREF",
			XML_ATTRIBUTE_IDREFS => "XML_ATTRIBUTE_IDREFS",
			XML_ATTRIBUTE_ENTITY => "XML_ATTRIBUTE_ENTITY",
			XML_ATTRIBUTE_NMTOKEN => "XML_ATTRIBUTE_NMTOKEN",
			XML_ATTRIBUTE_NMTOKENS => "XML_ATTRIBUTE_NMTOKENS",
			XML_ATTRIBUTE_ENUMERATION => "XML_ATTRIBUTE_ENUMERATION",
			XML_ATTRIBUTE_NOTATION => "XML_ATTRIBUTE_NOTATION"
		);
		
		$nodesOutput = "";
		foreach( $nodelist as $node )
		{
			$nodesOutput .= $elementTypes[ $node->nodeType ] . "\t\t";
			$nodesOutput .= $node->nodeName . "\t\t";
			$nodesOutput .= $node->parentNode ? $node->parentNode->getNodePath() : "root";
			$nodesOutput .= "\n";
		}
		file_put_contents( __DIR__ . "/../../../nodesOutput.txt", $nodesOutput );
	}

}
