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
	 * Create an Xml document representing the nodeset nodes
	 * @param \DOMNode[] $nodelist
	 * @param bool $exclude
	 * @param bool $withComments
	 * @return string This is a bag of nodes generated from the nodes list
	 */
	public static function nodesetToXml( $nodeList, $exclude = false, $withComments = false )
	{
		if ( count( $nodeList ) == 0) return "";

		/**
		 * Map between the old node and the new node
		 * @param int[] $nodeMap
		 */
		$nodeMap = array();

		/**
		 * Alternate index of the node list nodes (filled lazily)
		 * @var \DOMNode[] $nodeLookup
		 */
		$nodeLookup = array();

		// Create a new target document
		$newDoc = new \DOMDocument();

		// Pre-process the node list to index and remove all the namespaces
		$namespaceNodes = array();

		// Add each node in the list to the new document assuming it has a parent
		foreach ( $nodeList as $node )
		{
			/** @var \DOMNode $node */
			if ( $node->nodeType != XML_NAMESPACE_DECL_NODE ) continue;
			if ( $node->localName == 'xml' && $node->prefix == 'xml' ) continue;

			$path = $node->parentNode ? $node->parentNode->getNodePath() : '';
			$path .= '/'; // Make sure it ends with a slash

			if ( ! isset( $namespaceNodes[ $path ] ) )
			{
				$namespaceNodes[ $path ] = array();
			}

			$namespaceNodes[ $path ][ $node->nodeName ] = $node;
		}

		foreach ( $namespaceNodes as &$nodes )
		{
			ksort( $nodes );
		}
		unset( $nodes );

		/**
		 * @param \DOMNode $parentNode
		 * @param \DOMNode $currentNode
		 * @return bool
		 */
		$processNode = function( $parentNode, $currentNode ) use( $newDoc, &$nodeMap, &$nodeLookup, &$namespaceNodes )
		{
			switch( $currentNode->nodeType )
			{
				case XML_ENTITY_NODE:
					$newNode = $newDoc->createEntityReference( $currentNode->textContent );
					break;

				case XML_ELEMENT_NODE:
					$newNode = $newDoc->createElementNS( $currentNode->namespaceURI, $currentNode->prefix ? "{$currentNode->prefix}:{$currentNode->localName}" : $currentNode->localName );
					break;

				case XML_ATTRIBUTE_NODE:
					$newNode = $newDoc->createAttribute( $currentNode->nodeName );
					$newNode->value = $currentNode->textContent;
					break;

				case XML_COMMENT_NODE:
					$newNode = $newDoc->createComment( $currentNode->textContent );
					break;

				case XML_TEXT_NODE:
					$newNode = $newDoc->createTextNode( $currentNode->textContent );
					break;

				case XML_NAMESPACE_DECL_NODE:
					// This processing is not necessary.  Namespaces are added anyway.
					// if ( $currentNode->namespaceURI == "http://www.w3.org/XML/1998/namespace" ) return;
					// $newNode = $newDoc->createAttribute( $currentNode->nodeName );
					// $newNode->value = $currentNode->nodeValue;
					// break;
					return true;

				default:
					error_log( "Support for node type '{$currentNode->nodeType}' needs to be added" );
					return false;
			}

			// if ( $currentNode->nodeType != XML_ELEMENT_NODE )
			// {
			//	$newNode->innerText = $currentNode->innerText;
			// }
			$x = $parentNode->appendChild( $newNode );

			if ( $currentNode->nodeType != XML_NAMESPACE_DECL_NODE )
			{
				// Update the dictionaries
				$nodeLookup[ $newNode->getNodePath() ] = $newNode;
				$nodeMap[ $currentNode->getNodePath() ] = $newNode->getNodePath();
			}

			// If the parent node has no parent node (its a root node) copy any namespace nodes
			if ( $currentNode->nodeType != XML_ELEMENT_NODE ) return true;

			// Are there namespaces for the current node?
			$path = $currentNode->getNodePath() . '/';
			if ( ! ( $namespaceNodes[ $path ] ?? false ) || ! count( $namespaceNodes[ $path ] ) ) return true;

			$newNode->removeAttributeNS( $newNode->namespaceURI, $newNode->localName );

			foreach( $namespaceNodes[ $path ] as $namespaceNode )
			{
				/** @var \DOMNameSpaceNode $namespaceNode */
				if ( $namespaceNode->localName == $newNode->prefix ) continue;

				$newAttr = $newDoc->createAttribute( $namespaceNode->nodeName );
				$newAttr->value = $namespaceNode->namespaceURI;
				$newNode->appendChild( $newAttr );
			}

			// Remove all namespace nodes that begin with the same path
			// The nodes to delete
			$nodesToDelete = $namespaceNodes[ $path ];
			foreach( $namespaceNodes as $reviewPath => &$nodesToReview )
			{
				$nodesToReview = array_diff_key( $nodesToReview, $nodesToDelete );
			}
			unset( $nodesToReview );
			$namespaceNodes = array_filter( $namespaceNodes, function( $nodes ) { return $nodes; } );

			return true;
		};

		foreach ( $nodeList as $currentNode )
		{
			/** @var \DOMNode $currentNode */
			if ( $currentNode->nodeType == XML_DOCUMENT_NODE )
			{
				continue;
			}

			// Have to work on a copy as the iterator cannot be modified
			$node = $currentNode;

			// Look to see if an ancestor has already been added to the new document
			while (true)
			{
				$nodeId = $node->parentNode->getNodePath();
				if ( $nodeMap[ $nodeId ] ?? false )
				{
					// Add the node to the new document
					$parentHash = $nodeMap[ $nodeId ];
					if ( $nodeLookup[ $parentHash ] ?? false )
					{
						$parentNode = $nodeLookup[ $parentHash ];
						$processNode( $parentNode, $currentNode);
						// Next node
						break;
					}
				}
				else if ( $node->parentNode->nodeType == XML_DOCUMENT_NODE )
				{
                    // Create new root nodes
					$processNode( $newDoc, $currentNode );
					break;
				}

				// Try the next parent (in case an interim node has been subtracted)
				$node = $node->parentNode;
				if ( $node == null ) break;
			}
		}

		// This is a long way round to get from a new document to satifactory xml.
		// This is because namespaces added to nodes in the new document don't seem  
		// to be recognized so are added to each sub-node.  The solution is to write 
		// the XML to a string then load it into a document which can then be canonicalized
		$output = $newDoc->saveXML( $newDoc->documentElement, LIBXML_NOEMPTYTAG );

		// Create a new target document
		$newDoc = new \DOMDocument();
		$newDoc->loadXML( $output );

		$xml = $newDoc->C14N( $exclude, $withComments );

		return $xml;
	}
}
