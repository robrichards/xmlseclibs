<?php

/**
 * Implements support for XML-Signature XPath $filter 2.0
 * http://www.w3.org/TR/xmldsig-filter2/
 * 
 * This implementation is modelled after the example in SBRAssurance
 * https://github.com/OpenSBR/SBRAssurance/tree/master/OpenSBR/Xades/XmlDsig/XmlDsigFilterTransform.cs
 * 
 * The 2.0 specification identifies a performance problem when the node to be signed in a large
 * document requires a complex XPath query that then must be evaluated against every node.
 * 
 * The approach supported by the specification is to take just one pass over the document node.
 * 
 * The approach does not do anything that cannot be accomplished using an XPath.
 * 
 * The examples below are taken from the specification and are functionally equivalent.
 * 
 * <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
 * 	<XPath>(ancestor-or-self::ToBeSigned and not(ancestor-or-self::NotToBeSigned)) or 
 * ancestor-or-self::ReallyToBeSigned</XPath>
 * </Transform>
 * 
 * <Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">
 * 		<XPath $filter="intersect">//xx:ToBeSigned</XPath>
 *		<XPath $filter="subtract">//NotToBeSigned</XPath>
 *		<XPath $filter="union">//ReallyToBeSigned</XPath>
 * </Transform>
 * 
 * This does NOT implement the full specification; limitations:
 * 	- no XPath 2.0 support
 */

namespace RobRichards\XMLSecLibs;

define('intersect', 'intersect');
define('subtract', 'subtract');
define('union', 'union');

/**
 * XMLDSig filter transform class
 * This does NOT implement the full specification; limitations:
 *  - no XPath 2.0 support
 */
class XmlDsigFilterTransform
{
	const algorithm = "http://www.w3.org/2002/06/xmldsig-filter2";

	/**
	 * An array of namespaces indexed by prefix
	 * @var string[] 
	 */
	private $namespaces = array();

	/**
	 * An array of filter
	 * @var XmlDsigFilterElement[] $elements
	 */
	private $elements = array();

	/**
	 * The DOMDocument instance of the document being processed
	 * @var \DOMDocument
	 */
	private $document = null;

	public function __construct( $document )
	{
		$this->document = $document;
	}

	/**
	 * Create an instance and create a single filter for the query passed in
	 * @param string $xpath
	 * @param string $filter One of intersect,subtract or union
	 * @param string[] $namespaces An optional array of namespaces needed to evaluate the query
	 * @return void
	 */
	public function fromFilterQuery( $xpath, $filter, $namespaces = null )
	{
		if ( $namespaces != null ) $this->namespaces = $namespaces;
		$this->elements[] = new XmlDsigFilterElement( $xpath, $filter, $this->namespaces );
	}

	/**
	 * Create filter instances for each pair of query and filter
	 * @param string[] $xpaths  There must be a filter for each query
	 * @param string[] $filters There must be a query for each filter.  Each filter is one of intersect,subtract or union
	 * @param string[] $namespaces An optional array of namespaces needed to evaluate the query
	 * @return void
	 */
	public function fromFilterQueries( $xpaths, $filters, $namespaces = null )
	{
		if ( $namespaces != null ) $this->namespaces = $namespaces;
		if ( count( $xpaths ) != count( $filters ) )
			throw new \Exception("Invalid transform parmeters");

		for ( $i = 0; $i < count( $xpaths ); $i++ )
			$this->elements[] = new XmlDsigFilterElement( $xpaths[ $i ], $filters[ $i ], $this->namespaces );
	}

	/**
	 * Create a set of filters based on the content of a transform node
	 * @param \DOMNode[] $nodeList
	 * @return void
	 */
	public function LoadinnerXml( $nodeList )
	{
		if ( $nodeList == null )
			throw new \Exception("Unknown transform type: there are no filters defined in the transform");

		foreach ( $nodeList as $node )
		{
			/** @var \DOMElement $node */
			if ( $node->nodeType != XML_ELEMENT_NODE ) continue;
			$this->elements[] = $filter = new XmlDsigFilterElement();
			$filter->fromXml( $node );
		}
	}

	/**
	 * Recreate the input transform nodes
	 * @return void
	 */
	public function getinnerXml()
	{
		$document = new \DOMDocument();
		foreach ( $this->elements as $element )
			$document->appendChild( $element->getinnerXml( $document ) );
		return $document->childNodes;
	}

	/**
	 * Get the nodes from the input document that correspond to the filter definitions
	 * @return void
	 */
	public function getOutput()
	{
		$currentNodeList = array();

		// From the Xades filter specification:
		// For each XPath expression X, in sequence, evaluate the expression and store the resulting node-set, S, along with the associated set operation.
		// Prepend a node-set consisting of just the document node, along with the operation union.
		// Create a new, empty filter node-set.
		// Process each node in the input node-set document, adding each node to the output node-set F if a flag Z is true. The flag is computed as follows:
		//   Z is true if and only if the node is present in any subtree-expanded union node-set and all subsequent subtree-expanded intersect node-sets but no subsequent subtree-expanded subtract node-sets, or false otherwise. If there are no subsequent intersect or subtract node-sets, then that part of the test is automatically passed.
		//   Presence in a subtree-expanded node-set can be efficiently determined without actually expanding the node-set, by simply maintaining a stack or count that identifies whether any nodes from that node-set are an ancestor of the node being processed.

		// build response
		foreach ( $this->elements as $element )
			/** @var XmlDsigFilterElement $element */
			$element->createSet( $this->document );

		// Get a list of all the document nodes
		$xpath = new \DOMXPath( $this->document );
		$nodelist = $xpath->query( "//. | //@*" );
		foreach( $nodelist as $node )
		{
			$include = true;
			// intersect: include = false if not in set, otherwise unchanged
			// subtract: include = false if in set, otherwise unchanged
			// union: include = true if in set, otherwise unchanged
			foreach ( $this->elements as $element )
				$include = $element->include( $node ) ?? $include;
			if ( $include )
				$currentNodeList[] = $node;
		}

		$namespaceNodes = $xpath->query("//namespace::*");
		foreach( $namespaceNodes as $namespaceNode )
			$currentNodeList[] = $namespaceNode;

		return $currentNodeList;
	}
}

/**
 * Private class for each element of a $filter transform (intersect, subtract, union)
 */
class XmlDsigFilterElement
{
	/**
	 * Namespaces used to interpret the XPath query
	 * @var string[]
	 */
	private $namespaces = array();

	/**
	 * Copy of the query to apply
	 * @var string
	 */
	private $xpath = '';

	/**
	 * The $filter to be applied to this instance
	 * @var string One of intersect, subtract, union
	 */
	private $filter = union;

	/**
	 * Node set produced by the query
	 * @var \DOMNode[]
	 */
	private $nodeset = array();

	/**
	 * The prefix used on the <XPath> element if there is one
	 * @var string
	 */
	private $prefix = null;

	/**
	 * @param string $xpath The query to use to create a set of nodes
	 * @param string $filter One of intersect, subtract, union
	 * @param string[] $namespaces
	 */
	public function fromParts( $xpath, $filter, $namespaces)
	{
		$this->namespaces = $namespaces;
		$this->xpath = $xpath;
		$this->filter = $filter;
	}

	/**
	 * Create $filter element from XML
	 * @param \DOMElement $xmlElement
	 */
	public function fromXml( $xmlElement )
	{
		if ( $xmlElement != null && $xmlElement->localName == "XPath" )
		{
			$this->filter = $xmlElement->getAttribute("Filter");
			if ( ! $this->filter )
				throw new \Exception("Invalid transform parameters: @Filter does not exist in <XPath>");
 
			if ( $xmlElement->namespaceURI != XMLSecurityDSig::XPATH_FILTER2 )
				throw new \Exception('The namespace URI of the <XPath> must be filter 2.0');

			$this->prefix = $xmlElement->prefix;

			$this->xpath = trim( $xmlElement->textContent );
			$xpath = new \DOMXPath( $xmlElement->ownerDocument );
			$namespaces = $xpath->query( './namespace::*', $xmlElement );
			foreach ( $namespaces as $namespace )
			{
				/** @var \DOMNameSpaceNode $namespace */
				if ( strpos($namespace->nodeName, 'xmlns:') === 0 ) // xmlns
				{
					$text = $namespace->localName;
					$uri = $namespace->nodeValue;
					if ( $uri == "http://www.w3.org/XML/1998/namespace" ) continue; // Not needed
					if ( $uri == XMLSecurityDSig::XPATH_FILTER2) continue; // Will always be added explicitly
					if ( strpos( $this->xpath, "$text:" ) === false ) continue; // Not used
					if ( $text == null)
					{
						$text = $xmlElement->prefix;
						$uri = $xmlElement->namespaceURI;
					}
					$this->namespaces[ $text] = $uri;
				}
			}
		}
		if ( $xpath == null )
			throw new \Exception("Unknown transform type: an XPath query cannot be found");
	}

	/**
	 * Create XML node for this $filter element
	 * @param \DOMDocument $doc
	 * @return \DOMElement
	 */
	public function getinnerXml( $doc)
	{
		$xmlElement = $doc->createElement( ( $this->prefix ? "{$this->prefix}:" : "" ) . "XPath", "http://www.w3.org/2002/06/xmldsig-filter2" );
		if ( $this->prefix )
			$xmlElement->setAttribute("xmlns:" . $this->prefix, XMLSecurityDSig::XPATH_FILTER2 );
		else
			$xmlElement->setAttribute("xmlns", XMLSecurityDSig::XPATH_FILTER2 );

		if ($this->namespaces != null)
		{
			foreach ( $this->namespaces as $prefix => $namespace )
				if ( $prefix != "xml" && $prefix != "xmlns" && $prefix != null && strlen( $prefix ) > 0 )
				{
					$xmlElement->setAttribute("xmlns:" . $prefix, $namespace );
				}
		}
		$xmlElement->textContent = $this->xpath;
		$xmlElement->setAttribute( "Filter", $this->filter );
		return $xmlElement;
	}

	/**
	 * Initialise subset for this $filter element
	 * @param \DOMDocument $document The input document
	 */
	public function createSet( $document )
	{
		$xpath = new \DOMXPath( $document );
		foreach( $this->namespaces as $prefix => $namespace )
		{
			$xpath->registerNamespace( $prefix, $namespace );
		}
		$nodeset = $xpath->query( $this->xpath );

		// Take this indexing hit one time so the nodeset is not iterated many, many times in isInSet
		foreach( $nodeset as $node )
		{
			/** @var \DOMNode $node */
			$this->nodeset[ $node->getNodePath() ] = $node;
		}
	}

	/**
	 * Determines whether a node is in the selection
	 * @param \DOMNode $node The node being evaluated
	 * @return bool
	 */
	private function isInSet( $node)
	{
		$uid = $node->getNodePath();
		return $this->nodeset[ $uid ] ?? false || ( $node instanceof \DOMAttr 
			? $this->isInSet( $node->ownerElement) 
			: $node->parentNode != null && $this->isInSet( $node->parentNode ) );
	}

	/**
	 * Determine whether and how a node is affected by this element
	 * @param \DOMNode $node
	 * @return bool
	 */
	public function include( $node )
	{
		$inSet = $this->isInSet( $node );
		switch ( $this->filter )
		{
			case intersect:
				if ( ! $inSet )
					return false;
				break;
			case subtract:
				if ( $inSet )
					return false;
				break;
			case union:
				if ( $inSet )
					return true;
				break;
		}
		return null;
	}
}