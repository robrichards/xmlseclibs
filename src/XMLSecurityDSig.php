<?php
namespace RobRichards\XMLSecLibs;

use \DOMDocument;
use \DOMElement;
use \DOMNode;
use \DOMXPath;
use \Exception;
use RobRichards\XMLSecLibs\Utils\XPath as UtilsXPath;

/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2020, Robert Richards <rrichards@cdatazone.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author    Robert Richards <rrichards@cdatazone.org>
 * @copyright 2007-2020 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

class XMLSecurityDSig
{
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';
    const XMLDSIGNS11 = 'http://www.w3.org/2000/09/xmldsig11#';
    const XMLDSIGNS2 = 'http://www.w3.org/2000/09/xmldsig2#';
    const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
    const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
    const ENV_SIG = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
    const XPATH_FILTER2 = 'http://www.w3.org/2002/06/xmldsig-filter2';
    const CXPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';
    const BASE64 = 'http://www.w3.org/2000/09/xmldsig#base64';
    const XSLT = 'http://www.w3.org/TR/1999/REC-xslt-19991116';

    const template = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:SignatureMethod />
  </ds:SignedInfo>
</ds:Signature>';

    const BASE_TEMPLATE = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <SignatureMethod />
  </SignedInfo>
</Signature>';

    /** @var DOMElement */
    public $sigNode = null;

    /** @var array */
    public $idKeys = array();

    /** @var array */
    public $idNS = array();

    /** @var string */
    private $signedInfo = null;

    /** @var DomXPath */
    private $xPathCtx = null;

    /** @var string|null */
    private $canonicalMethod = null;

    /** @var string */
    private $prefix = '';

    /** @var string */
    const searchpfx = 'secdsig';

    /**
     * This variable contains an associative array of validated nodes.
     * @var array
     */
    private $validatedNodes = null;

    /**
     * @param string $prefix
     * @param string $id (optional) If supplied it will become the Id attribute of the <Signature>
     */
    public function __construct( $prefix='ds', $id = null )
    {
        $template = self::BASE_TEMPLATE;

        // Replace the prefix if one is provided
        if ( ! empty( $prefix ) )
        {
            $this->prefix = $prefix.':';
            $search = array( "<S", "</S", "xmlns=" );
            $replace = array( "<$prefix:S", "</$prefix:S", "xmlns:$prefix=" );
            $template = str_replace( $search, $replace, $template );
        }

        // Add the signature fragment
        $sigdoc = new DOMDocument();
        $sigdoc->loadXML( $template );
        $this->sigNode = $sigdoc->documentElement;

        // Add an Id if the param is valid
        if ( ! $id ) return;
        $this->sigNode->setAttribute( 'Id', $id );
    }

    /**
     * Reset the XPathObj to null
     */
    private function resetXPathObj()
    {
        $this->xPathCtx = null;
    }

    /**
     * Returns the XPathObj or null if xPathCtx is set and sigNode is empty.
     *
     * @return DOMXPath|null
     */
    private function getXPathObj()
    {
        if ( empty( $this->xPathCtx ) && ! empty( $this->sigNode ) )
        {
            $xpath = new DOMXPath( $this->sigNode->ownerDocument );
            $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS );
            $this->xPathCtx = $xpath;
        }
        return $this->xPathCtx;
    }

    /**
     * Generate guid
     *
     * @param string $prefix Prefix to use for guid. defaults to pfx
     *
     * @return string The generated guid
     */
    public static function generateGUID($prefix='pfx')
    {
        $uuid = md5(uniqid(mt_rand(), true));
        $guid = $prefix.substr($uuid, 0, 8)."-".
                substr($uuid, 8, 4)."-".
                substr($uuid, 12, 4)."-".
                substr($uuid, 16, 4)."-".
                substr($uuid, 20, 12);
        return $guid;
    }

    /**
     * Generate guid
     *
     * @param string $prefix Prefix to use for guid. defaults to pfx
     *
     * @return string The generated guid
     *
     * @deprecated Method deprecated in Release 1.4.1
     */
    public static function generate_GUID($prefix='pfx')
    {
        return self::generateGUID($prefix);
    }

    /**
     * Returns the <Signature> node 
     * @param DOMDocument $objDoc
     * @param int $pos
     * @return DOMNode|null
     */
    public function locateSignature( $objDoc, $pos = 0 )
    {
        $doc = $objDoc instanceof DOMDocument ? $objDoc : $objDoc->ownerDocument;

        if ( $doc )
        {
            // Get the signature node and store it
            $xpath = new DOMXPath( $doc );
            $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS );
            $query = ".//". self::searchpfx . ":Signature";
            $nodeset = $xpath->query( $query, $objDoc );
            $this->sigNode = $nodeset->item( $pos );

            // Check the number of SignedInfo nodes is valid
            $query = "./". self::searchpfx . ":SignedInfo";
            $nodeset = $xpath->query( $query, $this->sigNode );
            if ( $nodeset->length > 1 )
            {
                throw new \Exception("Invalid structure - Too many SignedInfo elements found");
            }
            return $this->sigNode;
        }
        return null;
    }

    /**
     * @param string $name
     * @param null|string $value
     * @return DOMElement
     */
    public function createNewSignNode( $name, $value = null )
    {
        $doc = $this->sigNode->ownerDocument;
        if ( is_null( $value ) )
        {
            $node = $doc->createElementNS( self::XMLDSIGNS, $this->prefix.$name );
        }
        else
        {
            $node = $doc->createElementNS( self::XMLDSIGNS, $this->prefix.$name, $value );
        }
        return $node;
    }

    /**
     * @param string $method
     * @throws \Exception
     */
    public function setCanonicalMethod($method)
    {
        switch ( $method )
        {
            case self::C14N:
            case self::C14N_COMMENTS:
            case self::EXC_C14N:
            case self::EXC_C14N_COMMENTS:
                $this->canonicalMethod = $method;
                break;
            default:
                throw new \Exception('Invalid Canonical Method');
        }

        if ( $xpath = $this->getXPathObj() )
        {
            // Get the Signedinfo node if it exists
            $query = "./". self::searchpfx . ":SignedInfo";
            $nodeset = $xpath->query( $query, $this->sigNode );
            if ( $sinfo = $nodeset->item(0) )
            {
                $query = "./". self::searchpfx . ":CanonicalizationMethod";
                $nodeset = $xpath->query($query, $sinfo);
                /** @var \DOMElement $canonNode */
                if ( ! ( $canonNode = $nodeset->item(0) ) )
                {
                    $canonNode = $this->createNewSignNode('CanonicalizationMethod');
                    $sinfo->insertBefore( $canonNode, $sinfo->firstChild );
                }
                $canonNode->setAttribute('Algorithm', $this->canonicalMethod);
            }
        }
    }

    /**
     * @param DOMNode $node
     * @param string $canonicalmethod
     * @param null|array $arXPath
     * @param null|array $prefixList
     * @return string
     */
    private function canonicalizeData( $node, $canonicalmethod, $arXPath=null, $prefixList=null )
    {
        $exclusive = false;
        $withComments = false;
        switch ($canonicalmethod) {
            case self::C14N:
                $exclusive = false;
                $withComments = false;
                break;
            case self::C14N_COMMENTS:
                $withComments = true;
                break;
            case self::EXC_C14N:
                $exclusive = true;
                break;
            case self::EXC_C14N_COMMENTS:
                $exclusive = true;
                $withComments = true;
                break;
        }

        if ( is_null( $arXPath ) && ( $node instanceof DOMNode ) && ( $node->ownerDocument !== null ) && $node->isSameNode( $node->ownerDocument->documentElement ) ) 
        {
            /* Check for any PI or comments as they would have been excluded */
            $element = $node;
            while ($refnode = $element->previousSibling)
            {
                if ( $refnode->nodeType == XML_PI_NODE || ( ( $refnode->nodeType == XML_COMMENT_NODE ) && $withComments ) )
                {
                    break;
                }
                $element = $refnode;
            }
            if ($refnode == null)
            {
                $node = $node->ownerDocument;
            }
        }

        return $node->C14N( $exclusive, $withComments, $arXPath, $prefixList );
    }

    /**
     * @return null|string
     */
    public function canonicalizeSignedInfo()
    {
        $doc = $this->sigNode->ownerDocument;
        $canonicalmethod = null;
        if ( $doc )
        {
            $xpath = $this->getXPathObj();
            $query = "./". self::searchpfx . ":SignedInfo";
            $nodeset = $xpath->query( $query, $this->sigNode );
            if ( $nodeset->length > 1 )
            {
                throw new \Exception("Invalid structure - Too many SignedInfo elements found");
            }

            if ( $signInfoNode = $nodeset->item(0) )
            {
                $query = "./". self::searchpfx . ":CanonicalizationMethod";
                $nodeset = $xpath->query( $query, $signInfoNode );
                $prefixList = null;
                if ( $canonNode = $nodeset->item(0) ) 
                {
                    /** @var \DOMElement $canonNode */
                    $canonicalmethod = $canonNode->getAttribute('Algorithm');
                    foreach ( $canonNode->childNodes as $node )
                    {
                        if ( $node->localName == 'InclusiveNamespaces' )
                        {
                            if ($pfx = $node->getAttribute('PrefixList'))
                            {
                                $arpfx = array_filter( explode(' ', $pfx ) );
                                if (count($arpfx) > 0)
                                {
                                    $prefixList = array_merge( $prefixList ? $prefixList : array(), $arpfx );
                                }
                            }
                        }
                    }
                }

                $this->signedInfo = $this->canonicalizeData( $signInfoNode, $canonicalmethod, null, $prefixList );
                return $this->signedInfo;
            }
        }
        return null;
    }

    /**
     * @param string $digestAlgorithm
     * @param string $data
     * @param bool $encode
     * @return string
     * @throws \Exception
     */
    public function calculateDigest($digestAlgorithm, $data, $encode = true)
    {
        switch ($digestAlgorithm)
        {
            case self::SHA1:
                $alg = 'sha1';
                break;
            case self::SHA256:
                $alg = 'sha256';
                break;
            case self::SHA384:
                $alg = 'sha384';
                break;
            case self::SHA512:
                $alg = 'sha512';
                break;
            case self::RIPEMD160:
                $alg = 'ripemd160';
                break;
            default:
                throw new \Exception("Cannot validate digest: Unsupported Algorithm <$digestAlgorithm>");
        }

        $digest = hash( $alg, $data, true );
        if ( $encode ) 
        {
            $digest = base64_encode( $digest );
        }
        return $digest;

    }

    /**
     * @param $refNode
     * @param string $data
     * @return bool
     */
    public function validateDigest($refNode, $data)
    {
        // Retrieve the algorithm
        $xpath = new DOMXPath( $refNode->ownerDocument );
        $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS );
        $query = "string(./". self::searchpfx . ":DigestMethod/@Algorithm)";
        $digestAlgorithm = $xpath->evaluate($query, $refNode);

        // Compute the digest
        $digValue = $this->calculateDigest( $digestAlgorithm, $data, false );

        // Get the recorded digest
        $query = "string(./". self::searchpfx . ":DigestValue)";
        $digestValue = $xpath->evaluate( $query, $refNode );

        return ($digValue === base64_decode( $digestValue ) );
    }

    /**
     * This function should process each transform independently, the output node-set of one being the input to the next
     * @param $refNode The reference node
     * @param DOMNode $objData The data to be transformed
     * @param bool $includeCommentNodes Allow the use of comments to be overridded for example if the reference uri is null or empty
     * @return string
     */
    public function processTransforms( $refNode, $objData, $includeCommentNodes = true )
    {
        $xpath = new DOMXPath( $refNode->ownerDocument );
        $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS );
        $query = "./". self::searchpfx . ":Transforms/". self::searchpfx . ":Transform";
        $transforms = $xpath->query( $query, $refNode );

        foreach ( $transforms AS $transform )
        {
            /** @var \DOMElement $transform */

            $arXPath = null;
            $prefixList = null;
            $canonicalMethod = self::C14N;
            
            if ( is_string( $objData ) )
            {
                $doc = new \DOMDocument();
                $doc->loadXML( $objData );
                $objData = $doc;
                unset( $doc );
            }

            $algorithm = $transform->getAttribute("Algorithm");

            switch ($algorithm)
            {
                case self::EXC_C14N:
                case self::EXC_C14N_COMMENTS:

                    // We remove comment nodes by forcing it to use a canonicalization without comments
                    $canonicalMethod = $includeCommentNodes ? $algorithm : self::EXC_C14N;

                    $node = $transform->firstChild;
                    while ( $node ) 
                    {
                        if ( $node->localName == 'InclusiveNamespaces')
                        {
                            if ( $pfx = $node->getAttribute('PrefixList') ) 
                            {
                                $arpfx = array();
                                $pfxlist = explode( " ", $pfx );
                                foreach ( $pfxlist AS $pfx ) 
                                {
                                    $val = trim( $pfx );
                                    if ( ! empty( $val  )) 
                                    {
                                        $arpfx[] = $val;
                                    }
                                }
                                if ( count($arpfx) > 0)
                                {
                                    $prefixList = $arpfx;
                                }
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }
                    break;

                case self::C14N:
                case self::C14N_COMMENTS:

                    // We remove comment nodes by forcing it to use a canonicalization without comments
                    $canonicalMethod = $includeCommentNodes ? $algorithm : self::C14N;
                    break;

                case self::CXPATH:

                    $node = $transform->firstChild;
                    while ( $node )
                    {
                        if ($node->localName == 'XPath') 
                        {
                            $arXPath['query'] = '(.//. | .//@* | .//namespace::*)[' . $node->nodeValue . ']';
                            $arXPath['namespaces'] = array();
                            $nslist = $xpath->query('./namespace::*', $node);
                            foreach ($nslist AS $nsnode)
                            {
                                if ($nsnode->localName == "xml") continue;
                                $arXPath['namespaces'][$nsnode->localName] = $nsnode->nodeValue;
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }

                    break ;

                case self::XPATH_FILTER2:
                    
                    $filter = new XmlDsigFilterTransform( $objData );
                    $filter->LoadinnerXml( $transform->childNodes );
                    // The nodes list is the result of the filter
                    $nodeList = $filter->getOutput();
                    // Create an XML document as a string from the node list
                    $objData = UtilsXPath::nodesetToXml( $nodeList, false, $includeCommentNodes );
                    continue 2;

                case self::ENV_SIG:

                    $canonicalMethod = $includeCommentNodes ? self::C14N_COMMENTS : self::C14N;

                    $arXPath['namespaces'] = array( 'ds' => self::XMLDSIGNS );
                    $arXPath['query'] = '(.//. | .//@* | .//namespace::*)[not(ancestor-or-self::ds:Signature)]';

                    break;

                case self::BASE64:
                    throw new \Exception('BASE64 Transform is not supported');

                case self::XSLT:
                    throw new \Exception('XSLT Transform is not supported');
            }

            $objData = $this->canonicalizeData( $objData, $canonicalMethod, $arXPath, $prefixList );    
        }

        return $objData;
    }

    /**
     * Each reference is a collection of <Transforms> and has an optional @URI and @Type
     * The idea is start using the document node-set (or $dataObject if one is passed)
     * then process the URI if provided then the <Transforms>
     * @param \DOMElement $refNode The <SignedInfo/reference> element being processed
     * @param \DOMDocument $dataObject Optionally a data object (the XML being validated) can be passed in.  Might be a separate file.
     * @return bool
     */
    public function processRefNode( $refNode, $dataObject = null )
    {
        /*
         * Depending on the URI, we may not want to include comments in the result
         * See: http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
         */
        $includeCommentNodes = true;

        // If there is a URI it will define the set of nodes to include.  If the URI exists but is empty, comments will be excluded
        if ( $refNode->hasAttribute("URI") ) 
        {
            $uri = $refNode->getAttribute("URI");
            $arUrl = parse_url( $uri );
            if ( empty( $arUrl ['path'] ) ) 
            {
                /* 
                 * This reference identifies a node with the given id by using a URI of the
                 * form "#identifier" (or an empty URI). This should not include comments.
                 * 
                 * TODO: Handler XPointer references in the URI.  An XPointer rmight be used 
                 *       if the user wants to retain comments when selecting a node identified by ID
                 */
                $includeCommentNodes = false;

                if ( $identifier = $arUrl['fragment'] ?? '' ) 
                {
                    $xPath = new DOMXPath( $refNode->ownerDocument );
                    if ( $this->idNS && is_array( $this->idNS ) )
                    {
                        foreach ($this->idNS as $nspf => $ns)
                        {
                            $xPath->registerNamespace($nspf, $ns);
                        }
                    }

                    $iDlist = '@Id="' . UtilsXPath::filterAttrValue($identifier, UtilsXPath::DOUBLE_QUOTE) . '"';
                    if ( is_array( $this->idKeys ) )
                    {
                        foreach ( $this->idKeys as $idKey )
                        {
                            $iDlist .= " or @" . UtilsXPath::filterAttrName($idKey) . '="' .
                            UtilsXPath::filterAttrValue( $identifier, UtilsXPath::DOUBLE_QUOTE) . '"';
                        }
                    }

                    $query = '//*['.$iDlist.']';
                    $dataObject = $xPath->query( $query )->item(0);
                } else
                {
                    $dataObject = $refNode->ownerDocument->documentElement;
                }
            }

            // Create a new document containing the filtered nodes
            // When $dataObject is not the document element would prefer to just save as XML
            // but the save process screws around with namespaces causing a problem.  So if
            // the object refers to a sub-node the XML is produced using C14N.  The reason
            // being cautious about use C14N is that its performance is really terrible when
            // the document has many nodes.
            $xml = $dataObject->isSameNode( $dataObject->ownerDocument->documentElement )
                ? $dataObject->ownerDocument->saveXML( $dataObject )
                : $dataObject->C14N( true, $includeCommentNodes );
            $dataObject = new \DOMDocument();
            $dataObject->loadXML( $xml );

        }
        else if ( ! $dataObject ) 
        {
            /* 
             * This reference identifies the root node without a URI. This may include comments.
             */

            // Create a new document
            $xml = $refNode->ownerDocument->saveXML();
            $dataObject = new \DOMDocument();
            $dataObject->loadXML( $xml );
        }

        // If $dataObject is an element convert it to the document
        if ( ! $dataObject instanceof \DOMDocument )
            $dataObject = $dataObject->ownerDocument;

        $data = $this->processTransforms( $refNode, $dataObject, $includeCommentNodes );
        if ( ! $this->validateDigest( $refNode, $data ) )
        {
            return false;
        }

        if ($dataObject instanceof DOMNode)
        {
            /* Add this node to the list of validated nodes. */
            if ( ! empty( $identifier ) )
            {
                $this->validatedNodes[$identifier] = $dataObject;
            }
            else
            {
                $this->validatedNodes[] = $dataObject;
            }
        }

        return true;
    }

    /**
     * @param \DOMElement $refNode
     * @return null
     */
    public function getRefNodeID($refNode)
    {
        if ( $uri = $refNode->getAttribute("URI") )
        {
            $arUrl = parse_url($uri);
            if ( empty( $arUrl['path'] ) )
            {
                if ( $identifier = $arUrl['fragment'] )
                {
                    return $identifier;
                }
            }
        }
        return null;
    }

    /**
     * @return array
     * @throws \Exception
     */
    public function getRefIDs()
    {
        $refids = array();

        $xpath = $this->getXPathObj();
        $query = "./". self::searchpfx . ":SignedInfo[1]/". self::searchpfx . ":Reference";
        $nodeset = $xpath->query( $query, $this->sigNode );
        if ( $nodeset->length == 0 )
        {
            throw new \Exception("Reference nodes not found");
        }
        foreach ( $nodeset AS $refNode )
        {
            $refids[] = $this->getRefNodeID( $refNode );
        }
        return $refids;
    }

    /**
     * @return bool
     * @param \DOMNode $xmlNode This will be supplied if the signature is in a separate file which will be in 
     * @throws \Exception
     */
    public function validateReference( $xmlNode = null )
    {
        $docElem = $this->sigNode->ownerDocument->documentElement;
        if ( ! $docElem->isSameNode( $this->sigNode ) )
        {
            if ( $this->sigNode->parentNode != null )
            {
                // $this->sigNode->parentNode->removeChild($this->sigNode);
            }
        }

        $xpath = $this->getXPathObj();
        $query = "./" . self::searchpfx . ":SignedInfo[1]/". self::searchpfx . ":Reference";
        $nodeset = $xpath->query( $query, $this->sigNode );
        if ( $nodeset->length == 0 )
        {
            throw new \Exception("Reference nodes not found");
        }

        /* Initialize/reset the list of validated nodes. */
        $this->validatedNodes = array();

        foreach ( $nodeset AS $refNode ) 
        {
            if (! $this->processRefNode( $refNode, $xmlNode ) )
            {
                /* Clear the list of validated nodes. */
                $this->validatedNodes = null;
                throw new \Exception("Reference validation failed: this means the data has been changed");
            }
        }
        return true;
    }

    /**
     * @param DOMNode $sinfoNode
     * @param DOMDocument $node
     * @param string $algorithm
     * @param null|array $arTransforms
     * @param null|array $options
     */
    private function addRefInternal($sinfoNode, $node, $algorithm, $arTransforms=null, $options=null)
    {
        $prefix = null;
        $prefix_ns = null;
        $id_name = 'Id';
        $overwrite_id  = true;
        $force_uri = false;

        if ( is_array( $options ) )
        {
            $prefix = empty($options['prefix']) ? null : $options['prefix'];
            $prefix_ns = empty($options['prefix_ns']) ? null : $options['prefix_ns'];
            $id_name = empty($options['id_name']) ? 'Id' : $options['id_name'];
            $overwrite_id = !isset($options['overwrite']) ? true : (bool) $options['overwrite'];
            $force_uri = !isset($options['force_uri']) ? false : (bool) $options['force_uri'];
        }

        $attname = $id_name;
        if ( ! empty( $prefix ) )
        {
            $attname = $prefix.':'.$attname;
        }

        $refNode = $this->createNewSignNode('Reference');
        $sinfoNode->appendChild( $refNode );

        if (! $node instanceof DOMDocument)
        {
            $uri = null;
            if ( ! $overwrite_id )
            {
                $uri = $prefix_ns ? $node->getAttributeNS( $prefix_ns, $id_name ) : $node->getAttribute( $id_name );
            }

            if ( empty( $uri ) )
            {
                $uri = self::generateGUID();
                $node->setAttributeNS( $prefix_ns, $attname, $uri );
            }
            $refNode->setAttribute( "URI", '#'.$uri );
        }
        elseif ( $force_uri )
        {
            $refNode->setAttribute( "URI", '' );
        }

        $transNodes = $this->createNewSignNode('Transforms');
        $refNode->appendChild( $transNodes );

        if ( is_array( $arTransforms ) )
        {
            foreach ($arTransforms AS $transform)
            {
                $transNode = $this->createNewSignNode('Transform');
                $transNodes->appendChild( $transNode );
                if ( is_array( $transform ) &&
                    ( ! empty( $transform[self::CXPATH] ) ) &&
                    ( ! empty( $transform[self::CXPATH]['query'] ) ) )
                    {
                        $transNode->setAttribute('Algorithm', self::CXPATH);
                        $XPathNode = $this->createNewSignNode('XPath', $transform[self::CXPATH]['query']);
                        $transNode->appendChild($XPathNode);
                        if ( ! empty( $transform[self::CXPATH]['namespaces'] ) )
                        {
                            foreach ($transform[self::CXPATH]['namespaces'] AS $prefix => $namespace)
                            {
                                $XPathNode->setAttributeNS( "http://www.w3.org/2000/xmlns/", "xmlns:$prefix", $namespace );
                            }
                        }
                }
                else
                {
                    $transNode->setAttribute('Algorithm', $transform);
                }
            }
        }
        elseif ( ! empty( $this->canonicalMethod ) )
        {
            $transNode = $this->createNewSignNode('Transform');
            $transNodes->appendChild( $transNode );
            $transNode->setAttribute( 'Algorithm', $this->canonicalMethod );
        }

        $canonicalData = $this->processTransforms( $refNode, $node, ! $force_uri );
        $digValue = $this->calculateDigest( $algorithm, $canonicalData );

        $digestMethod = $this->createNewSignNode('DigestMethod');
        $refNode->appendChild( $digestMethod );
        $digestMethod->setAttribute( 'Algorithm', $algorithm );

        $digestValue = $this->createNewSignNode( 'DigestValue', $digValue );
        $refNode->appendChild( $digestValue );
    }

    /**
     * @param DOMDocument $node
     * @param string $algorithm
     * @param null|array $arTransforms
     * @param null|array $options
     */
    public function addReference( $node, $algorithm, $arTransforms=null, $options=null )
    {
        if ( $xpath = $this->getXPathObj() )
        {
            $query = "./". self::searchpfx . ":SignedInfo";
            $nodeset = $xpath->query( $query, $this->sigNode );
            if ( $sInfo = $nodeset->item(0) )
            {
                $this->addRefInternal( $sInfo, $node, $algorithm, $arTransforms, $options );
            }
        }
    }

    /**
     * @param array $arNodes
     * @param string $algorithm
     * @param null|array $arTransforms
     * @param null|array $options
     */
    public function addReferenceList( $arNodes, $algorithm, $arTransforms=null, $options=null )
    {
        if ( $xpath = $this->getXPathObj() )
        {
            $query = "./". self::searchpfx . ":SignedInfo";
            $nodeset = $xpath->query( $query, $this->sigNode );
            if ( $sInfo = $nodeset->item(0) )
            {
                foreach ( $arNodes AS $node )
                {
                    $this->addRefInternal( $sInfo, $node, $algorithm, $arTransforms, $options );
                }
            }
        }
    }

    /**
     * @param DOMElement|string $data
     * @param null|string $mimetype
     * @param null|string $encoding
     * @return DOMElement
     */
    public function addObject( $data, $mimetype=null, $encoding=null )
    {
        $objNode = $this->createNewSignNode('Object');
        $this->sigNode->appendChild( $objNode );
        if ( ! empty( $mimetype ) )
        {
            $objNode->setAttribute( 'MimeType', $mimetype );
        }
        if ( ! empty( $encoding ) )
        {
            $objNode->setAttribute( 'Encoding', $encoding );
        }

        if ($data instanceof DOMElement)
        {
            $newData = $this->sigNode->ownerDocument->importNode( $data, true );
        }
        else
        {
            $newData = $this->sigNode->ownerDocument->createTextNode( $data );
        }
        $objNode->appendChild($newData);

        return $objNode;
    }

    /**
     * Adds a timestamp of te form defined for xsd:dateTimeStamp (eg. 2021-05-12T12:35:00Z).
     * The timestamp is added as a <SignatureProperty>.
     * 
     * The class does not explicity support <SignatureProperty> but does support <Object> so
     * the necessary elements for a <SignatureProperty> are created and passed into an <Object>
     * 
     * @param string $timestamp xsd:dateTimeStamp (eg. 2021-05-12T12:35:00Z).
     * @param string $signatureId The id of <Signature> and isused as the property @Target
     * @param string $propertyId An id to use to identify the property.  The name is opaque and no meaning can be inferred.
     * @return void
     */
    public function addTimestamp( $timestamp, $signatureId, $propertyId = 'timestamp' )
    {
        $propertiesXml = "<SignatureProperties xmlns=\"". self::XMLDSIGNS . "\">" .
            "<SignatureProperty Id=\"$propertyId\" Target=\"#$signatureId\">" .
            "     <xs:timestamp xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">$timestamp</xs:timestamp> " .
            "  </SignatureProperty>" .
            "</SignatureProperties>";

        // Replace the prefix if one is provided
        if ( ! empty( $this->prefix ) )
        {
            $prefix = rtrim( $this->prefix, ':' );
            $search = array( "<S", "</S", "xmlns=" );
            $replace = array( "<{$prefix}:S", "</{$prefix}:S", "xmlns:{$prefix}=" );
            $propertiesXml = str_replace( $search, $replace, $propertiesXml );
        }

        $propertiesDom = new \DOMDocument();
        $propertiesDom->loadXML( $propertiesXml );
        $object = $this->addObject( $propertiesDom->documentElement );
        unset( $propertiesDom );

        $xpath = $this->getXPathObj();
        $xpath->registerNamespace( 'ds', self::XMLDSIGNS );
        $nodes = $xpath->query("./ds:SignatureProperties/ds:SignatureProperty[\"@Id=$propertyId\"]", $object );
        if ( $nodes->length == 1 )
        {
            $this->addReference(
                $nodes[0],
                XMLSecurityDSig::SHA256, 
                array( self::EXC_C14N ),
                array( 'overwrite' => false )
            );

            return $nodes[0];
        }
    
        return $object;
    }

    /**
     * Return the security key for the SignatureMethod/@Algorithm
     * @param DOMNode $node
     * @return XMLSecurityKey
     */
    public function locateKey( $node = null )
    {
        if ( empty( $node ) )
        {
            $node = $this->sigNode;
        }

        if ( ! $node instanceof DOMNode )
        {
            return null;
        }

        if ( $doc = $node->ownerDocument )
        {
            $xpath = new DOMXPath( $doc );
            $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS );
            $query = "string(./". self::searchpfx . ":SignedInfo/". self::searchpfx . ":SignatureMethod/@Algorithm)";
            $algorithm = $xpath->evaluate( $query, $node );
            if ( $algorithm )
            {
                try
                {
                    $securityKey = new XMLSecurityKey( $algorithm, array( 'type' => 'public' ) );
                } catch ( \Exception $e )
                {
                    return null;
                }
                return $securityKey;
            }
        }
        return null;
    }

    /**
     * Returns:
     *  Bool when verifying HMAC_SHA1;
     *  Int otherwise, with following meanings:
     *    1 on succesful signature verification,
     *    0 when signature verification failed,
     *   -1 if an error occurred during processing.
     *
     * NOTE: be very careful when checking the int return value, because in
     * PHP, -1 will be cast to True when in boolean context. Always check the
     * return value in a strictly typed way, e.g. "$obj->verify(...) === 1".
     *
     * @param XMLSecurityKey $securityKey
     * @return bool|int
     * @throws \Exception
     */
    public function verify( $securityKey )
    {
        $doc = $this->sigNode->ownerDocument;
        $xpath = new DOMXPath( $doc );
        $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS );
        $query = "string(./". self::searchpfx . ":SignatureValue)";
        $sigValue = $xpath->evaluate( $query, $this->sigNode );
        if ( empty( $sigValue ) )
        {
            throw new \Exception("Unable to locate SignatureValue");
        }
        return $securityKey->verifySignature( $this->signedInfo, base64_decode( $sigValue ) );
    }

    /**
     * @param XMLSecurityKey $securityKey
     * @param string $data
     * @return mixed|string
     */
    public function signData($securityKey, $data)
    {
        return $securityKey->signData($data);
    }

    /**
     * @param XMLSecurityKey $securityKey
     * @param null|DOMNode $appendToNode
     */
    public function sign( $securityKey, $appendToNode = null )
    {
        // If we have a parent node append it now so C14N properly works
        if ( $appendToNode != null ) 
        {
            $this->resetXPathObj();
            $this->appendSignature( $appendToNode );
            $this->sigNode = $appendToNode->lastChild;
        }

        if ( $xpath = $this->getXPathObj() ) 
        {
            // Get the SignedInfo node
            $query = "./" . self::searchpfx . ":SignedInfo";
            $nodeset = $xpath->query( $query, $this->sigNode );

            if ( $sInfo = $nodeset->item(0) )
            {
                // Get the hash algorithm
                $query = "./" . self::searchpfx . ":SignatureMethod";
                $nodeset = $xpath->query( $query, $sInfo );
                /** @var \DOMElement $sMethod */
                $sMethod = $nodeset->item(0);
                $sMethod->setAttribute( 'Algorithm', $securityKey->type );

                // Compute the signature value
                $data = $this->canonicalizeData($sInfo, $this->canonicalMethod);
                $sigValue = base64_encode( $this->signData( $securityKey, $data ) );

                // Create a node for the  SignatureValue
                $sigValueNode = $this->createNewSignNode( 'SignatureValue', $sigValue );

                // And insert it in the right place
                if ($infoSibling = $sInfo->nextSibling)
                {
                    $infoSibling->parentNode->insertBefore( $sigValueNode, $infoSibling );
                } else
                {
                    $this->sigNode->appendChild( $sigValueNode );
                }
            }
        }
    }

    public function appendCert()
    {

    }

    /**
     * @param XMLSecurityKey $securityKey
     * @param null|DOMNode $parent
     */
    public function appendKey($securityKey, $parent=null)
    {
        $securityKey->serializeKey($parent);
    }

    /**
     * This function inserts the signature element.
     *
     * The signature element will be appended to the element, unless $beforeNode is specified. If $beforeNode
     * is specified, the signature element will be inserted as the last element before $beforeNode.
     *
     * @param DOMNode $node       The node the signature element should be inserted into.
     * @param DOMNode $beforeNode The node the signature element should be located before.
     *
     * @return DOMNode The signature element node
     */
    public function insertSignature( $node, $beforeNode = null )
    {

        $document = $node->ownerDocument;
        $signatureElement = $document->importNode($this->sigNode, true);

        if ($beforeNode == null)
        {
            return $node->insertBefore( $signatureElement );
        }
        else
        {
            return $node->insertBefore( $signatureElement, $beforeNode );
        }
    }

    /**
     * @param DOMNode $parentNode
     * @param bool $insertBefore
     * @return DOMNode
     */
    public function appendSignature( $parentNode, $insertBefore = false )
    {
        $beforeNode = $insertBefore ? $parentNode->firstChild : null;
        return $this->insertSignature( $parentNode, $beforeNode );
    }

    /**
     * @param string $cert
     * @param bool $isPEMFormat
     * @return string
     */
    public static function get509XCert( $cert, $isPEMFormat=true )
    {
        $certs = self::staticGet509XCerts( $cert, $isPEMFormat );
        if ( ! empty( $certs ) )
        {
            return $certs[0];
        }
        return '';
    }

    /**
     * @param string $certs
     * @param bool $isPEMFormat
     * @return array
     */
    public static function staticGet509XCerts( $certs, $isPEMFormat=true )
    {
        if ( $isPEMFormat )
        {
            $data = '';
            $certlist = array();
            $arCert = explode("\n", $certs);
            $inData = false;
            foreach ($arCert AS $curData)
            {
                if ( ! $inData )
                {
                    if ( strncmp( $curData, '-----BEGIN CERTIFICATE', 22 ) == 0 )
                    {
                        $inData = true;
                    }
                } 
                else
                {
                    if ( strncmp( $curData, '-----END CERTIFICATE', 20 ) == 0 )
                    {
                        $inData = false;
                        $certlist[] = $data;
                        $data = '';
                        continue;
                    }
                    $data .= trim( $curData );
                }
            }
            return $certlist;
        }
        else
        {
            return array($certs);
        }
    }

    /**
     * @param DOMElement $parentRef
     * @param string $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param null|DOMXPath $xpath
     * @param null|array $options
     * @throws \Exception
     */
    public static function staticAdd509Cert( $parentRef, $cert, $isPEMFormat = true, $isURL = false, $xpath = null, $options = null )
    {
        if ( $isURL )
        {
            $cert = file_get_contents($cert);
        }

        if ( ! $parentRef instanceof DOMElement)
        {
            throw new \Exception('Invalid parent Node parameter');
        }

        $baseDoc = $parentRef->ownerDocument;

        if ( empty( $xpath ) )
        {
            $xpath = new DOMXPath($parentRef->ownerDocument);
            $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS) ;
        }

        $query = "./". self::searchpfx . ":KeyInfo";
        $nodeset = $xpath->query( $query, $parentRef );
        $keyInfo = $nodeset->item(0);
        $dsig_pfx = '';
        if ( ! $keyInfo ) 
        {
            $pfx = $parentRef->lookupPrefix( self::XMLDSIGNS );
            if ( ! empty( $pfx ) ) 
            {
                $dsig_pfx = $pfx . ":";
            }
            $inserted = false;
            $keyInfo = $baseDoc->createElementNS( self::XMLDSIGNS, $dsig_pfx . 'KeyInfo' );

            $query = "./". self::searchpfx . ":Object";
            $nodeset = $xpath->query( $query, $parentRef );
            if ($sObject = $nodeset->item(0))
            {
                $sObject->parentNode->insertBefore( $keyInfo, $sObject );
                $inserted = true;
            }

            if (! $inserted)
            {
                $parentRef->appendChild( $keyInfo );
            }
        }
        else 
        {
            $pfx = $keyInfo->lookupPrefix( self::XMLDSIGNS );
            if ( ! empty( $pfx ) )
            {
                $dsig_pfx = $pfx . ":";
            }
        }

        // Add all certs if there are more than one
        $certs = self::staticGet509XCerts( $cert, $isPEMFormat );

        // Attach X509 data node
        $x509DataNode = $baseDoc->createElementNS( self::XMLDSIGNS, $dsig_pfx.'X509Data' );
        $keyInfo->appendChild( $x509DataNode );

        $issuerSerial = false;
        $subjectName = false;
        if ( is_array( $options ) )
        {
            if ( ! empty( $options['issuerSerial'] ) )
            {
                $issuerSerial = true;
            }
            if ( ! empty( $options['subjectName'] ) )
            {
                $subjectName = true;
            }
        }

        // Attach all certificate nodes and any additional data
        foreach ($certs as $X509Cert)
        {
            if ( $issuerSerial || $subjectName )
            {
                if ( $certData = openssl_x509_parse( "-----BEGIN CERTIFICATE-----\n" . chunk_split( $X509Cert, 64, "\n" ) . "-----END CERTIFICATE-----\n" ) )
                {
                    if ( $subjectName && ! empty( $certData['subject'] ) )
                    {
                        if ( is_array( $certData['subject'] ) )
                        {
                            $parts = array();
                            foreach ( $certData['subject'] AS $key => $value )
                            {
                                if ( is_array( $value ) )
                                {
                                    foreach ($value as $valueElement)
                                    {
                                        array_unshift( $parts, "$key=$valueElement" );
                                    }
                                }
                                else
                                {
                                    array_unshift( $parts, "$key=$value" );
                                }
                            }
                            $subjectNameValue = implode( ',', $parts );
                        }
                        else
                        {
                            $subjectNameValue = $certData['subject'];
                        }
                        $x509SubjectNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'X509SubjectName', $subjectNameValue);
                        $x509DataNode->appendChild($x509SubjectNode);
                    }
                    if ( $issuerSerial && ! empty( $certData['issuer'] ) && ! empty( $certData['serialNumber'] ) )
                    {
                        if ( is_array($certData['issuer'] ) ) 
                        {
                            $parts = array();
                            foreach ($certData['issuer'] AS $key => $value)
                            {
                                array_unshift( $parts, "$key=$value" );
                            }
                            $issuerName = implode( ',', $parts );
                        }
                        else
                        {
                            $issuerName = $certData['issuer'];
                        }

                        $x509IssuerNode = $baseDoc->createElementNS( self::XMLDSIGNS, $dsig_pfx.'X509IssuerSerial' );
                        $x509DataNode->appendChild( $x509IssuerNode );

                        $x509Node = $baseDoc->createElementNS( self::XMLDSIGNS, $dsig_pfx.'X509IssuerName', $issuerName );
                        $x509IssuerNode->appendChild( $x509Node );
                        $x509Node = $baseDoc->createElementNS( self::XMLDSIGNS, $dsig_pfx.'X509SerialNumber', $certData['serialNumber'] );
                        $x509IssuerNode->appendChild( $x509Node );
                    }
                }

            }
            $x509CertNode = $baseDoc->createElementNS( self::XMLDSIGNS, $dsig_pfx.'X509Certificate', $X509Cert );
            $x509DataNode->appendChild( $x509CertNode );
        }
    }

    /**
     * @param string $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param null|array $options
     */
    public function add509Cert($cert, $isPEMFormat=true, $isURL=false, $options=null)
    {
        if ( $xpath = $this->getXPathObj() )
        {
            self::staticAdd509Cert( $this->sigNode, $cert, $isPEMFormat, $isURL, $xpath, $options );
        }
    }

    /**
     * This function appends a node to the KeyInfo.
     *
     * The KeyInfo element will be created if one does not exist in the document.
     *
     * @param DOMNode $node The node to append to the KeyInfo.
     *
     * @return DOMNode The KeyInfo element node
     */
    public function appendToKeyInfo( $node )
    {
        $parentRef = $this->sigNode;
        $baseDoc = $parentRef->ownerDocument;

        $xpath = $this->getXPathObj();
        if ( empty( $xpath ) )
        {
            $xpath = new DOMXPath( $parentRef->ownerDocument );
            $xpath->registerNamespace( self::searchpfx, self::XMLDSIGNS );
        }

        $query = "./". self::searchpfx . ":KeyInfo";
        $nodeset = $xpath->query( $query, $parentRef );
        $keyInfo = $nodeset->item(0);
        if ( ! $keyInfo )
        {
            $dsig_pfx = '';
            $pfx = $parentRef->lookupPrefix( self::XMLDSIGNS );
            if ( ! empty( $pfx ) )
            {
                $dsig_pfx = $pfx.":";
            }

            $inserted = false;
            $keyInfo = $baseDoc->createElementNS( self::XMLDSIGNS, $dsig_pfx.'KeyInfo' );

            $query = "./". self::searchpfx . ":Object";
            $nodeset = $xpath->query( $query, $parentRef );
            if ( $sObject = $nodeset->item(0) )
            {
                $sObject->parentNode->insertBefore( $keyInfo, $sObject );
                $inserted = true;
            }

            if ( ! $inserted ) 
            {
                $parentRef->appendChild( $keyInfo );
            }
        }

        $keyInfo->appendChild( $node );

        return $keyInfo;
    }

    /**
     * This function retrieves an associative array of the validated nodes.
     *
     * The array will contain the id of the referenced node as the key and the node itself
     * as the value.
     *
     * Returns:
     *  An associative array of validated nodes or null if no nodes have been validated.
     *
     *  @return array Associative array of validated nodes
     */
    public function getValidatedNodes()
    {
        return $this->validatedNodes;
    }

    // /**
    //  * PHP canonicalization does not always result in the same output as other C14N
    //  * implementations such as xmllint, Python lxml or Microsoft Crypto libraries.
    //  * This preprocesses the DOM to make sure the output is consistent with other
    //  * implementations.  See https://bugs.php.net/bug.php?id=81188
    //  *
    //  * The difference between the PHP implementation of C14N and others is that PHP
    //  * does not order namespaces correctly (or, at least, not in the same way as 
    //  * the other C14N implementations to which I have access). 
    //  *
    //  * See https://www.w3.org/TR/2001/REC-xml-c14n-20010315 section 4.8
    //  *
    //  * The fragment below, which is a node that might appear in a <Transform> element 
    //  * (cut down for brevity) produces one output in PHP and another when using other
    //  * software such as xmllint.
    //  *
    //  * Input Xml:
    //  *
    //  * <XPath xmlns:dsig="xxx" Filter="subtract" xmlns:a="xxx" xmlns="xxx">some xpath query here</XPath>
    //  *
    //  * PHP output:
    //  *
    //  * <XPath xmlns:dsig="xxx" xmlns:a="xxx" xmlns="xxx" Filter="subtract" >some xpath query here</XPath>
    //  *
    //  * xmllint and other's output:
    //  *
    //  * <XPath xmlns="xxx" xmlns:a="xxx" xmlns:dsig="xxx" Filter="subtract">some xpath query here</XPath>
    //  *
    //  * You can see the difference is that PHP does put namespaces before attributes 
    //  * but leaves the namespaces in their document order.  The output by other tools
    //  * sorts the namespaces by their prefix.
    //  *
    //  * @param \DOMElement|\DOMDocument $element
    //  * @return void
    //  */
    // static function preCanonicalization( $element )
    // {
    //     if ( $element instanceof \DOMDocument )
    //     {
    //         $doc = $element;
    //         $element = $doc->documentElement;
    //     }
    //     else
    //         $doc = $element->ownerDocument;
    // 
    //     $namespaceNodes = array();
    //     $xpath = new \DOMXPath( $doc );
    //     // This query will pull all namespace attributes (DOMNameSpaceNode instances)
    //     // Most will be the default xml namespace or a copy of the namespace of the 
    //     // parent node so can be ignored.
    //     foreach( $xpath->query( './/namespace::*', $element ) as $node )
    //     {
    //         /** @var \DOMNameSpaceNode $node */
    //         // Ignore the XML namespace
    //         if ( $node->nodeValue == "http://www.w3.org/XML/1998/namespace" ) continue;
    // 
    //         // The parent node is the element to which the namespace attribute is assigned
    //         /** @var \DOMElement $elementNode */
    //         $elementNode = $node->parentNode;
    //         // If the element has a parent node (is not the root node) make sure the 
    //         // namespace is not the encapsulating namespace which can be ignored as 
    //         // this not a namespace listed in the output text document.
    //         if ( ! $node->prefix && $elementNode->parentNode && $elementNode->parentNode->namespaceURI == $elementNode->namespaceURI ) continue;
    // 
    //         // The id is not used except to keep the sets of recorded namespace details separate
    //         $id = spl_object_hash( $elementNode );
    //         if ( ! isset( $namespaceNodes[ $id ] ) )
    //         {
    //             $namespaceNodes[ $id ] = array('node' => $elementNode, 'ns' => array() );
    //         }
    // 
    //         // Remove it so it can be added in the correct order in a subsequent step
    //         if ( $elementNode->removeAttributeNS( $node->namespaceURI, $node->prefix ) === false )
    //             continue;
    // 
    //         // Record the details indexed by the namespace parent element
    //         $namespaceNodes[ $id ]['ns'][ $node->localName ] = $node->nodeValue;
    //     }
    // 
    //     // Now for each of the affected elements remove regular attributes 
    //     // then add namespace and then the regular attributes
    //     foreach( $namespaceNodes as $namespaceNode )
    //     {
    //         // Sort the namespace in order of their prefix with any default namespace first.
    //         // This is the feature that seems to be missing from the PHP C14N process.
    //         uksort( $namespaceNode['ns'], function( $a, $b ) 
    //         {
    //             // xmlns is *always* to be the first
    //             if ( $a == 'xmlns' ) return -1;
    //             if ( $b == 'xmlns' ) return 1;
    //             return strcmp( $a, $b );
    //         } );
    // 
    //         // Record and remove all the attributes
    //         /** @var \DOMNode $node */
    //         $node = $namespaceNode['node'];
    //         $attributes = array();
    //         foreach( $node->attributes as $attribute )
    //         {
    //             /** @var \DOMAttr $attribute */
    //             /** @var \DOMElement $node */
    //             if ( ! $node->removeAttributeNode( $attribute ) )
    //                 continue;
    // 
    //             $attributes[] = $attribute;
    //         }
    // 
    //         // The attributes don't need sorting as the canonicalization process will take care of them.
    //         // Reapply the attributes starting with the namespaces
    //         foreach( $namespaceNode['ns'] as $prefix => $namespaceURI )
    //         {
    //             if ( $prefix == 'xmlns' )
    //                 $node->setAttributeNS( '', "$prefix", $namespaceURI);
    //             else
    //                 $node->setAttribute( "xmlns:$prefix", $namespaceURI );
    //         }
    // 
    //         // And then the attributes
    //         foreach( $attributes as $attribute )
    //         {
    //             $node->setAttributeNode( $attribute );
    //         }
    //     }
    // }
}
