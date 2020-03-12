<?php

namespace SimpleSAML\XMLSec;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
use SimpleSAML\XMLSec\Utils\XPath as XPath;

/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2019, Robert Richards <rrichards@cdatazone.org>.
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
 * @copyright 2007-2019 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

class XMLSecurityDSig
{
    public const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';
    public const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    public const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    public const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    public const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
    public const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    public const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    public const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    public const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    public const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public const TEMPLATE = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:SignatureMethod />
  </ds:SignedInfo>
</ds:Signature>';

    public const BASE_TEMPLATE = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <SignatureMethod />
  </SignedInfo>
</Signature>';

    /** @var DOMElement|null */
    public $sigNode = null;

    /** @var array */
    public $idKeys = [];

    /** @var array */
    public $idNS = [];

    /** @var string|null */
    private $signedInfo = null;

    /** @var \DOMXPath|null */
    private $xPathCtx = null;

    /** @var string|null */
    private $canonicalMethod = null;

    /** @var string */
    private $prefix = '';

    /** @var string */
    private $searchpfx = 'secdsig';

    /**
     * This variable contains an associative array of validated nodes.
     * @var array|null
     */
    private $validatedNodes = null;


    /**
     * @param string $prefix
     */
    public function __construct(string $prefix = 'ds')
    {
        $template = self::BASE_TEMPLATE;
        if (!empty($prefix)) {
            $this->prefix = $prefix . ':';
            $search = array("<S", "</S", "xmlns=");
            $replace = array("<$prefix:S", "</$prefix:S", "xmlns:$prefix=");
            $template = str_replace($search, $replace, $template);
        }
        $sigdoc = new DOMDocument();
        $sigdoc->loadXML($template);
        $this->sigNode = $sigdoc->documentElement;
    }


    /**
     * Reset the XPathObj to null
     */
    private function resetXPathObj(): void
    {
        $this->xPathCtx = null;
    }

    /**
     * Returns the XPathObj or null if xPathCtx is set and sigNode is empty.
     *
     * @return \DOMXPath|null
     */
    private function getXPathObj(): DOMXPath
    {
        if (empty($this->xPathCtx) && ! empty($this->sigNode)) {
            $xpath = new DOMXPath($this->sigNode->ownerDocument);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
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
    public static function generateGUID(string $prefix = 'pfx'): string
    {
        $uuid = md5(uniqid(mt_rand(), true));
        $guid = $prefix . substr($uuid, 0, 8) . "-" .
                substr($uuid, 8, 4) . "-" .
                substr($uuid, 12, 4) . "-" .
                substr($uuid, 16, 4) . "-" .
                substr($uuid, 20, 12);
        return $guid;
    }


    /**
     * @param \DOMNode $objDoc
     * @param int $pos
     * @return \DOMNode|null
     */
    public function locateSignature(DOMNode $objDoc, int $pos = 0): ?DOMNode
    {
        if ($objDoc instanceof DOMDocument) {
            $doc = $objDoc;
        } else {
            $doc = $objDoc->ownerDocument;
        }

        if ($doc) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
            $query = ".//secdsig:Signature";
            $nodeset = $xpath->query($query, $objDoc);
            $this->sigNode = $nodeset->item($pos);
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($nodeset->length > 1) {
                throw new Exception("Invalid structure - Too many SignedInfo elements found");
            }
            return $this->sigNode;
        }
        return null;
    }

    /**
     * @param string $name
     * @param string|null $value
     * @return \DOMElement
     */
    public function createNewSignNode(string $name, string $value = null): DOMElement
    {
        $doc = $this->sigNode->ownerDocument;
        if (!is_null($value)) {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix . $name, $value);
        } else {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix . $name);
        }
        return $node;
    }


    /**
     * @param string $method
     * @throws \Exception
     */
    public function setCanonicalMethod(string $method): void
    {
        switch ($method) {
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
            case 'http://www.w3.org/2001/10/xml-exc-c14n#':
            case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                $this->canonicalMethod = $method;
                break;
            default:
                throw new Exception('Invalid Canonical Method');
        }
        if ($xpath = $this->getXPathObj()) {
            $query = './' . $this->searchpfx . ':SignedInfo';
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sinfo = $nodeset->item(0)) {
                $query = './' . $this->searchpfx . 'CanonicalizationMethod';
                $nodeset = $xpath->query($query, $sinfo);
                if (!($canonNode = $nodeset->item(0))) {
                    $canonNode = $this->createNewSignNode('CanonicalizationMethod');
                    $sinfo->insertBefore($canonNode, $sinfo->firstChild);
                }
                $canonNode->setAttribute('Algorithm', $this->canonicalMethod);
            }
        }
    }


    /**
     * @param \DOMNode $node
     * @param string $canonicalmethod
     * @param array|null $arXPath
     * @param array|null $prefixList
     * @return string
     */
    private function canonicalizeData(
        DOMNode $node,
        string $canonicalmethod,
        array $arXPath = null,
        array $prefixList = null
    ): string {
        $exclusive = false;
        $withComments = false;
        switch ($canonicalmethod) {
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
                $exclusive = false;
                $withComments = false;
                break;
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
                $withComments = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                $exclusive = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                $exclusive = true;
                $withComments = true;
                break;
        }

        if (
            is_null($arXPath)
            && ($node instanceof DOMNode)
            && ($node->ownerDocument !== null)
            && $node->isSameNode($node->ownerDocument->documentElement)
        ) {
            /* Check for any PI or comments as they would have been excluded */
            $element = $node;
            while ($refnode = $element->previousSibling) {
                if (
                    $refnode->nodeType == XML_PI_NODE
                    || (($refnode->nodeType == XML_COMMENT_NODE) && $withComments === true)
                ) {
                    break;
                }
                $element = $refnode;
            }
            if ($refnode == null) {
                $node = $node->ownerDocument;
            }
        }

        return $node->C14N($exclusive, $withComments, $arXPath, $prefixList);
    }


    /**
     * @return string|null
     */
    public function canonicalizeSignedInfo(): ?string
    {
        $doc = $this->sigNode->ownerDocument;
        $canonicalmethod = null;
        if ($doc) {
            $xpath = $this->getXPathObj();
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($nodeset->length > 1) {
                throw new Exception("Invalid structure - Too many SignedInfo elements found");
            }
            if ($signInfoNode = $nodeset->item(0)) {
                $query = "./secdsig:CanonicalizationMethod";
                $nodeset = $xpath->query($query, $signInfoNode);
                $prefixList = null;
                if ($canonNode = $nodeset->item(0)) {
                    $canonicalmethod = $canonNode->getAttribute('Algorithm');
                    foreach ($canonNode->childNodes as $node)
                    {
                        if ($node->localName == 'InclusiveNamespaces') {
                            if ($pfx = $node->getAttribute('PrefixList')) {
                                $arpfx = array_filter(explode(' ', $pfx));
                                if (count($arpfx) > 0) {
                                    $prefixList = array_merge($prefixList ? $prefixList : array(), $arpfx);
                                }
                            }
                        }
                    }
                }
                $this->signedInfo = $this->canonicalizeData($signInfoNode, $canonicalmethod, null, $prefixList);
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
    public function calculateDigest(string $digestAlgorithm, string $data, bool $encode = true): string
    {
        switch ($digestAlgorithm) {
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
                throw new Exception("Cannot validate digest: Unsupported Algorithm <$digestAlgorithm>");
        }

        $digest = hash($alg, $data, true);
        if ($encode) {
            $digest = base64_encode($digest);
        }
        return $digest;
    }


    /**
     * @param \DOMNode $refNode
     * @param string $data
     * @return bool
     */
    public function validateDigest(DOMNode $refNode, string $data): bool
    {
        $xpath = new DOMXPath($refNode->ownerDocument);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = 'string(./secdsig:DigestMethod/@Algorithm)';
        $digestAlgorithm = $xpath->evaluate($query, $refNode);
        $digValue = $this->calculateDigest($digestAlgorithm, $data, false);
        $query = 'string(./secdsig:DigestValue)';
        $digestValue = $xpath->evaluate($query, $refNode);
        return ($digValue === base64_decode($digestValue));
    }

    /**
     * @param \DOMNode $refNode
     * @param \DOMNode $objData
     * @param bool $includeCommentNodes
     * @return string
     */
    public function processTransforms(DOMNode $refNode, DOMNode $objData, bool $includeCommentNodes = true): string
    {
        $data = $objData;
        $xpath = new DOMXPath($refNode->ownerDocument);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = './secdsig:Transforms/secdsig:Transform';
        $nodelist = $xpath->query($query, $refNode);
        $canonicalMethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
        $arXPath = null;
        $prefixList = null;
        foreach ($nodelist as $transform) {
            $algorithm = $transform->getAttribute("Algorithm");
            switch ($algorithm) {
                case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                    if ($includeCommentNodes === false) {
                        /* We remove comment nodes by forcing it to use a canonicalization
                         * without comments.
                         */
                        $canonicalMethod = 'http://www.w3.org/2001/10/xml-exc-c14n#';
                    } else {
                        $canonicalMethod = $algorithm;
                    }

                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'InclusiveNamespaces') {
                            if ($pfx = $node->getAttribute('PrefixList')) {
                                $arpfx = array();
                                $pfxlist = explode(" ", $pfx);
                                foreach ($pfxlist as $pfx) {
                                    $val = trim($pfx);
                                    if (! empty($val)) {
                                        $arpfx[] = $val;
                                    }
                                }
                                if (count($arpfx) > 0) {
                                    $prefixList = $arpfx;
                                }
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }
                    break;
                case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
                case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
                    if (!$includeCommentNodes) {
                        /* We remove comment nodes by forcing it to use a canonicalization
                         * without comments.
                         */
                        $canonicalMethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
                    } else {
                        $canonicalMethod = $algorithm;
                    }

                    break;
                case 'http://www.w3.org/TR/1999/REC-xpath-19991116':
                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'XPath') {
                            $arXPath = [];
                            $arXPath['query'] = '(.//. | .//@* | .//namespace::*)[' . $node->nodeValue . ']';
                            $arXpath['namespaces'] = [];

                            $nslist = $xpath->query('./namespace::*', $node);
                            foreach ($nslist as $nsnode) {
                                if ($nsnode->localName != "xml") {
                                    $arXPath['namespaces'][$nsnode->localName] = $nsnode->nodeValue;
                                }
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }
                    break;
            }
        }
        if ($data instanceof DOMNode) {
            $data = $this->canonicalizeData($objData, $canonicalMethod, $arXPath, $prefixList);
        }
        return $data;
    }


    /**
     * @param \DOMNode $refNode
     * @return bool
     */
    public function processRefNode(DOMNode $refNode): bool
    {
        $dataObject = null;

        /*
         * Depending on the URI, we may not want to include comments in the result
         * See: http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
         */
        $includeCommentNodes = true;

        if ($uri = $refNode->getAttribute("URI")) {
            $arUrl = parse_url($uri);
            if (empty($arUrl['path'])) {
                if ($identifier = $arUrl['fragment']) {
                    /* This reference identifies a node with the given id by using
                     * a URI on the form "#identifier". This should not include comments.
                     */
                    $includeCommentNodes = false;

                    $xPath = new DOMXPath($refNode->ownerDocument);
                    if ($this->idNS && is_array($this->idNS)) {
                        foreach ($this->idNS as $nspf => $ns) {
                            $xPath->registerNamespace($nspf, $ns);
                        }
                    }
                    $iDlist = '@Id="' . XPath::filterAttrValue($identifier, XPath::DOUBLE_QUOTE) . '"';
                    if (is_array($this->idKeys)) {
                        foreach ($this->idKeys as $idKey) {
                            $iDlist .= " or @" . XPath::filterAttrName($idKey) . '="' .
                                XPath::filterAttrValue($identifier, XPath::DOUBLE_QUOTE) . '"';
                        }
                    }
                    $query = '//*[' . $iDlist . ']';
                    $dataObject = $xPath->query($query)->item(0);
                } else {
                    $dataObject = $refNode->ownerDocument;
                }
            }
        } else {
            /* This reference identifies the root node with an empty URI. This should
             * not include comments.
             */
            $includeCommentNodes = false;

            $dataObject = $refNode->ownerDocument;
        }
        $data = $this->processTransforms($refNode, $dataObject, $includeCommentNodes);
        if (!$this->validateDigest($refNode, $data)) {
            return false;
        }

        if ($dataObject instanceof DOMNode) {
            /* Add this node to the list of validated nodes. */
            if (!empty($identifier)) {
                $this->validatedNodes[$identifier] = $dataObject;
            } else {
                $this->validatedNodes[] = $dataObject;
            }
        }

        return true;
    }


    /**
     * @param \DOMNode $refNode
     * @return string|null
     */
    public function getRefNodeID(DOMNode $refNode): ?string
    {
        if ($uri = $refNode->getAttribute("URI")) {
            $arUrl = parse_url($uri);
            if (empty($arUrl['path'])) {
                if ($identifier = $arUrl['fragment']) {
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
    public function getRefIDs(): array
    {
        $refids = [];

        $xpath = $this->getXPathObj();
        $query = "./secdsig:SignedInfo[1]/secdsig:Reference";
        $nodeset = $xpath->query($query, $this->sigNode);
        if ($nodeset->length == 0) {
            throw new Exception("Reference nodes not found");
        }
        foreach ($nodeset as $refNode) {
            $refids[] = $this->getRefNodeID($refNode);
        }
        return $refids;
    }


    /**
     * @return bool
     * @throws \Exception
     */
    public function validateReference(): bool
    {
        $docElem = $this->sigNode->ownerDocument->documentElement;
        if (!$docElem->isSameNode($this->sigNode)) {
            if ($this->sigNode->parentNode !== null) {
                $this->sigNode->parentNode->removeChild($this->sigNode);
            }
        }
        $xpath = $this->getXPathObj();
        $query = "./secdsig:SignedInfo[1]/secdsig:Reference";
        $nodeset = $xpath->query($query, $this->sigNode);
        if ($nodeset->length == 0) {
            throw new Exception("Reference nodes not found");
        }

        /* Initialize/reset the list of validated nodes. */
        $this->validatedNodes = [];

        foreach ($nodeset as $refNode) {
            if (! $this->processRefNode($refNode)) {
                /* Clear the list of validated nodes. */
                $this->validatedNodes = null;
                throw new Exception("Reference validation failed");
            }
        }
        return true;
    }


    /**
     * @param \DOMNode $sinfoNode
     * @param \DOMDocument $node
     * @param string $algorithm
     * @param array|null $arTransforms
     * @param array|null $options
     */
    private function addRefInternal(
        DOMNode $sinfoNode,
        DOMNode $node,
        string $algorithm,
        array $arTransforms = null,
        array $options = null
    ): void {
        $prefix = null;
        $prefix_ns = null;
        $id_name = 'Id';
        $overwrite_id  = true;
        $force_uri = false;

        if (is_array($options)) {
            $prefix = empty($options['prefix']) ? null : $options['prefix'];
            $prefix_ns = empty($options['prefix_ns']) ? null : $options['prefix_ns'];
            $id_name = empty($options['id_name']) ? 'Id' : $options['id_name'];
            $overwrite_id = !isset($options['overwrite']) ? true : (bool) $options['overwrite'];
            $force_uri = !isset($options['force_uri']) ? false : (bool) $options['force_uri'];
        }

        $attname = $id_name;
        if (! empty($prefix)) {
            $attname = $prefix . ':' . $attname;
        }

        $refNode = $this->createNewSignNode('Reference');
        $sinfoNode->appendChild($refNode);

        if (!($node instanceof DOMDocument)) {
            $uri = null;
            if (! $overwrite_id) {
                $uri = $prefix_ns ? $node->getAttributeNS($prefix_ns, $id_name) : $node->getAttribute($id_name);
            }
            if (empty($uri)) {
                $uri = self::generateGUID();
                $node->setAttributeNS($prefix_ns, $attname, $uri);
            }
            $refNode->setAttribute("URI", '#' . $uri);
        } elseif ($force_uri) {
            $refNode->setAttribute("URI", '');
        }

        $transNodes = $this->createNewSignNode('Transforms');
        $refNode->appendChild($transNodes);

        if (is_array($arTransforms)) {
            foreach ($arTransforms as $transform) {
                $transNode = $this->createNewSignNode('Transform');
                $transNodes->appendChild($transNode);
                if (
                    is_array($transform)
                    && (!empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']))
                    && (!empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query']))
                ) {
                    $transNode->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
                    $XPathNode = $this->createNewSignNode(
                        'XPath',
                        $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query']
                    );
                    $transNode->appendChild($XPathNode);
                    if (!empty($ns = $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'])) {
                        foreach ($ns as $prefix => $namespace) {
                            $XPathNode->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:$prefix", $namespace);
                        }
                    }
                } else {
                    $transNode->setAttribute('Algorithm', $transform);
                }
            }
        } elseif (!empty($this->canonicalMethod)) {
            $transNode = $this->createNewSignNode('Transform');
            $transNodes->appendChild($transNode);
            $transNode->setAttribute('Algorithm', $this->canonicalMethod);
        }

        $canonicalData = $this->processTransforms($refNode, $node);
        $digValue = $this->calculateDigest($algorithm, $canonicalData);

        $digestMethod = $this->createNewSignNode('DigestMethod');
        $refNode->appendChild($digestMethod);
        $digestMethod->setAttribute('Algorithm', $algorithm);

        $digestValue = $this->createNewSignNode('DigestValue', $digValue);
        $refNode->appendChild($digestValue);
    }


    /**
     * @param \DOMDocument $node
     * @param string $algorithm
     * @param array|null $arTransforms
     * @param array|null $options
     */
    public function addReference(
        DOMDocument $node,
        string $algorithm,
        array $arTransforms = null,
        array $options = null
    ): void {
        if ($xpath = $this->getXPathObj()) {
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sInfo = $nodeset->item(0)) {
                $this->addRefInternal($sInfo, $node, $algorithm, $arTransforms, $options);
            }
        }
    }

    /**
     * @param array $arNodes
     * @param string $algorithm
     * @param array|null $arTransforms
     * @param array|null $options
     */
    public function addReferenceList(
        array $arNodes,
        string $algorithm,
        array $arTransforms = null,
        array $options = null
    ): void {
        if ($xpath = $this->getXPathObj()) {
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sInfo = $nodeset->item(0)) {
                foreach ($arNodes as $node) {
                    $this->addRefInternal($sInfo, $node, $algorithm, $arTransforms, $options);
                }
            }
        }
    }


    /**
     * @param \DOMElement|string $data
     * @param string|null $mimetype
     * @param string|null $encoding
     * @return \DOMElement
     */
    public function addObject($data, string $mimetype = null, string $encoding = null): DOMElement
    {
        $objNode = $this->createNewSignNode('Object');
        $this->sigNode->appendChild($objNode);
        if (!empty($mimetype)) {
            $objNode->setAttribute('MimeType', $mimetype);
        }
        if (!empty($encoding)) {
            $objNode->setAttribute('Encoding', $encoding);
        }

        if ($data instanceof DOMElement) {
            $newData = $this->sigNode->ownerDocument->importNode($data, true);
        } else {
            $newData = $this->sigNode->ownerDocument->createTextNode($data);
        }
        $objNode->appendChild($newData);

        return $objNode;
    }


    /**
     * @param \DOMNode|null $node
     * @return \SimpleSAML\XMLSec\XMLSecurityKey|null
     */
    public function locateKey(DOMNode $node = null): ?XMLSecurityKey
    {
        if (empty($node)) {
            $node = $this->sigNode;
        }
        if (!($node instanceof DOMNode)) {
            return null;
        }
        if ($doc = $node->ownerDocument) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
            $query = "string(./secdsig:SignedInfo/secdsig:SignatureMethod/@Algorithm)";
            $algorithm = $xpath->evaluate($query, $node);
            if ($algorithm) {
                try {
                    $objKey = new XMLSecurityKey($algorithm, ['type' => 'public']);
                } catch (Exception $e) {
                    return null;
                }
                return $objKey;
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
     * @param \SimpleSAML\XMLSec\XMLSecurityKey $objKey
     * @return bool|int
     * @throws \Exception
     */
    public function verify(XMLSecurityKey $objKey)
    {
        $doc = $this->sigNode->ownerDocument;
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = "string(./secdsig:SignatureValue)";
        $sigValue = $xpath->evaluate($query, $this->sigNode);
        if (empty($sigValue)) {
            throw new Exception("Unable to locate SignatureValue");
        }
        return $objKey->verifySignature($this->signedInfo, base64_decode($sigValue));
    }


    /**
     * @param \SimpleSAML\XMLSec\XMLSecurityKey $objKey
     * @param string $data
     * @return mixed|string
     */
    public function signData(XMLSecurityKey $objKey, string $data)
    {
        return $objKey->signData($data);
    }


    /**
     * @param \SimpleSAML\XMLSec\XMLSecurityKey $objKey
     * @param \DOMNode|null $appendToNode
     */
    public function sign(XMLSecurityKey $objKey, DOMNode $appendToNode = null): void
    {
        // If we have a parent node append it now so C14N properly works
        if ($appendToNode !== null) {
            $this->resetXPathObj();
            $this->appendSignature($appendToNode);
            $this->sigNode = $appendToNode->lastChild;
        }
        if ($xpath = $this->getXPathObj()) {
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sInfo = $nodeset->item(0)) {
                $query = "./secdsig:SignatureMethod";
                $nodeset = $xpath->query($query, $sInfo);
                $sMethod = $nodeset->item(0);
                $sMethod->setAttribute('Algorithm', $objKey->type);
                $data = $this->canonicalizeData($sInfo, $this->canonicalMethod);
                $sigValue = base64_encode($this->signData($objKey, $data));
                $sigValueNode = $this->createNewSignNode('SignatureValue', $sigValue);
                if ($infoSibling = $sInfo->nextSibling) {
                    $infoSibling->parentNode->insertBefore($sigValueNode, $infoSibling);
                } else {
                    $this->sigNode->appendChild($sigValueNode);
                }
            }
        }
    }


    public function appendCert(): void
    {
    }


    /**
     * @param \SimpleSAML\XMLSec\XMLSecurityKey $objKey
     * @param \DOMNode|null $parent
     */
    public function appendKey(XMLSecurityKey $objKey, DOMNode $parent = null): void
    {
        $objKey->serializeKey($parent);
    }


    /**
     * This function inserts the signature element.
     *
     * The signature element will be appended to the element, unless $beforeNode is specified. If $beforeNode
     * is specified, the signature element will be inserted as the last element before $beforeNode.
     *
     * @param \DOMNode $node       The node the signature element should be inserted into.
     * @param \DOMNode $beforeNode The node the signature element should be located before.
     *
     * @return \DOMNode The signature element node
     */
    public function insertSignature(DOMNode $node, DOMNode $beforeNode = null): DOMNode
    {
        $document = $node->ownerDocument;
        $signatureElement = $document->importNode($this->sigNode, true);

        if ($beforeNode === null) {
            return $node->insertBefore($signatureElement);
        } else {
            return $node->insertBefore($signatureElement, $beforeNode);
        }
    }


    /**
     * @param \DOMNode $parentNode
     * @param bool $insertBefore
     * @return \DOMNode
     */
    public function appendSignature(DOMNode $parentNode, bool $insertBefore = false): DOMNode
    {
        $beforeNode = $insertBefore ? $parentNode->firstChild : null;
        return $this->insertSignature($parentNode, $beforeNode);
    }


    /**
     * @param string $cert
     * @param bool $isPEMFormat
     * @return string
     */
    public static function get509XCert(string $cert, bool $isPEMFormat = true): string
    {
        $certs = self::staticGet509XCerts($cert, $isPEMFormat);
        if (!empty($certs)) {
            return $certs[0];
        }
        return '';
    }


    /**
     * @param string $certs
     * @param bool $isPEMFormat
     * @return array
     */
    public static function staticGet509XCerts(string $certs, bool $isPEMFormat = true): array
    {
        if ($isPEMFormat) {
            $data = '';
            $certlist = [];
            $arCert = explode("\n", $certs);
            $inData = false;
            foreach ($arCert as $curData) {
                if ($inData === false) {
                    if (strncmp($curData, '-----BEGIN CERTIFICATE', 22) == 0) {
                        $inData = true;
                    }
                } else {
                    if (strncmp($curData, '-----END CERTIFICATE', 20) == 0) {
                        $inData = false;
                        $certlist[] = $data;
                        $data = '';
                        continue;
                    }
                    $data .= trim($curData);
                }
            }
            return $certlist;
        } else {
            return [$certs];
        }
    }


    /**
     * @param \DOMElement $parentRef
     * @param string $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param \DOMXPath|null $xpath
     * @param array|null $options
     * @throws \Exception
     */
    public static function staticAdd509Cert(
        DOMElement $parentRef,
        string $cert,
        bool $isPEMFormat = true,
        bool $isURL = false,
        DOMXPath $xpath = null,
        array $options = null
    ): void {
        if ($isURL) {
            $cert = file_get_contents($cert);
        }

        $baseDoc = $parentRef->ownerDocument;

        if (empty($xpath)) {
            $xpath = new DOMXPath($parentRef->ownerDocument);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        }

        $query = "./secdsig:KeyInfo";
        $nodeset = $xpath->query($query, $parentRef);
        $keyInfo = $nodeset->item(0);
        $dsig_pfx = '';
        if ($keyInfo === null) {
            $pfx = $parentRef->lookupPrefix(self::XMLDSIGNS);
            if (! empty($pfx)) {
                $dsig_pfx = $pfx . ":";
            }
            $inserted = false;
            $keyInfo = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx . 'KeyInfo');

            $query = "./secdsig:Object";
            $nodeset = $xpath->query($query, $parentRef);
            if ($sObject = $nodeset->item(0)) {
                $sObject->parentNode->insertBefore($keyInfo, $sObject);
                $inserted = true;
            }

            if ($inserted === false) {
                $parentRef->appendChild($keyInfo);
            }
        } else {
            $pfx = $keyInfo->lookupPrefix(self::XMLDSIGNS);
            if (!empty($pfx)) {
                $dsig_pfx = $pfx . ":";
            }
        }

        // Add all certs if there are more than one
        $certs = self::staticGet509XCerts($cert, $isPEMFormat);

        // Attach X509 data node
        $x509DataNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx . 'X509Data');
        $keyInfo->appendChild($x509DataNode);

        $issuerSerial = false;
        $subjectName = false;
        if (is_array($options)) {
            if (!empty($options['issuerSerial'])) {
                $issuerSerial = true;
            }
            if (!empty($options['subjectName'])) {
                $subjectName = true;
            }
        }

        // Attach all certificate nodes and any additional data
        foreach ($certs as $X509Cert) {
            if ($issuerSerial || $subjectName) {
                $cert = chunk_split($X509Cert, 64, "\n");
                if (
                    $certData = openssl_x509_parse(
                        "-----BEGIN CERTIFICATE-----\n" . $cert . "-----END CERTIFICATE-----\n"
                    )
                ) {
                    if ($subjectName && !empty($certData['subject'])) {
                        if (is_array($certData['subject'])) {
                            $parts = array();
                            foreach ($certData['subject'] as $key => $value) {
                                if (is_array($value)) {
                                    foreach ($value as $valueElement) {
                                        array_unshift($parts, "$key=$valueElement");
                                    }
                                } else {
                                    array_unshift($parts, "$key=$value");
                                }
                            }
                            $subjectNameValue = implode(',', $parts);
                        } else {
                            $subjectNameValue = $certData['issuer'];
                        }
                        $x509SubjectNode = $baseDoc->createElementNS(
                            self::XMLDSIGNS,
                            $dsig_pfx . 'X509SubjectName',
                            $subjectNameValue
                        );
                        $x509DataNode->appendChild($x509SubjectNode);
                    }
                    if ($issuerSerial && ! empty($certData['issuer']) && ! empty($certData['serialNumber'])) {
                        if (is_array($certData['issuer'])) {
                            $parts = [];
                            foreach ($certData['issuer'] as $key => $value) {
                                array_unshift($parts, "$key=$value");
                            }
                            $issuerName = implode(',', $parts);
                        } else {
                            $issuerName = $certData['issuer'];
                        }

                        $x509IssuerNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx . 'X509IssuerSerial');
                        $x509DataNode->appendChild($x509IssuerNode);

                        $x509Node = $baseDoc->createElementNS(
                            self::XMLDSIGNS,
                            $dsig_pfx . 'X509IssuerName',
                            $issuerName
                        );
                        $x509IssuerNode->appendChild($x509Node);
                        $x509Node = $baseDoc->createElementNS(
                            self::XMLDSIGNS,
                            $dsig_pfx . 'X509SerialNumber',
                            $certData['serialNumber']
                        );
                        $x509IssuerNode->appendChild($x509Node);
                    }
                }
            }
            $x509CertNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx . 'X509Certificate', $X509Cert);
            $x509DataNode->appendChild($x509CertNode);
        }
    }


    /**
     * @param string $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param array|null $options
     */
    public function add509Cert(
        string $cert,
        bool $isPEMFormat = true,
        bool $isURL = false,
        array $options = null
    ): void {
        if ($xpath = $this->getXPathObj()) {
            self::staticAdd509Cert($this->sigNode, $cert, $isPEMFormat, $isURL, $xpath, $options);
        }
    }


    /**
     * This function appends a node to the KeyInfo.
     *
     * The KeyInfo element will be created if one does not exist in the document.
     *
     * @param \DOMNode $node The node to append to the KeyInfo.
     *
     * @return \DOMNode The KeyInfo element node
     */
    public function appendToKeyInfo(DOMNode $node): DOMNode
    {
        $parentRef = $this->sigNode;
        $baseDoc = $parentRef->ownerDocument;

        $xpath = $this->getXPathObj();
        if (empty($xpath)) {
            $xpath = new DOMXPath($parentRef->ownerDocument);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        }

        $query = "./secdsig:KeyInfo";
        $nodeset = $xpath->query($query, $parentRef);
        $keyInfo = $nodeset->item(0);
        if ($keyInfo === null) {
            $dsig_pfx = '';
            $pfx = $parentRef->lookupPrefix(self::XMLDSIGNS);
            if (!empty($pfx)) {
                $dsig_pfx = $pfx . ":";
            }
            $inserted = false;
            $keyInfo = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx . 'KeyInfo');

            $query = "./secdsig:Object";
            $nodeset = $xpath->query($query, $parentRef);
            if ($sObject = $nodeset->item(0)) {
                $sObject->parentNode->insertBefore($keyInfo, $sObject);
                $inserted = true;
            }

            if ($inserted === false) {
                $parentRef->appendChild($keyInfo);
            }
        }

        $keyInfo->appendChild($node);

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
    public function getValidatedNodes(): array
    {
        return $this->validatedNodes;
    }
}
