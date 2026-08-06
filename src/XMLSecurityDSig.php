<?php
namespace RobRichards\XMLSecLibs;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
use phpseclib3\File\X509;
use RobRichards\XMLSecLibs\Utils\XPath as XPath;

/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2026, Robert Richards <rrichards@cdatazone.org>.
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
 * @copyright 2007-2026 Robert Richards <rrichards@cdatazone.org>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 */

class XMLSecurityDSig
{
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';
    const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
    const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    /** Default maximum XPath transforms allowed per Reference (DoS protection). */
    const MAX_XPATH_TRANSFORMS = 5;

    /** Default maximum namespaces allowed on a single XPath transform (DoS protection). */
    const MAX_XPATH_NAMESPACES = 20;

    /**
     * Safe-by-default SignatureMethod allowlist applied by verifyDocument().
     * SHA-1 based signatures (rsa-sha1, dsa-sha1, hmac-sha1) are intentionally
     * excluded; callers that must interoperate with legacy peers can opt in by
     * populating $allowedSignatureAlgorithms explicitly.
     */
    const DEFAULT_SIGNATURE_ALGORITHMS = array(
        XMLSecurityKey::RSA_SHA256,
        XMLSecurityKey::RSA_SHA384,
        XMLSecurityKey::RSA_SHA512,
        XMLSecurityKey::RSA_SHA256_MGF1,
    );

    /**
     * Safe-by-default DigestMethod allowlist applied by verifyDocument().
     * SHA-1 and RIPEMD-160 are intentionally excluded.
     */
    const DEFAULT_DIGEST_ALGORITHMS = array(
        self::SHA256,
        self::SHA384,
        self::SHA512,
    );

    const BASE_TEMPLATE = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <SignatureMethod />
  </SignedInfo>
</Signature>';

    const BASE_TEMPLATE_NOWS = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><SignatureMethod /></SignedInfo></Signature>';

    /** @var DOMElement|null */
    public $sigNode = null;

    /** @var array */
    public $idKeys = array();

    /** @var array */
    public $idNS = array();

    /**
     * Maximum XPath transforms allowed per Reference (DoS protection).
     * Defaults to MAX_XPATH_TRANSFORMS; override for stricter or more relaxed limits.
     * @var int
     */
    public $maxXPathTransforms = self::MAX_XPATH_TRANSFORMS;

    /**
     * Maximum namespaces allowed on a single XPath transform (DoS protection).
     * Defaults to MAX_XPATH_NAMESPACES; override for stricter or more relaxed limits.
     * @var int
     */
    public $maxXPathNamespaces = self::MAX_XPATH_NAMESPACES;

    /**
     * Allow XPath (REC-xpath-19991116) Transforms while verifying references.
     *
     * The XPath Filtering Transform evaluates an arbitrary, document-supplied
     * XPath expression during validateReference() -- before any signature
     * cryptography runs. The expression is an arbitrary XPath by design, so it 
     * cannot be sanitized without breaking the feature.
     * The maxXPath* caps only bound the count, not the cost of a single expression.
     *
     * SAML and WS-Security do not use XPath transforms, so this defaults to
     * false (reject them on the verification path). Set to true only if you
     * must verify signatures that legitimately rely on XPath transforms and you
     * trust the document source. Signing is unaffected (the transforms are
     * caller-supplied, not attacker-controlled).
     *
     * @var bool
     */
    public $allowXPathTransforms = false;

    /**
     * Allowlist of acceptable SignatureMethod algorithm URIs.
     *
     * When null (the default), the low-level verify() primitive imposes no
     * restriction, preserving backward compatibility. verifyDocument() applies
     * DEFAULT_SIGNATURE_ALGORITHMS when this is null. Set explicitly (e.g.
     * add XMLSecurityKey::RSA_SHA1) to widen or narrow the accepted set.
     *
     * @var array|null
     */
    public $allowedSignatureAlgorithms = null;

    /**
     * Allowlist of acceptable Reference DigestMethod algorithm URIs.
     *
     * When null (the default), no restriction is imposed by the low-level
     * primitives. verifyDocument() applies DEFAULT_DIGEST_ALGORITHMS when null.
     *
     * @var array|null
     */
    public $allowedDigestAlgorithms = null;

    /**
     * Reject documents that carry a DOCTYPE when locating a Signature.
     *
     * A DOCTYPE has no legitimate role in a signed XML document, but it enables
     * a class of signature-verification bypasses: entity references in ID
     * attributes (e.g. Id="&e;") are resolved by getAttribute() yet are
     * invisible to the XPath "//*[@Id=...]" reference lookup, due to a libxml2
     * hashing bug (same root cause as CVE-2025-23369). The signature then
     * validates against one node while the application reads another. Rejecting
     * any DOCTYPE closes this vector (and entity-expansion DoS) outright.
     *
     * Defaults to true (secure). Set to false ONLY if you fully trust the
     * document source and require DTD support.
     *
     * @var bool
     */
    public $forbidDoctype = true;

    /** @var string|null */
    private $signedInfo = null;

    /** @var DomXPath|null */
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
     * @param null|array $options Optional flags; use 'stripWhitespace' => true for a compact template
     */
    public function __construct($prefix='ds', $options=null)
    {
        $stripWhitespace = false;
        if (is_array($options)) {
            $stripWhitespace = !isset($options['stripWhitespace']) ? false : (bool) $options['stripWhitespace'];
        }
        $template = $stripWhitespace ? self::BASE_TEMPLATE_NOWS : self::BASE_TEMPLATE;
        
        if (! empty($prefix)) {
            $this->prefix = $prefix.':';
            $search = array("<S", "</S", "xmlns=");
            $replace = array("<$prefix:S", "</$prefix:S", "xmlns:$prefix=");
            $template = str_replace($search, $replace, $template);
        }
        $sigdoc = new DOMDocument();
        $sigdoc->loadXML($template);
        $this->sigNode = $sigdoc->documentElement;
    }

    /**
     * Set an Id attribute on the Signature element.
     *
     * @param string $id
     * @return $this
     */
    public function setSignatureId($id)
    {
        $this->sigNode->setAttribute('Id', $id);
        return $this;
    }

    /**
     * Restore pre-4.0 interoperability defaults for signature verification.
     *
     * Use this only when you must accept documents/peers that rely on
     * behaviours 4.0 rejects by default (DOCTYPE, XPath Filtering Transforms,
     * uncapped XPath transform counts). Prefer migrating peers and then
     * removing the call.
     *
     * This does NOT weaken cryptographic checks that are always enforced in
     * 4.0 (SignatureMethod/key algorithm binding, hash_equals compares,
     * fail-closed Reference handling, unknown C14N rejection).
     *
     * @return $this
     */
    public function enableLegacyMode()
    {
        $this->forbidDoctype = false;
        $this->allowXPathTransforms = true;
        $this->maxXPathTransforms = PHP_INT_MAX;
        $this->maxXPathNamespaces = PHP_INT_MAX;
        return $this;
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
    public static function generateGUID($prefix='pfx')
    {
        $uuid = bin2hex(random_bytes(16));
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
     * @param DOMDocument $objDoc
     * @param int $pos
     * @return DOMNode|null
     */
    public function locateSignature($objDoc, $pos=0)
    {
        if ($objDoc instanceof DOMDocument) {
            $doc = $objDoc;
        } else {
            $doc = $objDoc->ownerDocument;
        }
        if ($doc) {
            if ($this->forbidDoctype && $doc->doctype !== null) {
                throw new Exception('A DOCTYPE is not allowed in a document being verified');
            }
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
     * @param null|string $value
     * @return DOMElement
     */
    public function createNewSignNode($name, $value=null)
    {
        $doc = $this->sigNode->ownerDocument;
        if (! is_null($value)) {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix.$name, $value);
        } else {
            $node = $doc->createElementNS(self::XMLDSIGNS, $this->prefix.$name);
        }
        return $node;
    }

    /**
     * @param string $method
     * @throws Exception
     */
    public function setCanonicalMethod($method)
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
            $query = './'.$this->searchpfx.':SignedInfo';
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sinfo = $nodeset->item(0)) {
                $query = './'.$this->searchpfx.':CanonicalizationMethod';
                $nodeset = $xpath->query($query, $sinfo);
                if (! ($canonNode = $nodeset->item(0))) {
                    $canonNode = $this->createNewSignNode('CanonicalizationMethod');
                    $sinfo->insertBefore($canonNode, $sinfo->firstChild);
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
    private function canonicalizeData($node, $canonicalmethod, $arXPath=null, $prefixList=null)
    {
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
            default:
                throw new Exception('Invalid CanonicalizationMethod: '.$canonicalmethod);
        }

        if (is_null($arXPath) && ($node instanceof DOMNode) && ($node->ownerDocument !== null) && $node->isSameNode($node->ownerDocument->documentElement)) {
            /* Check for any PI or comments as they would have been excluded */
            $element = $node;
            while ($refnode = $element->previousSibling) {
                if ($refnode->nodeType == XML_PI_NODE || (($refnode->nodeType == XML_COMMENT_NODE) && $withComments)) {
                    break;
                }
                $element = $refnode;
            }
            if ($refnode == null) {
                $node = $node->ownerDocument;
            }
        }

        $ret = $node->C14N($exclusive, $withComments, $arXPath, $prefixList);
        if ($ret === false) {
            throw new Exception("Canonicalization failed");
        }
        return $ret; 
    }

    /**
     * @return null|string
     */
    public function canonicalizeSignedInfo()
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
     * @throws Exception
     */
    public function calculateDigest($digestAlgorithm, $data, $encode = true)
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
     * @param $refNode
     * @param string $data
     * @return bool
     */
    public function validateDigest($refNode, $data)
    {
        $xpath = new DOMXPath($refNode->ownerDocument);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = 'string(./secdsig:DigestMethod/@Algorithm)';
        $digestAlgorithm = $xpath->evaluate($query, $refNode);
        if ($this->allowedDigestAlgorithms !== null
            && ! in_array($digestAlgorithm, $this->allowedDigestAlgorithms, true)) {
            throw new Exception("DigestMethod algorithm is not allowed: '$digestAlgorithm'");
        }
        $digValue = $this->calculateDigest($digestAlgorithm, $data, false);
        $query = 'string(./secdsig:DigestValue)';
        $digestValue = $xpath->evaluate($query, $refNode);
        return ($digValue !== false && hash_equals($digValue, base64_decode($digestValue)));
    }

    /**
     * @param $refNode
     * @param DOMNode $objData
     * @param bool $includeCommentNodes
     * @return string
     * @throws Exception
     */
    public function processTransforms($refNode, $objData, $includeCommentNodes = true, $signing = false)
    {
        $data = $objData;
        $xpath = new DOMXPath($refNode->ownerDocument);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
        $query = './secdsig:Transforms/secdsig:Transform';
        $nodelist = $xpath->query($query, $refNode);
        $canonicalMethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
        $arXPath = null;
        $prefixList = null;
        $xpathTransformCount = 0;
        foreach ($nodelist AS $transform) {
            $algorithm = $transform->getAttribute("Algorithm");
            switch ($algorithm) {
                case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':

                    if (!$includeCommentNodes) {
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
                                foreach ($pfxlist AS $pfx) {
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
                    /*
                     * Reject attacker-controlled XPath transforms on the
                     * verification path unless explicitly allowed. Signing uses
                     * caller-supplied transforms and is always permitted.
                     */
                    if (! $signing && ! $this->allowXPathTransforms) {
                        throw new Exception(
                            'XPath Transforms are not allowed during verification; set '
                            . 'XMLSecurityDSig::$allowXPathTransforms = true to enable them'
                        );
                    }
                    $xpathTransformCount++;
                    if ($xpathTransformCount > $this->maxXPathTransforms) {
                        throw new Exception(
                            'Too many XPath Transformations found ('.$nodelist->length.') with a max allowed of '.$this->maxXPathTransforms
                        );
                    }
                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'XPath') {
                            $arXPath = array();
                            $arXPath['query'] = '(.//. | .//@* | .//namespace::*)['.$node->nodeValue.']';
                            $arXPath['namespaces'] = array();
                            $nslist = $xpath->query('./namespace::*', $node);
                            foreach ($nslist AS $nsnode) {
                                /* Exclude xml and the default xmlns (empty prefix). */
                                if ($nsnode->localName != "xml" && $nsnode->localName !== '' && $nsnode->localName !== 'xmlns') {
                                    $arXPath['namespaces'][$nsnode->localName] = $nsnode->nodeValue;
                                }
                            }
                            $nsCount = count($arXPath['namespaces']);
                            if ($nsCount > $this->maxXPathNamespaces) {
                                throw new Exception(
                                    'Too many namespaces in XPath Transformation found ('.$nsCount.')  with a max allowed of '.$this->maxXPathNamespaces
                                );
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
     * @param DOMNode $refNode
     * @return bool
     * @throws Exception
     */
    public function processRefNode($refNode)
    {
        $dataObject = null;
        $identifier = null;

        /*
         * Depending on the URI, we may not want to include comments in the result
         * See: http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
         */
        $includeCommentNodes = true;

        if ($uri = $refNode->getAttribute("URI")) {
            $arUrl = parse_url($uri);
            if (! empty($arUrl['path']) || ! empty($arUrl['host']) || ! empty($arUrl['scheme'])) {
                throw new Exception('Reference URI must be a same-document reference');
            }
            if ($identifier = $arUrl['fragment'] ?? null) {

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
                $iDlist = '@Id="'.XPath::filterAttrValue($identifier, XPath::DOUBLE_QUOTE).'"';
                if (is_array($this->idKeys)) {
                    foreach ($this->idKeys as $idKey) {
                        $iDlist .= " or @".XPath::filterAttrName($idKey).'="'.
                            XPath::filterAttrValue($identifier, XPath::DOUBLE_QUOTE).'"';
                    }
                }
                $query = '//*['.$iDlist.']';
                $nodeset = $xPath->query($query);
                if ($nodeset->length === 0) {
                    throw new Exception('Reference URI does not identify a node');
                }
                if ($nodeset->length > 1) {
                    throw new Exception('Reference URI identifies multiple nodes');
                }
                $dataObject = $nodeset->item(0);
            } else {
                $dataObject = $refNode->ownerDocument;
            }
        } else {
            /* This reference identifies the root node with an empty URI. This should
             * not include comments.
             */
            $includeCommentNodes = false;

            $dataObject = $refNode->ownerDocument;
        }

        if (! $dataObject instanceof DOMNode) {
            throw new Exception('Reference URI could not be resolved');
        }

        $data = $this->processTransforms($refNode, $dataObject, $includeCommentNodes);
        if (!$this->validateDigest($refNode, $data)) {
            return false;
        }

        /* Add this node to the list of validated nodes. */
        if (! empty($identifier)) {
            $this->validatedNodes[$identifier] = $dataObject;
        } else {
            $this->validatedNodes[] = $dataObject;
        }

        return true;
    }

    /**
     * @param DOMNode $refNode
     * @return null
     */
    public function getRefNodeID($refNode)
    {
        if ($uri = $refNode->getAttribute("URI")) {
            $arUrl = parse_url($uri);
            if (is_array($arUrl) && empty($arUrl['path'])) {
                if ($identifier = $arUrl['fragment'] ?? null) {
                    return $identifier;
                }
            }
        }
        return null;
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getRefIDs()
    {
        $refids = array();

        $xpath = $this->getXPathObj();
        $query = "./secdsig:SignedInfo[1]/secdsig:Reference";
        $nodeset = $xpath->query($query, $this->sigNode);
        if ($nodeset->length == 0) {
            throw new Exception("Reference nodes not found");
        }
        foreach ($nodeset AS $refNode) {
            $refids[] = $this->getRefNodeID($refNode);
        }
        return $refids;
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function validateReference()
    {
        $docElem = $this->sigNode->ownerDocument->documentElement;
        if (! $docElem->isSameNode($this->sigNode)) {
            if ($this->sigNode->parentNode != null) {
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
        $this->validatedNodes = array();

        foreach ($nodeset AS $refNode) {
            if (! $this->processRefNode($refNode)) {
                /* Clear the list of validated nodes. */
                $this->validatedNodes = null;
                throw new Exception("Reference validation failed");
            }
        }
        return true;
    }

    /**
     * @param DOMNode $sinfoNode
     * @param DOMDocument|DOMElement $node
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
        $transforms_elem = true;

        if (is_array($options)) {
            $prefix = empty($options['prefix']) ? null : $options['prefix'];
            $prefix_ns = empty($options['prefix_ns']) ? null : $options['prefix_ns'];
            $id_name = empty($options['id_name']) ? 'Id' : $options['id_name'];
            $overwrite_id = !isset($options['overwrite']) ? true : (bool) $options['overwrite'];
            $force_uri = !isset($options['force_uri']) ? false : (bool) $options['force_uri'];
            $transforms_elem = !isset($options['transforms_elem']) ? true : (bool) $options['transforms_elem'];
        }

        $attname = $id_name;
        if (! empty($prefix)) {
            $attname = $prefix.':'.$attname;
        }

        $refNode = $this->createNewSignNode('Reference');
        $sinfoNode->appendChild($refNode);

        if (! $node instanceof DOMDocument) {
            $uri = null;
            if (! $overwrite_id) {
                $uri = $prefix_ns ? $node->getAttributeNS($prefix_ns, $id_name) : $node->getAttribute($id_name);
            }
            if (empty($uri)) {
                $uri = self::generateGUID();
                $node->setAttributeNS($prefix_ns, $attname, $uri);
            }
            $refNode->setAttribute("URI", '#'.$uri);
        } elseif ($force_uri) {
            $refNode->setAttribute("URI", '');
        }

        if ($transforms_elem) {
            $transNodes = $this->createNewSignNode('Transforms');
            $refNode->appendChild($transNodes);

            if (is_array($arTransforms)) {
                foreach ($arTransforms AS $transform) {
                    $transNode = $this->createNewSignNode('Transform');
                    $transNodes->appendChild($transNode);
                    if (is_array($transform) &&
                        (! empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116'])) &&
                        (! empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query']))) {
                        $transNode->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
                        $XPathNode = $this->createNewSignNode('XPath', $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query']);
                        $transNode->appendChild($XPathNode);
                        if (! empty($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'])) {
                            foreach ($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'] AS $prefix => $namespace) {
                                $XPathNode->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:$prefix", $namespace);
                            }
                        }
                    } else {
                        $transNode->setAttribute('Algorithm', $transform);
                    }
                }
            } elseif (! empty($this->canonicalMethod)) {
                $transNode = $this->createNewSignNode('Transform');
                $transNodes->appendChild($transNode);
                $transNode->setAttribute('Algorithm', $this->canonicalMethod);
            }
        }

        $canonicalData = $this->processTransforms($refNode, $node, true, true);
        $digValue = $this->calculateDigest($algorithm, $canonicalData);

        $digestMethod = $this->createNewSignNode('DigestMethod');
        $refNode->appendChild($digestMethod);
        $digestMethod->setAttribute('Algorithm', $algorithm);

        $digestValue = $this->createNewSignNode('DigestValue', $digValue);
        $refNode->appendChild($digestValue);
    }

    /**
     * @param DOMDocument|DOMElement $node
     * @param string $algorithm
     * @param null|array $arTransforms
     * @param null|array $options
     */
    public function addReference($node, $algorithm, $arTransforms=null, $options=null)
    {
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
     * @param null|array $arTransforms
     * @param null|array $options
     */
    public function addReferenceList($arNodes, $algorithm, $arTransforms=null, $options=null)
    {
        if ($xpath = $this->getXPathObj()) {
            $query = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sInfo = $nodeset->item(0)) {
                foreach ($arNodes AS $node) {
                    $this->addRefInternal($sInfo, $node, $algorithm, $arTransforms, $options);
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
    public function addObject($data, $mimetype=null, $encoding=null)
    {
        $objNode = $this->createNewSignNode('Object');
        $this->sigNode->appendChild($objNode);
        if (! empty($mimetype)) {
            $objNode->setAttribute('MimeType', $mimetype);
        }
        if (! empty($encoding)) {
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
     * @param null|DOMNode $node
     * @return null|XMLSecurityKey
     */
    public function locateKey($node=null)
    {
        if (empty($node)) {
            $node = $this->sigNode;
        }
        if (! $node instanceof DOMNode) {
            return null;
        }
        if ($doc = $node->ownerDocument) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', self::XMLDSIGNS);
            $query = "string(./secdsig:SignedInfo/secdsig:SignatureMethod/@Algorithm)";
            $algorithm = $xpath->evaluate($query, $node);
            if ($algorithm) {
                try {
                    $objKey = new XMLSecurityKey($algorithm, array('type' => 'public'));
                } catch (Exception $e) {
                    return null;
                }
                return $objKey;
            }
        }
        return null;
    }

    /**
     * Returns an int for all signature algorithms (including HMAC-SHA1):
     *    1 on successful signature verification,
     *    0 when signature verification failed,
     *   -1 if an error occurred during processing.
     *
     * NOTE: be very careful when checking the int return value, because in
     * PHP, -1 will be cast to True when in boolean context. Always check the
     * return value in a strictly typed way, e.g. "$obj->verify(...) === 1".
     *
     * @param XMLSecurityKey $objKey
     * @return int
     * @throws Exception
     */
    public function verify($objKey)
    {
        $doc = $this->sigNode->ownerDocument;
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('secdsig', self::XMLDSIGNS);

        $query = "string(./secdsig:SignedInfo/secdsig:SignatureMethod/@Algorithm)";
        $sigMethod = $xpath->evaluate($query, $this->sigNode);

        /*
         * Always bind the document's declared SignatureMethod to the algorithm
         * of the caller-supplied key. The key's algorithm is fixed by the
         * caller -- or, in the locateKey() flow, derived from the same document
         * -- so a mismatch always signals tampering.
         */
        if ($objKey->type !== $sigMethod) {
            throw new Exception('SignatureMethod algorithm does not match the supplied key type');
        }

        if ($this->allowedSignatureAlgorithms !== null
            && ! in_array($sigMethod, $this->allowedSignatureAlgorithms, true)) {
            throw new Exception("SignatureMethod algorithm is not allowed: '$sigMethod'");
        }

        $query = "string(./secdsig:SignatureValue)";
        $sigValue = $xpath->evaluate($query, $this->sigNode);
        if (empty($sigValue)) {
            throw new Exception("Unable to locate SignatureValue");
        }
        return $objKey->verifySignature($this->signedInfo, base64_decode($sigValue));
    }

    /**
     * Safe, high-level XML signature verification.
     *
     * This is the recommended entry point for relying parties (SAML,
     * WS-Security, etc.). Unlike the low-level primitives, it is safe by
     * default:
     *
     *  - The verification key MUST be supplied by the caller (a pinned key or
     *    trust anchor). The key is NEVER derived from the document's KeyInfo,
     *    so an attacker cannot both supply the message and the key that
     *    verifies it.
     *  - Both the SignatureMethod and every Reference DigestMethod are checked
     *    against an algorithm allowlist. Strong defaults
     *    (DEFAULT_SIGNATURE_ALGORITHMS / DEFAULT_DIGEST_ALGORITHMS) are applied
     *    unless the caller has populated $allowedSignatureAlgorithms /
     *    $allowedDigestAlgorithms explicitly.
     *  - Success is only reported when the SignedInfo signature is valid AND
     *    every Reference digest validated. The set of validated nodes is
     *    returned so callers never have to re-query the document (which would
     *    reintroduce XML Signature Wrapping).
     *
     * @param XMLSecurityKey       $objKey Trusted/pinned verification key.
     * @param DOMDocument|DOMNode  $objDoc Document (or node) to verify.
     * @param int                  $pos    Which Signature element to verify (default: first).
     * @return array Associative array of validated nodes (id => node). Never empty on success.
     * @throws Exception on any verification failure.
     */
    public function verifyDocument($objKey, $objDoc, $pos = 0)
    {
        if (! $objKey instanceof XMLSecurityKey) {
            throw new Exception('A trusted key must be supplied to verifyDocument()');
        }

        if ($this->allowedSignatureAlgorithms === null) {
            $this->allowedSignatureAlgorithms = self::DEFAULT_SIGNATURE_ALGORITHMS;
        }
        if ($this->allowedDigestAlgorithms === null) {
            $this->allowedDigestAlgorithms = self::DEFAULT_DIGEST_ALGORITHMS;
        }

        $this->resetXPathObj();
        if (! $this->locateSignature($objDoc, $pos)) {
            throw new Exception('Cannot locate Signature Node');
        }
        if ($this->canonicalizeSignedInfo() === null) {
            throw new Exception('Cannot canonicalize SignedInfo');
        }

        /* Throws on any unresolved/failed/duplicate reference (fail closed). */
        $this->validateReference();

        if ($this->verify($objKey) !== 1) {
            throw new Exception('Signature validation failed');
        }

        $validatedNodes = $this->getValidatedNodes();
        if (empty($validatedNodes)) {
            throw new Exception('Signature verified but no signed nodes were validated');
        }
        return $validatedNodes;
    }

    /**
     * @param XMLSecurityKey $objKey
     * @param string $data
     * @return mixed|string
     */
    public function signData($objKey, $data)
    {
        return $objKey->signData($data);
    }

    /**
     * @param XMLSecurityKey $objKey
     * @param null|DOMNode $appendToNode
     */
    public function sign($objKey, $appendToNode = null)
    {
        // If we have a parent node append it now so C14N properly works
        if ($appendToNode != null) {
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

    public function appendCert()
    {

    }

    /**
     * @param XMLSecurityKey $objKey
     * @param null|DOMNode $parent
     */
    public function appendKey($objKey, $parent=null)
    {
        $objKey->serializeKey($parent);
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
    public function insertSignature($node, $beforeNode = null)
    {

        $document = $node->ownerDocument;
        $signatureElement = $document->importNode($this->sigNode, true);

        if ($beforeNode == null) {
            return $node->insertBefore($signatureElement);
        } else {
            return $node->insertBefore($signatureElement, $beforeNode);
        }
    }

    /**
     * @param DOMNode $parentNode
     * @param bool $insertBefore
     * @return DOMNode
     */
    public function appendSignature($parentNode, $insertBefore = false)
    {
        $beforeNode = $insertBefore ? $parentNode->firstChild : null;
        return $this->insertSignature($parentNode, $beforeNode);
    }

    /**
     * @param string $cert
     * @param bool $isPEMFormat
     * @return string
     */
    public static function get509XCert($cert, $isPEMFormat=true)
    {
        $certs = self::staticGet509XCerts($cert, $isPEMFormat);
        if (! empty($certs)) {
            return $certs[0];
        }
        return '';
    }

    /**
     * @param string $certs
     * @param bool $isPEMFormat
     * @return array
     */
    public static function staticGet509XCerts($certs, $isPEMFormat=true)
    {
        if ($isPEMFormat) {
            $data = '';
            $certlist = array();
            $arCert = explode("\n", $certs);
            $inData = false;
            foreach ($arCert AS $curData) {
                if (! $inData) {
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
            return array($certs);
        }
    }

    /**
     * Fetch a certificate from a URL with SSRF protections.
     *
     * Only http/https are permitted by default; file:// must be explicitly
     * enabled via $options['allow_file_scheme']. For http/https the host is
     * resolved and every resulting IP address is validated to be public
     * (rejecting loopback, private, link-local, reserved and CGNAT ranges),
     * and HTTP redirects are disabled so a public URL cannot bounce to an
     * internal one.
     *
     * @param string $url
     * @param null|array $options
     * @return string
     * @throws Exception
     */
    private static function fetchCertFromURL($url, $options = null)
    {
        $allowFile = is_array($options) && ! empty($options['allow_file_scheme']);
        $parts = parse_url($url);
        if ($parts === false || empty($parts['scheme'])) {
            throw new Exception('Invalid certificate URL');
        }
        $scheme = strtolower($parts['scheme']);

        if ($scheme === 'file') {
            if (! $allowFile) {
                throw new Exception('file:// certificate URLs are disabled');
            }
            $data = file_get_contents($url);
            if ($data === false) {
                throw new Exception('Unable to load certificate from URL');
            }
            return $data;
        }

        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new Exception('Unsupported certificate URL scheme');
        }

        $host = isset($parts['host']) ? trim($parts['host'], '[]') : '';
        if ($host === '') {
            throw new Exception('Certificate URL host is not allowed');
        }
        $ips = self::assertPublicHost($host);

        /*
         * Pin the connection to an already-validated IP so a DNS rebinding
         * between the SSRF check and the fetch cannot reach a private address.
         * Preserve the original Host / TLS peer name for virtual hosting and
         * certificate verification.
         */
        $pinnedIp = $ips[0];
        $port = isset($parts['port']) ? (int) $parts['port'] : ($scheme === 'https' ? 443 : 80);
        $path = isset($parts['path']) ? $parts['path'] : '/';
        if (isset($parts['query'])) {
            $path .= '?'.$parts['query'];
        }
        if (strpos($pinnedIp, ':') !== false) {
            $authority = '['.$pinnedIp.']:'.$port;
        } else {
            $authority = $pinnedIp.':'.$port;
        }
        $fetchUrl = $scheme.'://'.$authority.$path;

        $headers = 'Host: '.$host."\r\n";
        $streamOpts = array(
            'follow_location' => 0,
            'max_redirects' => 0,
            'timeout' => 10,
            'header' => $headers,
        );
        $sslOpts = array(
            'peer_name' => $host,
            'SNI_enabled' => true,
            'verify_peer' => true,
            'verify_peer_name' => true,
        );
        $context = stream_context_create(array(
            'http' => $streamOpts,
            'https' => $streamOpts,
            'ssl' => $sslOpts,
        ));
        $data = file_get_contents($fetchUrl, false, $context);
        if ($data === false) {
            throw new Exception('Unable to load certificate from URL');
        }
        return $data;
    }

    /**
     * Ensure a host resolves only to public IP addresses (SSRF guard).
     *
     * @param string $host Hostname or IP literal (IPv6 without brackets).
     * @return string[] Validated public IP addresses for this host.
     * @throws Exception when the host cannot be resolved or maps to a
     *                   non-public address.
     */
    private static function assertPublicHost($host)
    {
        $ips = array();
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips[] = $host;
        } else {
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            if (is_array($records)) {
                foreach ($records as $record) {
                    if (! empty($record['ip'])) {
                        $ips[] = $record['ip'];
                    }
                    if (! empty($record['ipv6'])) {
                        $ips[] = $record['ipv6'];
                    }
                }
            }
            if (empty($ips)) {
                $resolved = gethostbyname($host);
                if ($resolved !== $host) {
                    $ips[] = $resolved;
                }
            }
        }

        if (empty($ips)) {
            throw new Exception('Unable to resolve certificate URL host');
        }

        foreach ($ips as $ip) {
            if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                throw new Exception('Certificate URL host is not allowed');
            }
            /* PHP's reserved-range flag misses CGNAT (100.64.0.0/10). */
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $long = ip2long($ip);
                if ($long !== false && ($long & 0xffc00000) === (ip2long('100.64.0.0') & 0xffc00000)) {
                    throw new Exception('Certificate URL host is not allowed');
                }
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * @param DOMElement $parentRef
     * @param string $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param null|DOMXPath $xpath
     * @param null|array $options
     * @throws Exception
     */
    public static function staticAdd509Cert($parentRef, $cert, $isPEMFormat=true, $isURL=false, $xpath=null, $options=null)
    {
        if ($isURL) {
            $cert = self::fetchCertFromURL($cert, $options);
        }
        if (! $parentRef instanceof DOMElement) {
            throw new Exception('Invalid parent Node parameter');
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
        if (! $keyInfo) {
            $pfx = $parentRef->lookupPrefix(self::XMLDSIGNS);
            if (! empty($pfx)) {
                $dsig_pfx = $pfx.":";
            }
            $inserted = false;
            $keyInfo = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'KeyInfo');

            $query = "./secdsig:Object";
            $nodeset = $xpath->query($query, $parentRef);
            if ($sObject = $nodeset->item(0)) {
                $sObject->parentNode->insertBefore($keyInfo, $sObject);
                $inserted = true;
            }

            if (! $inserted) {
                $parentRef->appendChild($keyInfo);
            }
        } else {
            $pfx = $keyInfo->lookupPrefix(self::XMLDSIGNS);
            if (! empty($pfx)) {
                $dsig_pfx = $pfx.":";
            }
        }

        // Add all certs if there are more than one
        $certs = self::staticGet509XCerts($cert, $isPEMFormat);

        // Attach X509 data node
        $x509DataNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'X509Data');
        $keyInfo->appendChild($x509DataNode);

        $issuerSerial = false;
        $subjectName = false;
        if (is_array($options)) {
            if (! empty($options['issuerSerial'])) {
                $issuerSerial = true;
            }
            if (! empty($options['subjectName'])) {
                $subjectName = true;
            }
        }

        // Attach all certificate nodes and any additional data
        foreach ($certs as $X509Cert) {
            if ($issuerSerial || $subjectName) {
                $pem = "-----BEGIN CERTIFICATE-----\n".chunk_split($X509Cert, 64, "\n")."-----END CERTIFICATE-----\n";
                $x509 = new X509();
                if ($certData = $x509->loadX509($pem)) {
                    if ($subjectName) {
                        $subjectNameValue = self::getX509NameString($x509, false);
                        if ($subjectNameValue !== null) {
                            $x509SubjectNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'X509SubjectName', $subjectNameValue);
                            $x509DataNode->appendChild($x509SubjectNode);
                        }
                    }
                    if ($issuerSerial) {
                        $issuerName = self::getX509NameString($x509, true);
                        $serialNumber = self::getX509SerialNumber($certData);
                        if ($issuerName !== null && $serialNumber !== null) {
                            $x509IssuerNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'X509IssuerSerial');
                            $x509DataNode->appendChild($x509IssuerNode);

                            $x509Node = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'X509IssuerName', $issuerName);
                            $x509IssuerNode->appendChild($x509Node);
                            $x509Node = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'X509SerialNumber', $serialNumber);
                            $x509IssuerNode->appendChild($x509Node);
                        }
                    }
                }

            }
            $x509CertNode = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'X509Certificate', $X509Cert);
            $x509DataNode->appendChild($x509CertNode);
        }
    }

    /**
     * Format an X.509 DN in openssl_x509_parse-compatible reverse RDN order.
     *
     * @param X509 $x509
     * @param bool $issuer
     * @return string|null
     */
    private static function getX509NameString(X509 $x509, $issuer)
    {
        $dnArray = $issuer ? $x509->getIssuerDN(X509::DN_OPENSSL) : $x509->getDN(X509::DN_OPENSSL);
        if (! is_array($dnArray) || empty($dnArray)) {
            return null;
        }

        $parts = array();
        foreach ($dnArray as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $valueElement) {
                    array_unshift($parts, "$key=$valueElement");
                }
            } else {
                array_unshift($parts, "$key=$value");
            }
        }
        return implode(',', $parts);
    }

    /**
     * @param array $certData
     * @return string|null
     */
    private static function getX509SerialNumber(array $certData)
    {
        if (! isset($certData['tbsCertificate']['serialNumber'])) {
            return null;
        }
        $serial = $certData['tbsCertificate']['serialNumber'];
        if (is_object($serial) && method_exists($serial, 'toString')) {
            return $serial->toString();
        }
        return (string) $serial;
    }

    /**
     * @param string $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param null|array $options
     */
    public function add509Cert($cert, $isPEMFormat=true, $isURL=false, $options=null)
    {
        if ($xpath = $this->getXPathObj()) {
            static::staticAdd509Cert($this->sigNode, $cert, $isPEMFormat, $isURL, $xpath, $options);
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
    public function appendToKeyInfo($node)
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
        if (! $keyInfo) {
            $dsig_pfx = '';
            $pfx = $parentRef->lookupPrefix(self::XMLDSIGNS);
            if (! empty($pfx)) {
                $dsig_pfx = $pfx.":";
            }
            $inserted = false;
            $keyInfo = $baseDoc->createElementNS(self::XMLDSIGNS, $dsig_pfx.'KeyInfo');

            $query = "./secdsig:Object";
            $nodeset = $xpath->query($query, $parentRef);
            if ($sObject = $nodeset->item(0)) {
                $sObject->parentNode->insertBefore($keyInfo, $sObject);
                $inserted = true;
            }

            if (! $inserted) {
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
    public function getValidatedNodes()
    {
        return $this->validatedNodes;
    }
}
