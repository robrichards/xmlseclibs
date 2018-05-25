<?php

namespace SimpleSAML\XMLSec;

use SimpleSAML\XMLSec\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSec\Backend\SignatureBackend;
use SimpleSAML\XMLSec\Constants as C;
use SimpleSAML\XMLSec\Exception\InvalidArgumentException;
use SimpleSAML\XMLSec\Exception\NoSignatureFound;
use SimpleSAML\XMLSec\Exception\RuntimeException;
use SimpleSAML\XMLSec\Key\AbstractKey;
use SimpleSAML\XMLSec\Key\X509Certificate;
use SimpleSAML\XMLSec\Utils\DOMDocumentFactory;
use SimpleSAML\XMLSec\Utils\Security as Sec;

/**
 * Class implementing XML digital signatures.
 *
 * @package SimpleSAML\XMLSec
 */
class Signature
{
    /** @var array */
    public $idNS = [];

    /** @var array */
    public $idKeys = [];

    /** @var SignatureBackend */
    protected $backend;

    /** @var \DOMElement */
    protected $root;

    /** @var \DOMElement */
    protected $sigNode;

    /** @var \DOMElement */
    protected $sigMethodNode;

    /** @var \DOMElement */
    protected $c14nMethodNode;

    /** @var \DOMElement */
    protected $sigInfoNode;

    /** @var \DOMElement */
    protected $objectNode;

    /** @var string */
    protected $signfo;

    /** @var string */
    protected $sigAlg;

    /** @var \DOMElement[] */
    protected $verifiedElements = [];

    /** @var string */
    protected $c14nMethod = C::C14N_EXCLUSIVE_WITHOUT_COMMENTS;

    /** @var string */
    protected $nsPrefix = 'ds:';

    /** @var array */
    protected $algBlacklist = [
        C::SIG_RSA_SHA1,
        C::SIG_HMAC_SHA1,
    ];

    /** @var array */
    protected $references = [];

    /** @var bool */
    protected $enveloping = false;


    /**
     * Signature constructor.
     *
     * @param \DOMElement|string $root The DOM element or a string of data we want to sign.
     * @param SignatureBackend $backend The backend to use to generate or verify signatures. See individual algorithms
     * for defaults.
     */
    public function __construct($root, SignatureBackend $backend = null)
    {
        if ($backend !== null) {
            $this->backend = $backend;
        }

        $this->initSignature();

        if (is_string($root)) {
            $this->root = $this->addObject($root);
            $this->enveloping = true;
        } else {
            $this->root = $root;
        }
    }


    /**
     * Add an object element to the signature containing the given data.
     *
     * @param \DOMElement|string $data The data we want to envelope inside the signature.
     * @param string|null $mimetype An optional mime type to specify.
     * @param string|null $encoding An optional encoding to specify.
     *
     * @return \DOMElement The resulting object element added to the signature.
     */
    public function addObject($data, $mimetype = null, $encoding = null)
    {
        if ($this->objectNode === null) {
            $this->objectNode = $this->createElement('Object');
            $this->sigNode->appendChild($this->objectNode);
        }

        if (is_string($mimetype) && !empty($mimetype)) {
            $this->objectNode->setAttribute('MimeType', $mimetype);
        }

        if (is_string($encoding) && !empty($encoding)) {
            $this->objectNode->setAttribute('Encoding', $encoding);
        }

        if ($data instanceof \DOMElement) {
            $this->objectNode->appendChild($this->sigNode->ownerDocument->importNode($data, true));
        } else {
            $this->objectNode->appendChild($this->sigNode->ownerDocument->createTextNode($data));
        }

        return $this->objectNode;
    }


    /**
     * Add a reference to a given node (an element or a document).
     *
     * @param \DOMNode $node A DOMElement that we want to sign, or a DOMDocument if we want to sign the entire document.
     * @param string $alg The identifier of a supported digest algorithm to use when processing this reference.
     * @param array $transforms An array containing a list of transforms that must be applied to the reference.
     * Optional.
     * @param array $options An array containing a set of options for this reference. Optional. Supported options are:
     *   - prefix (string): the XML prefix used in the element being referenced. Defaults to none (no prefix used).
     *
     *   - prefix_ns (string): the namespace associated with the given prefix. Defaults to none (no prefix used).
     *
     *   - id_name (string): the name of the "id" attribute in the referenced element. Defaults to "Id".
     *
     *   - force_uri (boolean): Whether to explicitly add a URI attribute to the reference when referencing a
     *     DOMDocument or not. Defaults to true. If force_uri is false and $node is a DOMDocument, the URI attribute
     *     will be completely omitted.
     *
     *   - overwrite (boolean): Whether to overwrite the identifier existing in the element referenced with a new,
     *     random one, or not. Defaults to true.
     *
     * @throws InvalidArgumentException If $node is not an instance of DOMDocument or DOMElement.
     */
    public function addReference(\DOMNode $node, $alg, array $transforms = [], array $options = [])
    {
        if (!in_array(get_class($node), ['DOMDocument', 'DOMElement'])) {
            throw new InvalidArgumentException('Only references to the DOM document or elements are allowed.');
        }

        $prefix = @$options['prefix'] ?: null;
        $prefixNS = @$options['prefix_ns'] ?: null;
        $idName = @$options['id_name'] ?: 'Id';
        $attrName = $prefix ? $prefix.':'.$idName : $idName;
        $forceURI = true;
        if (isset($options['force_uri'])) {
            $forceURI = $options['force_uri'];
        }
        $overwrite = true;
        if (isset($options['overwrite'])) {
            $overwrite = $options['overwrite'];
        }

        $reference = $this->createElement('Reference');
        $this->sigInfoNode->appendChild($reference);

        // register reference
        $includeCommentNodes = false;
        if ($node instanceof \DOMElement) {
            $uri = null;
            /** @var \DOMElement $node */
            if (!$overwrite) {
                $uri = $prefixNS ? $node->getAttributeNS($prefixNS, $idName) : $node->getAttribute($idName);
            }
            if (empty($uri)) {
                $uri = Utils\Random::generateGUID();
                $node->setAttributeNS($prefixNS, $attrName, $uri);
            }

            if (in_array(C::C14N_EXCLUSIVE_WITH_COMMENTS, $transforms) ||
                in_array(C::C14N_INCLUSIVE_WITH_COMMENTS, $transforms)
            ) {
                $includeCommentNodes = true;
                $reference->setAttribute('URI', "#xpointer($attrName('$uri'))");
            } else {
                $reference->setAttribute('URI', '#'.$uri);
            }
        } elseif ($forceURI) {
            // $node is a \DOMDocument, should add a reference to the root element (enveloped signature)
            if (in_array($this->c14nMethod, [C::C14N_INCLUSIVE_WITH_COMMENTS, C::C14N_EXCLUSIVE_WITH_COMMENTS])) {
                // if we want to use a C14N method that includes comments, the URI must be an xpointer
                $reference->setAttribute('URI', '#xpointer(/)');
            } else {
                // C14N without comments, we can set an empty URI
                $reference->setAttribute('URI', '');
            }
        }

        // apply and register transforms
        $transformList = $this->createElement('Transforms');
        $reference->appendChild($transformList);

        if (!empty($transforms)) {
            foreach ($transforms as $transform) {
                $transformNode = $this->createElement('Transform');
                $transformList->appendChild($transformNode);

                if (is_array($transform) && !empty($transform[C::XPATH_URI]['query'])) {
                    $transformNode->setAttribute('Algorithm', C::XPATH_URI);
                    $xpNode = $this->createElement('XPath', $transform[C::XPATH_URI]['query']);
                    $transformNode->appendChild($xpNode);
                } else {
                    $transformNode->setAttribute('Algorithm', $transform);
                }
            }
        } elseif (!empty($this->c14nMethod)) {
            $transformNode = $this->createElement('Transform');
            $transformList->appendChild($transformNode);
            $transformNode->setAttribute('Algorithm', $this->c14nMethod);
        }

        $canonicalData = $this->processTransforms($reference, $node, $includeCommentNodes);
        $digest = $this->hash($alg, $canonicalData);

        $digestMethod = $this->createElement('DigestMethod');
        $reference->appendChild($digestMethod);
        $digestMethod->setAttribute('Algorithm', $alg);

        $digestValue = $this->createElement('DigestValue', $digest);
        $reference->appendChild($digestValue);

        if (!in_array($node, $this->references)) {
            $this->references[] = $node;
        }
    }


    /**
     * Add a set of references to the signature.
     *
     * @param \DOMNode[] $nodes An array of DOMNode objects to be referred in the signature.
     * @param string $alg The identifier of the digest algorithm to use.
     * @param array $transforms An array of transforms to apply to each reference.
     * @param array $options An array of options.
     *
     * @throws InvalidArgumentException If any of the nodes in the $nodes array is not an instance of DOMDocument or
     * DOMElement.
     *
     * @see addReference()
     */
    public function addReferences($nodes, $alg, array $transforms = [], $options = [])
    {
        foreach ($nodes as $node) {
            $this->addReference($node, $alg, $transforms, $options);
        }
    }


    /**
     * Attach one or more X509 certificates to the signature.
     *
     * @param X509Certificate|X509Certificate[] $certs An X509Certificate object or an array of them.
     * @param boolean $addSubject Whether to add the subject of the certificate or not.
     * @param string|false $digest A digest algorithm identifier if the digest of the certificate should be added. False
     * otherwise.
     * @param boolean $addIssuerSerial Whether to add the serial number of the issuer or not.
     *
     * @throws InvalidArgumentException If $certs is not a X509Certificate object or an array of them.
     */
    public function addX509Certificates($certs, $addSubject = false, $digest = false, $addIssuerSerial = false)
    {
        if (is_array($certs) && !$certs instanceof X509Certificate) {
            throw new InvalidArgumentException(
                'Passed certificates must be either an X509Certificate or a list of them'
            );
        }
        if ($certs instanceof X509Certificate) {
            $certs = [$certs];
        }

        $keyInfoNode = $this->createElement('KeyInfo');
        $certDataNode = $this->createElement('X509Data');
        $keyInfoNode->appendChild($certDataNode);

        if ($this->objectNode === null) {
            $this->sigNode->appendChild($keyInfoNode);
        } else {
            $this->sigNode->insertBefore($keyInfoNode, $this->objectNode);
        }

        foreach ($certs as $cert) {
            if (!$cert instanceof X509Certificate) {
                throw new InvalidArgumentException(
                    'The $certs array can only contain X509Certificate objects'
                );
            }
            $details = $cert->getCertificateDetails();

            if ($addSubject && isset($details['subject'])) {
                // add subject
                $subjectNameValue = $details['issuer'];
                if (is_array($details['subject'])) {
                    $parts = [];
                    foreach ($details['subject'] as $key => $value) {
                        if (is_array($value)) {
                            foreach ($value as $valueElement) {
                                array_unshift($parts, $key.'='.$valueElement);
                            }
                        } else {
                            array_unshift($parts, $key.'='.$value);
                        }
                    }
                    $subjectNameValue = implode(',', $parts);
                }
                $x509SubjectNode = $this->createElement('X509SubjectName', $subjectNameValue);
                $certDataNode->appendChild($x509SubjectNode);
            }

            if ($digest !== false) {
                // add certificate digest
                $fingerprint = base64_encode(hex2bin($cert->getRawThumbprint($digest)));
                $x509DigestNode = $this->createElement('X509Digest', $fingerprint, C::XMLDSIG11NS, 'dsig11');
                $x509DigestNode->setAttribute('Algorithm', $digest);
                $certDataNode->appendChild($x509DigestNode);
            }

            if ($addIssuerSerial && isset($details['issuer']) && isset($details['serialNumber'])) {
                if (is_array($details['issuer'])) {
                    $parts = [];
                    foreach ($details['issuer'] as $key => $value) {
                        array_unshift($parts, $key.'='.$value);
                    }
                    $issuerName = implode(',', $parts);
                } else {
                    $issuerName = $details['issuer'];
                }

                $x509IssuerNode = $this->createElement('X509IssuerSerial');
                $certDataNode->appendChild($x509IssuerNode);

                $x509IssuerNameNode = $this->createElement('X509IssuerName', $issuerName);
                $x509IssuerNode->appendChild($x509IssuerNameNode);

                $x509SerialNumberNode = $this->createElement('X509SerialNumber', $details['serialNumber']);
                $x509IssuerNode->appendChild($x509SerialNumberNode);
            }

            $pem_lines = explode("\n", trim($cert->getCertificate()));
            array_shift($pem_lines);
            array_pop($pem_lines);
            $pem = join($pem_lines);
            $x509CertNode = $this->createElement('X509Certificate', $pem);
            $certDataNode->appendChild($x509CertNode);
        }
    }


    /**
     * Append a signature as the last child of the signed element.
     *
     * @return \DOMNode The appended signature.
     */
    public function append()
    {
        return $this->insert();
    }


    /**
     * Use this signature as an enveloping signature, effectively adding the signed data to a ds:Object element.
     *
     * @param string|null $mimetype The mime type corresponding to the signed data.
     * @param string|null $encoding The encoding corresponding to the signed data.
     */
    public function envelop($mimetype = null, $encoding = null)
    {
        $this->root = $this->addObject($this->root, $mimetype, $encoding);
    }


    /**
     * Build a new XML digital signature from a given document or node.
     *
     * @param \DOMNode $node The DOMDocument or DOMElement that contains the signature.
     *
     * @return Signature A Signature object corresponding to the signature present in the given DOM document or element.
     *
     * @throws InvalidArgumentException If $node is not an instance of DOMDocument or DOMElement.
     * @throws RuntimeException If there is no signature in the $node.
     */
    public static function fromXML(\DOMNode $node)
    {
        if (!in_array(get_class($node), ['DOMElement', 'DOMDocument'])) {
            throw new InvalidArgumentException('Signatures can only be created from DOM documents or elements');
        }

        $signature = self::findSignature($node);
        if ($node instanceof \DOMDocument) {
            $node = $node->documentElement;
        }
        $dsig = new self($node);
        $dsig->setSignatureElement($signature);
        return $dsig;
    }


    /**
     * Obtain the list of currently blacklisted algorithms.
     *
     * Signatures using blacklisted algorithms cannot be created or verified.
     *
     * @return array An array containing the identifiers of the algorithms blacklisted currently.
     */
    public function getBlacklistedAlgorithms()
    {
        return $this->algBlacklist;
    }


    /**
     * Get the list of namespaces to designate ID attributes.
     *
     * @return array An array of strings with the namespaces used in ID attributes.
     */
    public function getIdNamespaces()
    {
        return $this->idNS;
    }


    /**
     * Get the prefix to designate the XML digital signature namespace currently configured.
     *
     * @return string The prefix used in this signature.
     */
    public function getPrefix()
    {
        return rtrim($this->nsPrefix, ':');
    }


    /**
     * Get a list of attributes used as an ID.
     *
     * @return array An array of strings with the attributes used as an ID.
     */
    public function getIdAttributes()
    {
        return $this->idKeys;
    }


    /**
     * Get the root configured for this signature.
     *
     * This will be the signed element, whether that's a user-provided XML element or a ds:Object element containing
     * the actual data (which can in turn be either XML or not).
     *
     * @return \DOMElement The root element for this signature.
     */
    public function getRoot()
    {
        return $this->root;
    }


    /**
     * Get the identifier of the algorithm used in this signature.
     *
     * @return string The identifier of the algorithm used in this signature.
     */
    public function getSignatureMethod()
    {
        return $this->sigAlg;
    }


    /**
     * Get a list of elements verified by this signature.
     *
     * The elements in this list are referenced by the signature and the references verified to be correct. However,
     * this doesn't mean the signature is valid, only that the references were so.
     *
     * Note that the list returned will be empty unless verify() has been called before.
     *
     * @return \DOMElement[] A list of elements correctly referenced by this signature. An empty list of verify() has
     * not been called yet, or if the references couldn't be verified.
     */
    public function getVerifiedElements()
    {
        return $this->verifiedElements;
    }


    /**
     * Insert a signature as a child of the signed element, optionally before a given element.
     *
     * @param \DOMElement|false $before An optional DOM element the signature should be prepended to.
     *
     * @return \DOMNode The inserted signature.
     *
     * @throws RuntimeException If this signature is in enveloping mode.
     */
    public function insert($before = false)
    {
        if ($this->enveloping) {
            throw new RuntimeException('Cannot insert the signature in the object it is enveloping.');
        }

        $signature = $this->root->ownerDocument->importNode($this->sigNode, true);

        if ($before instanceof \DOMElement) {
            return $this->root->insertBefore($signature, $before);
        }
        return $this->root->insertBefore($signature);
    }


    /**
     * Prepend a signature as the first child of the signed element.
     *
     * @return \DOMNode The prepended signature.
     */
    public function prepend()
    {
        foreach ($this->root->childNodes as $child) {
            // look for the first child element, if any
            if ($child instanceof \DOMElement) {
                return $this->insert($child);
            }
        }
        return $this->append();
    }


    /**
     * Set the backend to create or verify signatures.
     *
     * @param SignatureBackend $backend The SignatureBackend implementation to use. See individual algorithms for
     * details about the default backends used.
     */
    public function setBackend(SignatureBackend $backend)
    {
        $this->backend = $backend;
    }


    /**
     * Set the list of currently blacklisted algorithms.
     *
     * Signatures using blacklisted algorithms cannot be created or verified.
     *
     * @param array $algs An array containing the identifiers of the algorithms to blacklist.
     */
    public function setBlacklistedAlgorithms($algs)
    {
        $this->algBlacklist = $algs;
    }


    /**
     * Set the canonicalization method used in this signature.
     *
     * Note that exclusive canonicalization without comments is used by default, so it's not necessary to call
     * setCanonicalizationMethod() if that canonicalization method is desired.
     *
     * @param string $method The identifier of the canonicalization method to use.
     *
     * @throws InvalidArgumentException If $method is not a valid identifier of a supported canonicalization method.
     */
    public function setCanonicalizationMethod($method)
    {
        if (!in_array($method, [
            C::C14N_EXCLUSIVE_WITH_COMMENTS,
            C::C14N_EXCLUSIVE_WITHOUT_COMMENTS,
            C::C14N_INCLUSIVE_WITH_COMMENTS,
            C::C14N_INCLUSIVE_WITHOUT_COMMENTS
        ])) {
            throw new InvalidArgumentException('Invalid canonicalization method');
        }
        $this->c14nMethod = $method;
        $this->c14nMethodNode->setAttribute('Algorithm', $method);
    }


    /**
     * Set the encoding for the signed contents in an enveloping signature.
     *
     * @param string $encoding The encoding used in the signed contents.
     *
     * @throws RuntimeException If this is not an enveloping signature.
     */
    public function setEncoding($encoding)
    {
        if (!$this->$this->enveloping) {
            throw new RuntimeException('Cannot set the encoding for non-enveloping signatures.');
        }
        $this->root->setAttribute('Encoding', $encoding);
    }


    /**
     * Set a list of attributes used as an ID.
     *
     * @param array $keys An array of strings with the attributes used as an ID.
     */
    public function setIdAttributes(array $keys)
    {
        $this->idKeys = $keys;
    }


    /**
     * Set the list of namespaces to designate ID attributes.
     *
     * @param array $namespaces An array of strings with the namespaces used in ID attributes.
     */
    public function setIdNamespaces(array $namespaces)
    {
        $this->idNS = $namespaces;
    }


    /**
     * Set the mime type for the signed contents in an enveloping signature.
     *
     * @param string $mimetype The mime type of the signed contents.
     *
     * @throws RuntimeException If this is not an enveloping signature.
     */
    public function setMimeType($mimetype)
    {
        if (!$this->enveloping) {
            throw new RuntimeException('Cannot set the mime type for non-enveloping signatures.');
        }
        $this->root->setAttribute('MimeType', $mimetype);
    }


    /**
     * Set the prefix to designate the XML digital signature namespace currently configured.
     *
     * @param string|false $prefix The prefix to use in this signature, or false to not use any prefix.
     */
    public function setPrefix($prefix)
    {
        if (!is_string($prefix) || empty($prefix)) {
            $this->nsPrefix = '';
        } else {
            if ($this->nsPrefix === $prefix.':') {
                return;
            }
            $this->nsPrefix = $prefix.':';
        }

        $this->sigNode->ownerDocument->removeChild($this->sigNode);
        $this->initSignature();
    }


    /**
     * Set the signature element to a given one, and initialize the signature from there.
     *
     * @param \DOMElement $element A DOM element containing an XML signature.
     *
     * @throws RuntimeException If the element does not correspond to an XML signature or it is malformed (e.g. there
     * are missing mandatory elements or attributes).
     */
    public function setSignatureElement(\DOMElement $element)
    {
        if ($element->localName !== 'Signature' || $element->namespaceURI !== C::XMLDSIGNS) {
            throw new RuntimeException('Node is not an XML signature');
        }
        $this->sigNode = $element;

        $xp = self::getXPath($this->sigNode->ownerDocument);

        $signedInfoNodes = $xp->query('./ds:SignedInfo', $this->sigNode);
        if (count($signedInfoNodes) < 1) {
            throw new RuntimeException('There is no SignedInfo element in the signature');
        }
        $this->sigInfoNode = $signedInfoNodes->item(0);


        $this->sigAlg = $xp->evaluate('string(./ds:SignedInfo/ds:SignatureMethod/@Algorithm)', $this->sigNode);
        if (empty($this->sigAlg)) {
            throw new RuntimeException('Unable to determine SignatureMethod');
        }

        $c14nMethodNodes = $xp->query('./ds:CanonicalizationMethod', $this->sigInfoNode);
        if (count($c14nMethodNodes) < 1) {
            throw new RuntimeException('There is no CanonicalizationMethod in the signature');
        }

        $this->c14nMethodNode = $c14nMethodNodes->item(0);
        if (!$this->c14nMethodNode->hasAttribute('Algorithm')) {
            throw new RuntimeException('CanonicalizationMethod missing required Algorithm attribute');
        }
        $this->c14nMethod = $this->c14nMethodNode->getAttribute('Algorithm');
    }


    /**
     * Sign the document or element.
     *
     * This method will finish the signature process. It will create an XML signature valid for document or elements
     * specified previously with addReference() or addReferences(). If none of those methods have been called previous
     * to calling sign() (there are no references in the signature), the $root passed during construction of the
     * Signature object will be referenced automatically.
     *
     * @param AbstractKey $key The key to use for signing. Bear in mind that the type of this key must be compatible
     * with the types of key accepted by the algorithm specified in $alg.
     * @param string $alg The identifier of the signature algorithm to use. See \SimpleSAML\XMLSec\Constants.
     * @param bool $appendToNode Whether to append the signature as the last child of the root element or not.
     *
     * @throws InvalidArgumentException If $appendToNode is true and this is an enveloping signature.
     */
    public function sign(AbstractKey $key, $alg, $appendToNode = false)
    {
        if ($this->enveloping && $appendToNode) {
            throw new InvalidArgumentException(
                'Cannot append the signature, we are in enveloping mode.'
            );
        }

        $this->sigMethodNode->setAttribute('Algorithm', $alg);
        $factory = new SignatureAlgorithmFactory($this->algBlacklist);
        $signer = $factory->getAlgorithm($alg, $key);
        $digestAlg = $factory->getDigestAlgorithm();

        if (empty($this->references)) {
            // no references have been added, ref root
            $transforms = [];
            if (!$this->enveloping) {
                $transforms[] = C::XMLDSIG_ENVELOPED;
            }
            $this->addReference($this->root->ownerDocument, $digestAlg, $transforms, []);
        }

        if ($appendToNode) {
            $this->sigNode = $this->append();
        } elseif (in_array($this->c14nMethod, [C::C14N_INCLUSIVE_WITHOUT_COMMENTS, C::C14N_INCLUSIVE_WITH_COMMENTS])) {
            // append Signature to root node for inclusive canonicalization
            $restoreSigNode = $this->sigNode;
            $this->sigNode = $this->prepend();
        }

        $sigValue = base64_encode($signer->sign($this->canonicalizeData($this->sigInfoNode, $this->c14nMethod)));

        // remove Signature from node if we added it for c14n
        if (!$appendToNode &&
            in_array($this->c14nMethod, [C::C14N_INCLUSIVE_WITHOUT_COMMENTS, C::C14N_INCLUSIVE_WITH_COMMENTS])
        ) { // remove from root in case we added it for inclusive canonicalization
            $this->root->removeChild($this->root->lastChild);
            /** @var \DOMElement $restoreSigNode */
            $this->sigNode = $restoreSigNode;
        }

        $sigValueNode = $this->createElement('SignatureValue', $sigValue);
        if ($this->sigInfoNode->nextSibling) {
            $this->sigInfoNode->nextSibling->parentNode->insertBefore($sigValueNode, $this->sigInfoNode->nextSibling);
        } else {
            $this->sigNode->appendChild($sigValueNode);
        }
    }


    /**
     * Verify this signature with a given key.
     *
     * @param AbstractKey $key The key to use to verify this signature.
     *
     * @return bool True if the signature can be verified with $key, false otherwise.
     *
     * @throws RuntimeException If there is no SignatureValue in the signature, or we couldn't verify all the
     * references.
     */
    public function verify(AbstractKey $key)
    {
        $xp = self::getXPath($this->sigNode->ownerDocument);
        $sigval = $xp->evaluate('string(./ds:SignatureValue)', $this->sigNode);
        if (empty($sigval)) {
            throw new RuntimeException('Unable to locate SignatureValue');
        }

        $siginfo = $this->canonicalizeData($this->sigInfoNode, $this->c14nMethod);
        if (!$this->validateReferences()) {
            throw new RuntimeException('Unable to verify all references');
        }

        $factory = new SignatureAlgorithmFactory($this->algBlacklist);
        return $factory->getAlgorithm($this->sigAlg, $key)->verify($siginfo, base64_decode($sigval));
    }


    /**
     * Canonicalize any given node.
     *
     * @param \DOMNode $node The DOM node that needs canonicalization.
     * @param string $c14nMethod The identifier of the canonicalization algorithm to use.
     * See \SimpleSAML\XMLSec\Constants.
     * @param array|null $xpaths An array of xpaths to filter the nodes by. Defaults to null (no filters).
     * @param array|null $prefixes An array of namespace prefixes to filter the nodes by. Defaults to null (no filters).
     *
     * @return string The canonical representation of the given DOM node, according to the algorithm requested.
     */
    protected function canonicalizeData(\DOMNode $node, $c14nMethod, $xpaths = null, $prefixes = null)
    {
        $exclusive = false;
        $withComments = false;
        switch ($c14nMethod) {
            case C::C14N_EXCLUSIVE_WITH_COMMENTS:
            case C::C14N_INCLUSIVE_WITH_COMMENTS:
                $withComments = true;
        }
        switch ($c14nMethod) {
            case C::C14N_EXCLUSIVE_WITH_COMMENTS:
            case C::C14N_EXCLUSIVE_WITHOUT_COMMENTS:
                $exclusive = true;
        }

        if (is_null($xpaths) && ($node->ownerDocument !== null) &&
            $node->isSameNode($node->ownerDocument->documentElement)
        ) {
            // check for any PI or comments as they would have been excluded
            $element = $node;
            while ($refNode = $element->previousSibling) {
                if ((($refNode->nodeType === XML_COMMENT_NODE) && $withComments) ||
                    $refNode->nodeType === XML_PI_NODE
                ) {
                    break;
                }
                $element = $refNode;
            }
            if ($refNode == null) {
                $node = $node->ownerDocument;
            }
        }

        return $node->C14N($exclusive, $withComments, $xpaths, $prefixes);
    }


    /**
     * Create a new element in this signature.
     *
     * @param string $name The name of this element.
     * @param string|null $content The text contents of the element, or null if it is not supposed to have any text
     * contents. Defaults to null.
     * @param string $ns The namespace the new element must be created under. Defaults to the standard XMLDSIG
     * namespace.
     * @param string|null $nsPrefix The prefix to use for the elements's name.
     *
     * @return \DOMElement A new DOM element with the given name.
     */
    protected function createElement($name, $content = null, $ns = C::XMLDSIGNS, $nsPrefix = null)
    {
        if ($this->sigNode === null) {
            // initialize signature
            $doc = DOMDocumentFactory::create();
        } else {
            $doc = $this->sigNode->ownerDocument;
        }

        if ($nsPrefix === null) {
            $nsPrefix = $this->nsPrefix;
        }

        if ($content !== null) {
            return $doc->createElementNS($ns, $nsPrefix.$name, $content);
        }

        return $doc->createElementNS($ns, $nsPrefix.$name);
    }


    /**
     * Find a signature from a given node.
     *
     * @param \DOMNode $node A DOMElement node where a signature is expected as a child (enveloped) or a DOMDocument
     * node to search for document signatures (one single reference with an empty URI).
     *
     * @return \DOMElement The signature element.
     *
     * @throws RuntimeException If there is no DOMDocument element available.
     * @throws NoSignatureFound If no signature is found.
     */
    protected static function findSignature(\DOMNode $node)
    {
        $doc = $node instanceof \DOMDocument ? $node : $node->ownerDocument;

        if ($doc === null) {
            throw new RuntimeException('Cannot search for signatures, no DOM document available');
        }

        $xp = self::getXPath($doc);
        $nodeset = $xp->query('./ds:Signature', $node);

        if ($nodeset->length === 0) {
            throw new NoSignatureFound();
        }
        return $nodeset->item(0);
    }


    /**
     * Get a DOMXPath object that can be used to search for XMLDSIG elements.
     *
     * @param \DOMDocument $doc The document to associate to the DOMXPath object.
     *
     * @return \DOMXPath A DOMXPath object ready to use in the given document, with the XMLDSIG namespace already
     * registered.
     */
    protected static function getXPath(\DOMDocument $doc)
    {
        $xp = new \DOMXPath($doc);
        $xp->registerNamespace('ds', C::XMLDSIGNS);
        return $xp;
    }


    /**
     * Compute the hash for some data with a given algorithm.
     *
     * @param string $alg The identifier of the algorithm to use.
     * @param string $data The data to digest.
     * @param bool $encode Whether to bas64-encode the result or not. Defaults to true.
     *
     * @return string The (binary or base64-encoded) digest corresponding to the given data.
     *
     * @throws InvalidArgumentException If $alg is not a valid identifier of a supported digest algorithm.
     */
    protected function hash($alg, $data, $encode = true)
    {
        if (!array_key_exists($alg, C::$DIGEST_ALGORITHMS)) {
            throw new InvalidArgumentException('Unsupported digest method "'.$alg.'"');
        }

        $digest = hash(C::$DIGEST_ALGORITHMS[$alg], $data, true);
        if ($encode) {
            $digest = base64_encode($digest);
        }
        return $digest;
    }


    /**
     * Initialize the basic structure of a signature from scratch.
     */
    protected function initSignature()
    {
        $this->sigNode = $this->createElement('Signature');
        $this->sigInfoNode = $this->createElement('SignedInfo');
        $this->c14nMethodNode = $this->createElement('CanonicalizationMethod');
        $this->c14nMethodNode->setAttribute('Algorithm', $this->c14nMethod);
        $this->sigMethodNode = $this->createElement('SignatureMethod');

        $this->sigInfoNode->appendChild($this->c14nMethodNode);
        $this->sigInfoNode->appendChild($this->sigMethodNode);
        $this->sigNode->appendChild($this->sigInfoNode);
        $this->sigNode->ownerDocument->appendChild($this->sigNode);
    }


    /**
     * Process a given reference, by looking for it, processing the specified transforms, canonicalizing the result
     * and comparing its corresponding digest.
     *
     * Verified references will be stored in the "verifiedElements" property.
     *
     * @param \DOMElement $ref The ds:Reference element to process.
     *
     * @return bool True if the digest of the processed reference matches the one given, false otherwise.
     *
     * @throws RuntimeException If the referenced element is missing or the reference points to an external document.
     *
     * @see http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
     */
    protected function processReference(\DOMElement $ref)
    {
        /*
         * Depending on the URI, we may need to remove comments during canonicalization.
         * See: http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
         */
        $includeCommentNodes = true;
        $dataObject = $ref->ownerDocument;
        if ($ref->hasAttribute("URI")) {
            $uri = $ref->getAttribute('URI');
            if (empty($uri)) {
                // this reference identifies the enclosing XML, it should not include comments
                $includeCommentNodes = false;
            }
            $arUrl = parse_url($uri);
            if (empty($arUrl['path'])) {
                if ($identifier = @$arUrl['fragment']) {
                    /*
                     * This reference identifies a node with the given ID by using a URI on the form '#identifier'.
                     * This should not include comments.
                     */
                    $includeCommentNodes = false;

                    $xp = self::getXPath($ref->ownerDocument);
                    if ($this->idNS && is_array($this->idNS)) {
                        foreach ($this->idNS as $nspf => $ns) {
                            $xp->registerNamespace($nspf, $ns);
                        }
                    }
                    $iDlist = '@Id="'.$identifier.'"';
                    if (is_array($this->idKeys)) {
                        foreach ($this->idKeys as $idKey) {
                            $iDlist .= " or @$idKey='$identifier'";
                        }
                    }
                    $query = '//*['.$iDlist.']';
                    $dataObject = $xp->query($query)->item(0);
                    if ($dataObject === null) {
                        throw new RuntimeException('Reference not found');
                    }
                }
            } else {
                throw new RuntimeException('Processing of external documents is not supported');
            }
        } else {
            // this reference identifies the root node with an empty URI, it should not include comments
            $includeCommentNodes = false;
        }

        $data = $this->processTransforms($ref, $dataObject, $includeCommentNodes);
        if (!$this->validateDigest($ref, $data)) {
            return false;
        }

        // parse the canonicalized reference...
        $doc = DOMDocumentFactory::create();
        $doc->loadXML($data);
        $dataObject = $doc->documentElement;

        // ... and add it to the list of verified elements
        if (!empty($identifier)) {
            $this->verifiedElements[$identifier] = $dataObject;
        } else {
            $this->verifiedElements[] = $dataObject;
        }

        return true;
    }


    /**
     * Process all transforms specified by a given Reference element.
     *
     * @param \DOMElement $ref The Reference element.
     * @param mixed $data The data referenced.
     * @param bool $includeCommentNodes Whether to allow canonicalization with comments or not.
     *
     * @return string The canonicalized data after applying all transforms specified by $ref.
     *
     * @see http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
     */
    protected function processTransforms(\DOMElement $ref, $data, $includeCommentNodes = false)
    {
        if (!$data instanceof \DOMNode) {
            return $data;
        }

        $xp = self::getXPath($ref->ownerDocument);
        $transforms = $xp->query('./ds:Transforms/ds:Transform', $ref);
        $canonicalMethod = C::C14N_EXCLUSIVE_WITHOUT_COMMENTS;
        $arXPath = null;
        $prefixList = null;
        foreach ($transforms as $transform) {
            /** @var \DOMElement $transform */
            $algorithm = $transform->getAttribute("Algorithm");
            switch ($algorithm) {
                case C::C14N_EXCLUSIVE_WITHOUT_COMMENTS:
                case C::C14N_EXCLUSIVE_WITH_COMMENTS:
                    if (!$includeCommentNodes) {
                        // remove comment nodes by forcing it to use a canonicalization without comments
                        $canonicalMethod = C::C14N_EXCLUSIVE_WITHOUT_COMMENTS;
                    } else {
                        $canonicalMethod = $algorithm;
                    }

                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName === 'InclusiveNamespaces') {
                            if ($pfx = $node->getAttribute('PrefixList')) {
                                $arpfx = [];
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
                case C::C14N_INCLUSIVE_WITHOUT_COMMENTS:
                case C::C14N_INCLUSIVE_WITH_COMMENTS:
                    if (!$includeCommentNodes) {
                        // remove comment nodes by forcing it to use a canonicalization without comments
                        $canonicalMethod = C::C14N_INCLUSIVE_WITHOUT_COMMENTS;
                    } else {
                        $canonicalMethod = $algorithm;
                    }

                    break;
                case C::XPATH_URI:
                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'XPath') {
                            $arXPath = [];
                            $arXPath['query'] = '(.//. | .//@* | .//namespace::*)['.$node->nodeValue.']';
                            $arXpath['namespaces'] = [];
                            $nslist = $xp->query('./namespace::*', $node);
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

        return $this->canonicalizeData($data, $canonicalMethod, $arXPath, $prefixList);
    }


    /**
     * Compute and compare the digest corresponding to some data given to the one specified by a reference.
     *
     * @param \DOMElement $ref The ds:Reference element containing the digest.
     * @param string $data The referenced element, canonicalized, to digest and compare.
     *
     * @return bool True if the resulting digest matches the one in the reference, false otherwise.
     */
    protected function validateDigest(\DOMElement $ref, $data)
    {
        $xp = self::getXPath($ref->ownerDocument);
        $alg = $xp->evaluate('string(./ds:DigestMethod/@Algorithm)', $ref);
        $computed = $this->hash($alg, $data, false);
        $evaluated = base64_decode($xp->evaluate('string(./ds:DigestValue)', $ref));
        return Sec::compareStrings($computed, $evaluated);
    }


    /**
     * Iterate over the references specified by the signature, apply their transforms, and validate their digests
     * against the referenced elements.
     *
     * @return boolean True if all references could be verified, false otherwise.
     *
     * @throws RuntimeException If there are no references.
     */
    protected function validateReferences()
    {
        $doc = $this->sigNode->ownerDocument;

        if (!$doc->documentElement->isSameNode($this->sigNode) && $this->sigNode->parentNode !== null) {
            // enveloped signature, remove it
            $this->sigNode->parentNode->removeChild($this->sigNode);
        }

        $xp = self::getXPath($doc);
        $refNodes = $xp->query('./ds:SignedInfo/ds:Reference', $this->sigNode);
        if ($refNodes->length < 1) {
            throw new RuntimeException('There are no Reference nodes');
        }

        $verified = true;
        foreach ($refNodes as $refNode) {
            $verified = $this->processReference($refNode) && $verified;
        }

        return $verified;
    }
}
