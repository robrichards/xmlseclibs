--TEST--
verifyDocument() accepts only canonicalization and enveloped-signature transforms
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

function pinnedKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $objKey;
}

function privateKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $objKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    return $objKey;
}

/* An expression that fails if it is evaluated. */
function xpathFilteredSignature() {
    return <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<Root>
  <Value>hello</Value>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not-a-function(</ds:XPath></ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAA</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
  </ds:Signature>
</Root>
XML;
}

/* Sign SignedInfo only. Reference transforms are not applied here. */
function withValidSignatureValue($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $signer = new XMLSecurityDSig();
    $signer->locateSignature($doc);
    $canonical = $signer->canonicalizeSignedInfo();
    $signed = base64_encode(privateKey()->signData($canonical));
    $xpath = new DOMXPath($doc);
    $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
    $sigValue = $xpath->query('//ds:SignatureValue')->item(0);
    while ($sigValue->firstChild) {
        $sigValue->removeChild($sigValue->firstChild);
    }
    $sigValue->appendChild($doc->createTextNode($signed));
    return $doc;
}

function rejectInVerifyDocument($legacy) {
    $doc = withValidSignatureValue(xpathFilteredSignature());
    $objDSig = new XMLSecurityDSig();
    if ($legacy) {
        $objDSig->enableLegacyMode();
    }
    $warnings = array();
    set_error_handler(function ($severity, $message) use (&$warnings) {
        $warnings[] = $message;
        return true;
    });
    $useInternal = libxml_use_internal_errors(true);
    libxml_clear_errors();
    try {
        $objDSig->verifyDocument(pinnedKey(), $doc);
        $result = 'not rejected';
    } catch (Exception $e) {
        $result = get_class($e).': '.$e->getMessage();
    }
    $xmlErrors = libxml_get_errors();
    libxml_clear_errors();
    libxml_use_internal_errors($useInternal);
    restore_error_handler();
    $label = $legacy ? 'LEGACY' : 'DEFAULT';
    print $label.': '.$result."\n";
    print $label.'_EVAL: '.((count($warnings) + count($xmlErrors)) === 0 ? 'no' : 'yes')."\n";
}

rejectInVerifyDocument(false);
rejectInVerifyDocument(true);

/* The low-level path still verifies one XPath transform when it is enabled. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/basic-doc.xml');
$signer = new XMLSecurityDSig();
$signer->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$signer->addReference(
    $doc,
    XMLSecurityDSig::SHA256,
    array(
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        array('http://www.w3.org/TR/1999/REC-xpath-19991116' => array('query' => 'true()')),
    )
);
$signer->sign(privateKey());
$signer->appendSignature($doc->documentElement);

$verifier = new XMLSecurityDSig();
$verifier->allowXPathTransforms = true;
$verifier->locateSignature($doc);
$verifier->canonicalizeSignedInfo();
try {
    $verifier->validateReference();
    print 'LOWLEVEL: '.($verifier->verify(pinnedKey()) === 1 ? 'valid' : 'invalid')."\n";
} catch (Exception $e) {
    print 'LOWLEVEL: '.$e->getMessage()."\n";
}

/* Legacy mode still accepts enveloped-signature plus exclusive c14n. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/basic-doc.xml');
$signer = new XMLSecurityDSig();
$signer->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$signer->addReference(
    $doc,
    XMLSecurityDSig::SHA256,
    array(XMLSecurityDSig::ENVELOPED, XMLSecurityDSig::EXC_C14N),
    array('force_uri' => true)
);
$signer->sign(privateKey());
$signer->appendSignature($doc->documentElement);
$verifier = new XMLSecurityDSig();
$verifier->enableLegacyMode();
try {
    $nodes = $verifier->verifyDocument(pinnedKey(), $doc);
    print 'LEGACY_C14N: '.(count($nodes) > 0 ? 'ok' : 'empty')."\n";
} catch (Exception $e) {
    print 'LEGACY_C14N: '.$e->getMessage()."\n";
}

/* Two XPath transforms in one reference are rejected on verify. */
$two = <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<Root>
  <Value>hello</Value>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform>
          <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>false()</ds:XPath></ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAA</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
  </ds:Signature>
</Root>
XML;
$doc = new DOMDocument();
$doc->loadXML($two);
$verifier = new XMLSecurityDSig();
$verifier->allowXPathTransforms = true;
$verifier->locateSignature($doc);
$verifier->canonicalizeSignedInfo();
try {
    $verifier->validateReference();
    print "TWO_VERIFY: not rejected\n";
} catch (Exception $e) {
    print 'TWO_VERIFY: '.get_class($e).': '.$e->getMessage()."\n";
}

/* Two XPath transforms are rejected on sign, before the document changes. */
$doc = new DOMDocument();
$doc->load(dirname(__FILE__) . '/basic-doc.xml');
$before = $doc->saveXML();
$signer = new XMLSecurityDSig();
$signer->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$template = $signer->sigNode->ownerDocument->saveXML();
try {
    $signer->addReference(
        $doc->documentElement,
        XMLSecurityDSig::SHA256,
        array(
            array('http://www.w3.org/TR/1999/REC-xpath-19991116' => array('query' => 'true()')),
            array('http://www.w3.org/TR/1999/REC-xpath-19991116' => array('query' => 'false()')),
        )
    );
    print "TWO_SIGN: not rejected\n";
} catch (Exception $e) {
    print 'TWO_SIGN: '.get_class($e).': '.$e->getMessage()."\n";
}
print 'TWO_SIGN_UNMODIFIED: '.($doc->saveXML() === $before ? 'yes' : 'no')."\n";
print 'TWO_SIGN_TEMPLATE: '.($signer->sigNode->ownerDocument->saveXML() === $template ? 'yes' : 'no')."\n";
?>
--EXPECTF--
DEFAULT: Exception: verifyDocument() only accepts canonicalization and enveloped-signature transforms: 'http://www.w3.org/TR/1999/REC-xpath-19991116'
DEFAULT_EVAL: no
LEGACY: Exception: verifyDocument() only accepts canonicalization and enveloped-signature transforms: 'http://www.w3.org/TR/1999/REC-xpath-19991116'
LEGACY_EVAL: no
LOWLEVEL: valid
LEGACY_C14N: ok
TWO_VERIFY: Exception: Too many XPath Transformations found (2) with a max allowed of 1
TWO_SIGN: Exception: Too many XPath Transformations found (2) with a max allowed of 1
TWO_SIGN_UNMODIFIED: yes
TWO_SIGN_TEMPLATE: yes
