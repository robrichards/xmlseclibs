--TEST--
Reference URI fail-closed checks
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

function checkRef($xml, $label) {
	$doc = new DOMDocument();
	$doc->loadXML($xml);
	$objXMLSecDSig = new XMLSecurityDSig();
	$objXMLSecDSig->locateSignature($doc);
	$objXMLSecDSig->canonicalizeSignedInfo();
	try {
		$objXMLSecDSig->validateReference();
		print "$label: unexpected success\n";
	} catch (Exception $e) {
		print "$label: ".$e->getMessage()."\n";
	}
}

/* External URI must be rejected */
$external = <<<XML
<?xml version="1.0"?>
<Root>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="http://example.com/data.xml">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkRef($external, 'EXTERNAL');

/* Missing Id fragment */
$missing = <<<XML
<?xml version="1.0"?>
<Root>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#does-not-exist">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkRef($missing, 'MISSING');

/* Duplicate Id values */
$dup = <<<XML
<?xml version="1.0"?>
<Root>
  <A Id="same">one</A>
  <B Id="same">two</B>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#same">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkRef($dup, 'DUPLICATE');

/* Query-only URI must be rejected */
$queryOnly = <<<XML
<?xml version="1.0"?>
<Root>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="?x=1">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkRef($queryOnly, 'QUERY');

/* Bare "#" fragment must be rejected */
$bareHash = <<<XML
<?xml version="1.0"?>
<Root>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkRef($bareHash, 'BAREHASH');

/* Unknown Transform Algorithm must fail closed */
$unknownXform = <<<XML
<?xml version="1.0"?>
<Root>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="">
      <ds:Transforms>
        <ds:Transform Algorithm="http://example.com/unknown-transform"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkRef($unknownXform, 'UNKNOWN_TRANSFORM');
?>
--EXPECTF--
EXTERNAL: Reference URI must be a same-document reference
MISSING: Reference URI does not identify a node
DUPLICATE: Reference URI identifies multiple nodes
QUERY: Reference URI must be a same-document reference
BAREHASH: Reference URI must be a same-document reference
UNKNOWN_TRANSFORM: Transform algorithm is not supported: 'http://example.com/unknown-transform'
