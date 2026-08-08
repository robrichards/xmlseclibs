--TEST--
Duplicate SignedInfo children are rejected
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

function checkStruct($xml, $label) {
	$doc = new DOMDocument();
	$doc->loadXML($xml);
	$objXMLSecDSig = new XMLSecurityDSig();
	$objXMLSecDSig->locateSignature($doc);
	try {
		$objXMLSecDSig->canonicalizeSignedInfo();
		print "$label: unexpected success\n";
	} catch (Exception $e) {
		print "$label: ".$e->getMessage()."\n";
	}
}

$dupCanon = <<<XML
<?xml version="1.0"?>
<Root>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkStruct($dupCanon, 'DUP_CANON');

$dupSigMethod = <<<XML
<?xml version="1.0"?>
<Root>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;
checkStruct($dupSigMethod, 'DUP_SIGMETHOD');
?>
--EXPECTF--
DUP_CANON: Invalid structure - Too many CanonicalizationMethod elements found
DUP_SIGMETHOD: Invalid structure - Too many SignatureMethod elements found
