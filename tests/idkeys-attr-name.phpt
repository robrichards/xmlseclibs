--TEST--
idKeys attribute names cannot inject XPath operators
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

$xml = <<<XML
<?xml version="1.0"?>
<Root>
  <A Id="target">one</A>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#target">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
</Root>
XML;

$doc = new DOMDocument();
$doc->loadXML($xml);
$objXMLSecDSig = new XMLSecurityDSig();
$objXMLSecDSig->idKeys = array('foo or bar');
$objXMLSecDSig->locateSignature($doc);
$objXMLSecDSig->canonicalizeSignedInfo();
try {
    $objXMLSecDSig->validateReference();
    print "INJECT: unexpected success\n";
} catch (Exception $e) {
    print "INJECT: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
INJECT: Invalid idKeys attribute name
