--TEST--
Signing HHVM ID w/out ns regenerated
--DESCRIPTION--
Signing on HHVM a node which id attribute does not have namespace prefix, prevent regeneratation of its ID
--FILE--
<?php

require(dirname(__FILE__) . '/../xmlseclibs.php');

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$doc = new \DOMDocument();
$doc->load(__DIR__.'/sign-hhvm-id-wout-ns-regenerated.xml');

$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
$objKey->loadKey(dirname(__FILE__) . '/privkey.pem', TRUE);

/** @var \DOMElement $assertion */
$assertion = $doc->getElementsByTagName('Assertion')->item(0);

$objXMLSecDSig = new XMLSecurityDSig();
$objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$objXMLSecDSig->addReferenceList(
    array($assertion),
    XMLSecurityDSig::SHA1,
    array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
    array('id_name' => 'ID', 'overwrite' => false)
);

print $assertion->getAttribute('ID')."\n";
?>
--EXPECTF--
assertion-id
