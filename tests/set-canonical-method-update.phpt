--TEST--
setCanonicalMethod updates existing CanonicalizationMethod instead of duplicating
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

$objDSig = new XMLSecurityDSig();
$objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);
$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

$doc = $objDSig->sigNode->ownerDocument;
$xpath = new DOMXPath($doc);
$xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
$nodes = $xpath->query('./ds:SignedInfo/ds:CanonicalizationMethod', $objDSig->sigNode);
echo $nodes->length."\n";
echo $nodes->item(0)->getAttribute('Algorithm')."\n";
?>
--EXPECTF--
1
http://www.w3.org/2001/10/xml-exc-c14n#
