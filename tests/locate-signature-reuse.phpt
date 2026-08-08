--TEST--
locateSignature resets XPath context across documents
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;

$sigXml = '<Root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod/></ds:SignedInfo></ds:Signature></Root>';

$doc1 = new DOMDocument();
$doc1->loadXML($sigXml);

$doc2 = new DOMDocument();
$doc2->loadXML(str_replace('<Root>', '<Other>', str_replace('</Root>', '</Other>', $sigXml)));

$objDSig = new XMLSecurityDSig();
/* Prime an XPath context against the constructor template document. */
$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$objDSig->locateSignature($doc1);
$objDSig->canonicalizeSignedInfo();

try {
    $objDSig->locateSignature($doc2);
    $objDSig->canonicalizeSignedInfo();
    echo "REUSE: OK\n";
} catch (Throwable $e) {
    echo "REUSE: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
REUSE: OK
