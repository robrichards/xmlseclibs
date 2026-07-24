--TEST--
XPath Transforms are rejected on the verify path by default (GHSA-7mf5-fjj8-mvjc)
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/* Build a document that is legitimately signed with an XPath Transform. */
function signWithXPathTransform() {
    $doc = new DOMDocument();
    $doc->load(dirname(__FILE__) . '/basic-doc.xml');
    $objDSig = new XMLSecurityDSig();
    $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $objDSig->addReference(
        $doc,
        XMLSecurityDSig::SHA256,
        array(
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            array('http://www.w3.org/TR/1999/REC-xpath-19991116' => array('query' => 'true()')),
        )
    );
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
    $objKey->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    $objDSig->sign($objKey);
    $objDSig->appendSignature($doc->documentElement);
    return $doc->saveXML();
}

function pubKey() {
    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
    $objKey->loadKey(dirname(__FILE__) . '/mycert.pem', true, true);
    return $objKey;
}

$signedXml = signWithXPathTransform();

/* 1. Signing with an XPath transform is unaffected. */
print "SIGN: ".(strpos($signedXml, 'REC-xpath-19991116') !== false ? "ok" : "missing transform")."\n";

/* 2. Default verification refuses the XPath transform (pre-auth DoS surface). */
$doc = new DOMDocument();
$doc->loadXML($signedXml);
$objDSig = new XMLSecurityDSig();
$objDSig->locateSignature($doc);
$objDSig->canonicalizeSignedInfo();
try {
    $objDSig->validateReference();
    print "DENY: not rejected\n";
} catch (Exception $e) {
    print "DENY: ".$e->getMessage()."\n";
}

/* 3. Opt-in allows it and the signature still validates. */
$doc = new DOMDocument();
$doc->loadXML($signedXml);
$objDSig = new XMLSecurityDSig();
$objDSig->allowXPathTransforms = true;
$objDSig->locateSignature($doc);
$objDSig->canonicalizeSignedInfo();
try {
    $objDSig->validateReference();
    print "ALLOW: ".($objDSig->verify(pubKey()) === 1 ? "valid" : "invalid")."\n";
} catch (Exception $e) {
    print "ALLOW: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
SIGN: ok
DENY: XPath Transforms are not allowed during verification; set XMLSecurityDSig::$allowXPathTransforms = true to enable them
ALLOW: valid
