--TEST--
Signature verification rejects documents carrying a DOCTYPE (GHSA-9wcx-p7hr-f935)
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

/* Take a legitimately signed document and inject a DOCTYPE, mimicking the
 * entity-reference XPath-hash-skip bypass (same libxml2 root cause as
 * CVE-2025-23369). The DOCTYPE itself must be refused. */
$signed = file_get_contents(dirname(__FILE__) . '/sign-sha256-rsa-sha256-test.res');
$withDoctype = preg_replace(
    '/(<\?xml[^>]*\?>\n)/',
    "$1<!DOCTYPE Root [ <!ENTITY e \"anything\"> ]>\n",
    $signed,
    1
);

/* 1. verifyDocument() (safe path) rejects the DOCTYPE. */
$doc = new DOMDocument();
$doc->loadXML($withDoctype, LIBXML_NOENT);
$objXMLSecDSig = new XMLSecurityDSig();
try {
    $objXMLSecDSig->verifyDocument(pinnedKey(), $doc);
    print "SAFE: unexpected success\n";
} catch (Exception $e) {
    print "SAFE: ".$e->getMessage()."\n";
}

/* 2. The low-level locateSignature() primitive rejects it too. */
$doc = new DOMDocument();
$doc->loadXML($withDoctype, LIBXML_NOENT);
$objXMLSecDSig = new XMLSecurityDSig();
try {
    $objXMLSecDSig->locateSignature($doc);
    print "LOWLEVEL: unexpected success\n";
} catch (Exception $e) {
    print "LOWLEVEL: ".$e->getMessage()."\n";
}

/* 3. Opt-out (forbidDoctype = false) lets a trusted caller keep DTD support;
 * the underlying document is unmodified so it still verifies. */
$doc = new DOMDocument();
$doc->loadXML($withDoctype, LIBXML_NOENT);
$objXMLSecDSig = new XMLSecurityDSig();
$objXMLSecDSig->forbidDoctype = false;
try {
    $nodes = $objXMLSecDSig->verifyDocument(pinnedKey(), $doc);
    print "OPTOUT: ".(count($nodes) > 0 ? "verified" : "no nodes")."\n";
} catch (Exception $e) {
    print "OPTOUT: ".$e->getMessage()."\n";
}
?>
--EXPECTF--
SAFE: A DOCTYPE is not allowed in a document being verified
LOWLEVEL: A DOCTYPE is not allowed in a document being verified
OPTOUT: verified
